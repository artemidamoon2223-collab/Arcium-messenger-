//! Contacts: peer identities obtained out of band and pinned.
//! Specification: `docs/NET-MESSAGING.md`, section 2.
//!
//! A contact card names both identity keys of a device: the X25519 key its
//! sessions are keyed from and the Ed25519 key that signs its prekeys. Cards
//! travel outside the network (a QR code, a message on another channel) and
//! are compared by fingerprint. Once pinned, a card is never replaced: a
//! different card for the same X25519 key is refused, and a prekey bundle or a
//! handshake that names other keys is never used.

use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey;

use crate::{ArciumCore, CoreError};
use core_storage::{EncryptedStore, StorageError};

/// `CONTACT_CARD_V1`: version(1) = 0x01, identity_dh_pk(32), signing_pk(32).
pub const CONTACT_CARD_V1_LEN: usize = 65;
const CARD_VERSION: u8 = 0x01;
const FINGERPRINT_DOMAIN: &[u8] = b"ARCIUM-CONTACT-CARD-V1";

/// A parsed contact card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Card {
    pub dh_pk: [u8; 32],
    pub signing_pk: [u8; 32],
}

impl Card {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CONTACT_CARD_V1_LEN);
        out.push(CARD_VERSION);
        out.extend_from_slice(&self.dh_pk);
        out.extend_from_slice(&self.signing_pk);
        out
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, CoreError> {
        let bad = |msg: &str| CoreError::InvalidContactCard { msg: msg.into() };
        if bytes.len() != CONTACT_CARD_V1_LEN {
            return Err(bad("expected 65 bytes"));
        }
        if bytes[0] != CARD_VERSION {
            return Err(bad("unsupported card version"));
        }
        Ok(Self {
            dh_pk: bytes[1..33].try_into().expect("32 bytes"),
            signing_pk: bytes[33..65].try_into().expect("32 bytes"),
        })
    }
}

fn contact_key(dh_pk: &[u8; 32]) -> String {
    let hex: String = dh_pk.iter().map(|b| format!("{b:02x}")).collect();
    format!("contact:v1/{hex}")
}

/// The pinned card for `dh_pk`, if this device has one.
pub(crate) fn pinned(store: &EncryptedStore, dh_pk: &[u8; 32]) -> Result<Option<Card>, CoreError> {
    match store.get(&contact_key(dh_pk)) {
        Ok(bytes) => Card::decode(&bytes).map(Some),
        Err(StorageError::NotFound) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// A short, human-comparable fingerprint of a contact card: the first 16 bytes
/// of `SHA-256("ARCIUM-CONTACT-CARD-V1" || card)` as hex, in groups of four.
/// Two people compare it to confirm the card each received is the other's.
#[uniffi::export]
pub fn contact_card_fingerprint(card: Vec<u8>) -> Result<String, CoreError> {
    Card::decode(&card)?;
    let digest = Sha256::new()
        .chain_update(FINGERPRINT_DOMAIN)
        .chain_update(&card)
        .finalize();
    let hex: Vec<String> = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
    Ok(hex
        .chunks(2)
        .map(|c| c.concat())
        .collect::<Vec<_>>()
        .join(" "))
}

#[uniffi::export]
impl ArciumCore {
    /// This device's `CONTACT_CARD_V1`, to hand to a peer out of band.
    pub fn contact_card(&self) -> Result<Vec<u8>, CoreError> {
        let identity = self.require_identity()?;
        Ok(Card {
            dh_pk: PublicKey::from(&identity.dh_key).to_bytes(),
            signing_pk: identity.signing_key.verifying_key().to_bytes(),
        }
        .encode())
    }

    /// Pins a peer's card, received out of band. Returns the peer's X25519
    /// identity key, which names the peer everywhere else in this API.
    ///
    /// Adding the same card again is harmless. A different card for an
    /// identity already pinned is refused with `ContactIdentityChanged` and
    /// changes nothing: a peer identity is never replaced silently.
    pub fn add_contact(&self, card: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        let parsed = Card::decode(&card)?;
        if parsed.dh_pk == self.our_identity_pk()? {
            return Err(CoreError::InvalidContactCard {
                msg: "this is our own card".into(),
            });
        }
        let mut store = self.store.lock().map_err(|_| CoreError::Storage {
            msg: "mutex poisoned".into(),
        })?;
        let key = contact_key(&parsed.dh_pk);
        let tx = store.transaction()?;
        match tx.get(&key) {
            Ok(existing) if existing == card => return Ok(parsed.dh_pk.to_vec()),
            Ok(_) => return Err(CoreError::ContactIdentityChanged),
            Err(StorageError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        tx.put(&key, &card)?;
        tx.commit()?;
        Ok(parsed.dh_pk.to_vec())
    }

    /// The X25519 identity keys of every pinned contact.
    pub fn contacts(&self) -> Result<Vec<Vec<u8>>, CoreError> {
        let store = self.store.lock().map_err(|_| CoreError::Storage {
            msg: "mutex poisoned".into(),
        })?;
        let mut out = Vec::new();
        for key in store.list_keys_with_prefix("contact:")? {
            if !key.starts_with("contact:v1/") {
                continue;
            }
            let card = Card::decode(&store.get(&key)?)?;
            out.push(card.dh_pk.to_vec());
        }
        Ok(out)
    }
}
