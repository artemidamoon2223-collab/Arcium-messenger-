//! The device identity (Ed25519 signing key, X25519 DH key), its stored
//! record, and the local session handle derived from a peer's identity key.

use super::*;

// ── Local session handles ─────────────────────────────────────────────────────

/// Derives the caller's own lookup handle for the session with the peer whose
/// 32-byte X25519 identity public key is `peer_identity_pk`, so the platform
/// layer never has to reimplement a hash to obtain the `u64` this API's session
/// methods take.
///
/// The handle is local: it is transmitted nowhere, and the peer may pick a
/// different one for the same session. It is also a truncation, so it is not
/// collision-free — but the caller does not have to police that: an occupied
/// handle is never overwritten. `establish_session_*` fails with
/// `SessionIdCollision` when a different peer already holds it, and with
/// `SessionAlreadyExists` when the same peer does.
///
/// This is deliberately **not** `hash_contact`, which hashes a phone number for
/// PSI and is pinned to the deployed circuit; see `core_crypto::session_handle`.
#[uniffi::export]
pub fn local_session_handle(peer_identity_pk: Vec<u8>) -> Result<u64, CoreError> {
    let pk: [u8; 32] = peer_identity_pk.as_slice().try_into().map_err(|_| CoreError::InvalidKey {
        msg: format!(
            "expected a 32-byte peer identity public key, got {}",
            peer_identity_pk.len()
        ),
    })?;
    Ok(core_crypto::session_handle::local_session_handle(&pk))
}

// ── Identity ──────────────────────────────────────────────────────────────────

#[derive(uniffi::Object)]
pub struct Identity {
    pub(crate) signing_key: SigningKey,
    pub(crate) dh_key: StaticSecret,
}

#[uniffi::export]
impl Identity {
    #[uniffi::constructor]
    pub fn generate() -> Arc<Self> {
        Arc::new(Self {
            signing_key: SigningKey::generate(&mut OsRng),
            dh_key: StaticSecret::random_from_rng(OsRng),
        })
    }

    /// Returns the 32-byte Ed25519 verifying (public) key.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }

    /// Returns the 32-byte X25519 DH public key (used for X3DH key agreement).
    /// Distinct from `public_key_bytes()`, which is the Ed25519 signing key.
    pub fn dh_public_key_bytes(&self) -> Vec<u8> {
        PublicKey::from(&self.dh_key).as_bytes().to_vec()
    }
}

pub(crate) const IDENTITY_KEY: &str = "identity/v1";
/// The Ed25519 signing secret, then the X25519 secret.
pub(crate) const IDENTITY_RECORD_LEN: usize = 64;

/// Classifies a read of `IDENTITY_KEY`: only a missing record is `Ok(None)`.
pub(crate) fn identity_from_record(read: Result<Vec<u8>, StorageError>) -> Result<Option<Arc<Identity>>, CoreError> {
    let bytes = match read {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(StorageError::NotFound) => return Ok(None),
        Err(StorageError::Decryption) => {
            return Err(CoreError::IdentityUnreadable {
                msg: "the record does not decrypt".into(),
            })
        }
        Err(e) => return Err(e.into()),
    };
    if bytes.len() != IDENTITY_RECORD_LEN {
        return Err(CoreError::IdentityUnreadable {
            msg: format!("the record is {} bytes, expected {IDENTITY_RECORD_LEN}", bytes.len()),
        });
    }
    let mut sk_bytes = Zeroizing::new([0u8; 32]);
    let mut dh_bytes = Zeroizing::new([0u8; 32]);
    sk_bytes.copy_from_slice(&bytes[..32]);
    dh_bytes.copy_from_slice(&bytes[32..]);
    Ok(Some(Arc::new(Identity {
        signing_key: SigningKey::from_bytes(&sk_bytes),
        dh_key: StaticSecret::from(*dh_bytes),
    })))
}
