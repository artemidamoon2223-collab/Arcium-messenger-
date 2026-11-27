use core_crypto::ratchet::{DoubleRatchet, RatchetError};
use core_crypto::spk_id::{spk_id, SPK_ID_LEN};
use core_crypto::x3dh::{
    signed_prekey_object_v1, x3dh_initiate, x3dh_respond, PrekeyBundle, X3dhError, CIPHER_SUITE,
    PROTOCOL_VERSION,
};
use core_protocol::checkpoint::SessionRole;
use core_protocol::durable::SideWrite;
use core_protocol::messaging::{
    FirstContact, Messenger, MessagingError, NewSession, ProvisionalHandshake, Received,
    ValidatedRecord,
};
use core_protocol::Session;
use core_storage::{EncryptedStore, StorageError};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

mod contacts;
mod messaging_api;
pub(crate) mod network;
mod plaintext;
pub use messaging_api::{IncomingMessage, OutgoingMessage, ReceiveResult, RecoveryReport, SendResult};
pub use plaintext::{PlaintextBytes, PlaintextText};

mod error;
mod handshake;
mod identity;
mod prekeys;
mod responder;
pub use error::CoreError;
pub use identity::{local_session_handle, Identity};
pub(crate) use handshake::*;
pub(crate) use identity::*;
pub(crate) use prekeys::*;
pub(crate) use responder::*;

// ── ArciumCore ────────────────────────────────────────────────────────────────
/// The encrypted store and the durable messaging state machine over it.
///
/// Sessions live only in the store: every messaging call loads the session,
/// stages its transition, and commits the new state together with the
/// operation's outbox or inbox record before returning anything
/// (`core_protocol::messaging`, spec `docs/S2-B2-DURABLE-MESSAGING.md`).
/// Nothing about a session is cached here, so a second `ArciumCore` on the
/// same file cannot advance a session from a state it no longer holds.
///
/// Lock order: `store`, then `messenger`. `messenger` only records which
/// sessions have an unresolved commit.
#[derive(uniffi::Object)]
pub struct ArciumCore {
    store: Mutex<EncryptedStore>,
    messenger: Mutex<Messenger>,
    /// Where the process's Tor client keeps its state, if this core is the
    /// first to start it: `tor/` next to the store file, so in the same
    /// directory, which the app keeps (never a cache Android may clear:
    /// arti's record that the network requires an update lives there).
    tor_dir: std::path::PathBuf,
}

#[uniffi::export]
impl ArciumCore {
    #[uniffi::constructor]
    pub fn new(storage_path: String, master_key: Vec<u8>) -> Result<Arc<Self>, CoreError> {
        // Wrap immediately so the caller-supplied master key is zeroized on
        // every exit path (F-8) — the Kotlin side already zeros its own copy
        // (PR #48's MasterKeyProvider), this covers what the Rust side holds.
        let master_key = Zeroizing::new(master_key);
        // ring as the process's rustls provider, before any Tor client
        // exists (decision D-193); once per process.
        core_transport::install_crypto_provider();
        // Borrowed, not copied: the store makes the one copy it keeps, in its
        // own wiping owner, so no plain 32-byte array of the key exists here.
        let key: &[u8; 32] = master_key.as_slice().try_into().map_err(|_| CoreError::InvalidKey {
            msg: "expected exactly 32 bytes".into(),
        })?;
        let store = EncryptedStore::open_with_key(&storage_path, key)?;
        let tor_dir = std::path::Path::new(&storage_path)
            .parent()
            .unwrap_or(std::path::Path::new(""))
            .join("tor");
        Ok(Arc::new(Self {
            store: Mutex::new(store),
            messenger: Mutex::new(Messenger::with_confirm_hook(Box::new(replace_prekey_on_confirm))),
            tor_dir,
        }))
    }

    /// Stores `identity` as this store's identity, only if it has none.
    ///
    /// Create-only: one transaction reads the identity record and writes
    /// only when there is none. Nothing is written when
    ///
    /// - an identity is stored and readable: `IdentityAlreadyExists`;
    /// - an identity record is stored but unreadable: `IdentityUnreadable`;
    /// - the store cannot be read or written: `Storage`.
    ///
    /// A `Storage` error from the final commit can leave the outcome unknown:
    /// the identity may have been stored (see `StoreTransaction::commit`).
    /// Calling again never replaces it: it returns `IdentityAlreadyExists` if
    /// the first call took effect, and `load_identity` returns that identity.
    pub fn save_identity(&self, identity: Arc<Identity>) -> Result<(), CoreError> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(IDENTITY_RECORD_LEN));
        bytes.extend_from_slice(identity.signing_key.as_bytes());
        bytes.extend_from_slice(identity.dh_key.as_bytes());
        let mut store = self
            .store
            .lock()
            .map_err(|_| CoreError::Storage { msg: "mutex poisoned".into() })?;
        // Dropping `tx` on any early return rolls it back; nothing is written.
        let tx = store.transaction()?;
        if identity_from_record(tx.get(IDENTITY_KEY))?.is_some() {
            return Err(CoreError::IdentityAlreadyExists);
        }
        tx.put(IDENTITY_KEY, &bytes)?;
        tx.commit()?;
        Ok(())
    }

    /// The stored identity. `Ok(None)` only when the store holds no identity
    /// record under this master key; a record that is stored but cannot be
    /// read is `IdentityUnreadable`, and a store that cannot be read is
    /// `Storage` — neither is reported as "no identity".
    ///
    /// The store finds records by a name derived from the master key, so
    /// `Ok(None)` does not show that the database file holds no identity
    /// under some other key.
    pub fn load_identity(&self) -> Result<Option<Arc<Identity>>, CoreError> {
        // A poisoned mutex must not panic across the FFI boundary.
        let store = self
            .store
            .lock()
            .map_err(|_| CoreError::Storage { msg: "mutex poisoned".into() })?;
        identity_from_record(store.get(IDENTITY_KEY))
    }

    /// Generates this device's signed prekey and one one-time prekey, signs the
    /// signed prekey over `SIGNED_PREKEY_OBJECT_V1`, and persists everything.
    ///
    /// Calling this again replaces both prekeys, and drops a previous signed
    /// prekey: a hard reset. Every bundle already handed out then names a
    /// signed prekey and a one-time prekey this device no longer holds, so
    /// handshakes built from those bundles are refused with
    /// `StaleSignedPrekey` / `OneTimePrekeyUnavailable` rather than silently
    /// deriving a key the peer cannot match.
    ///
    /// The network layer does not call it: it creates the record if none
    /// exists and rotates the signed prekey itself, at the start of every
    /// round (`ArciumCore::maintain_prekeys`, tracker R-6). Every answered
    /// handshake uses a one-time prekey (X-6). Once that prekey is replaced,
    /// the secrets this device keeps no longer derive the keys of a first
    /// message under it: the first message accepted under it replaces it,
    /// and so does the receive that confirms this device's own initiator
    /// session (`replace_prekey_on_confirm`). Until then they do, for any
    /// first contact under the prekey held, until the signed prekey it names
    /// is rotated out (`docs/NET-MESSAGING.md` section 8).
    pub fn establish_prekeys(&self) -> Result<(), CoreError> {
        let identity = self.require_identity()?;
        let record = PrekeyRecord::new(&identity);
        self.store
            .lock()
            .map_err(|_| CoreError::Storage {
                msg: "mutex poisoned".into(),
            })?
            .put(PREKEYS_KEY, &pack_prekeys(&record))?;
        Ok(())
    }

    /// Pure read of the already-persisted prekey material as a
    /// `PREKEY_BUNDLE_V1` (D3) — generates nothing and consumes nothing, so two
    /// calls return identical bytes. Fails if no prekey record exists yet.
    ///
    /// The network layer exports the bundle only to publish it, right after
    /// the rotation check of the round (`NetworkMessenger::put_bundle`). The
    /// rotation after a one-time-prekey change ((E), `plan_rotation`) relies
    /// on that: a bundle exported at any other time could pair the current
    /// signed prekey with a one-time prekey made since, and a handshake
    /// built from it would be refused once and made again. The exported
    /// calls that skip the round (this one, `establish_session_responder`,
    /// `receive_message`) neither rotate nor publish; no release code path
    /// on Android calls them (instrumentation tests and the debug crash
    /// provider do).
    pub fn export_prekey_bundle(&self) -> Result<Vec<u8>, CoreError> {
        let identity = self.require_identity()?;
        // The decrypted record holds the signed-prekey and one-time-prekey
        // secrets in the clear; wipe the buffer on every exit path (F-8), as
        // load_identity already does for the identity blob.
        let record_bytes = Zeroizing::new(
            self.store
                .lock()
                .map_err(|_| CoreError::Storage {
                    msg: "mutex poisoned".into(),
                })?
                .get(PREKEYS_KEY)?,
        );
        let record = unpack_prekeys(&record_bytes)?;

        Ok(pack_prekey_bundle(
            &PublicKey::from(&identity.dh_key),
            &identity.signing_key.verifying_key(),
            &record.signed_prekey_pk(),
            &record.signature,
            record.opk.as_ref().map(|(id, sk)| (*id, PublicKey::from(sk))),
        ))
    }

    /// Establishes a session as the X3DH initiator ("Alice") against a peer's
    /// `PREKEY_BUNDLE_V1`. Returns the 84-byte `INITIATOR_HANDSHAKE_V1` the peer
    /// needs for `establish_session_responder`.
    ///
    /// The signature over the bundle is checked before any Diffie-Hellman runs,
    /// so a bundle whose parts do not belong together never contributes key
    /// material.
    pub fn establish_session_initiator(
        &self,
        session_id: u64,
        peer_bundle: Vec<u8>,
    ) -> Result<Vec<u8>, CoreError> {
        let identity = self.require_identity()?;
        let bundle = unpack_prekey_bundle(&peer_bundle)?;
        let our_identity_pk = PublicKey::from(&identity.dh_key);

        // x3dh_initiate verifies the signed-prekey object first; surface that as
        // its own error rather than as a generic handshake failure.
        let alice_session =
            x3dh_initiate(&identity.dh_key, our_identity_pk, &bundle).map_err(|e| match e {
                X3dhError::BadSignature => CoreError::BadSignedPrekeySignature,
                other => CoreError::from(other),
            })?;

        let ratchet = DoubleRatchet::init_alice(
            &alice_session.root_key,
            alice_session.their_signed_prekey_pk,
        );
        // The root key's useful life ended with the ratchet; it is wiped here,
        // not at the end of the function, which commits to the store below.
        drop(alice_session.root_key);
        // The peer recorded as owner is the identity taken from the bundle —
        // the same key X3DH just ran against — so ownership cannot disagree
        // with the cryptography.
        let session = Session {
            ratchet,
            ad: alice_session.ad.clone(),
            peer_identity_pk: bundle.identity_pk.to_bytes(),
        };
        let handshake = pack_initiator_handshake(
            &our_identity_pk,
            &alice_session.ephemeral_pk,
            &spk_id(bundle.signed_prekey_pk.as_bytes()),
            bundle.one_time_prekey_id,
        );

        // The session, its handle and the handshake are committed together;
        // the handshake is returned only after that commit, and can be read
        // again with `initiator_handshake` if it is lost before being sent.
        let (mut store, mut messenger) = self.lock()?;
        messenger
            .create_session(
                &mut store,
                our_identity_pk.to_bytes(),
                NewSession {
                    handle: session_id,
                    session,
                    role: SessionRole::Initiator,
                    initial_outbound: Some(handshake.clone()),
                    extra: Vec::new(),
                },
            )
            .map_err(|e| CoreError::messaging(session_id, e))?;
        Ok(handshake)
    }

    /// Records the 84-byte `INITIATOR_HANDSHAKE_V1` an initiator ("Alice")
    /// produced, as the X3DH responder ("Bob"). **This creates no session.**
    ///
    /// Receiving a handshake is not authentication: its bytes are public and
    /// anyone can send them. So the handshake is only validated against this
    /// device's prekeys and recorded as *provisional* under `session_id`.
    /// Nothing is consumed, no handle is taken, `has_session` stays false, and
    /// a later handshake for this handle replaces it. The session is created
    /// by `receive_message(session_id, …)` when the initiator's first message
    /// authenticates under the keys this handshake derives — only that proves
    /// the initiator holds the secret of the identity key the handshake names.
    /// That same transaction consumes the one-time prekey.
    ///
    /// # Prekey rules
    ///
    /// The handshake names which signed prekey and which one-time prekey it
    /// used. This device answers from its own record, never from what the
    /// handshake asserts:
    ///
    /// | stored state | `used_otp` | named `opk_id` | outcome |
    /// |---|---|---|---|
    /// | any | any | any | `StaleSignedPrekey` if `spk_id` names neither the current signed prekey nor the previous one, or the previous one while the one-time prekey it was published with is no longer held |
    /// | one-time prekey held | yes | matches | recorded; consumed when the first message authenticates |
    /// | one-time prekey held | yes | differs | `OneTimePrekeyUnavailable` |
    /// | one-time prekey held | no | — | `OneTimePrekeyRequired` |
    /// | none held | no | — | `OneTimePrekeyRequired` |
    /// | none held | yes | any | `OneTimePrekeyUnavailable` |
    ///
    /// A one-time prekey error never falls back to the weaker no-`dh4` path: that
    /// would let anyone who can edit bytes in flight choose the weaker handshake.
    /// The same rules are checked again when the first message arrives, against
    /// the prekeys held then. The one-time-prekey rows apply alike under the
    /// current and the previous signed prekey (tracker R-6: a rotation keeps
    /// the previous one for one period, `plan_rotation`).
    ///
    /// Because a consumed identifier is replaced rather than remembered,
    /// replaying a handshake whose session was created names an identifier
    /// that is no longer current and is refused. That is the whole of the
    /// replay property claimed here. A handshake without a one-time prekey
    /// would have none (its root key re-derives identically on every replay),
    /// so it is never answered, also when this device holds no one-time
    /// prekey (tracker X-6); the wire format keeps the form, and an initiator
    /// still builds it from a bundle without one, which is then refused.
    ///
    /// # Refusals
    ///
    /// Once a session exists — authenticated, or started here as initiator —
    /// a handshake never replaces it: `SessionAlreadyExists` for this peer,
    /// `SessionIdCollision` if the handle belongs to another peer. Nothing is
    /// written and nothing is consumed. (A restart by the peer, option B, is
    /// recorded beside the session instead, and the network layer replaces
    /// the session only once its first message authenticates there.)
    ///
    /// # Sessions stored by older builds
    ///
    /// Builds before this one stored a responder session on receipt of a
    /// handshake. If this peer's session under `session_id` is exactly such a
    /// session with nothing done to it since — no message from the peer
    /// authenticated, nothing sent, nothing pending — it has no more
    /// authority than a recorded handshake: it is deleted with its handle
    /// and this handshake recorded in its place, in one transaction, only
    /// after this handshake passed the prekey rules above and only while the
    /// prekey record is still the one it passed them against. The one-time
    /// prekey the old session consumed stays consumed. Any other session is
    /// refused as above.
    pub fn establish_session_responder(
        &self,
        session_id: u64,
        initiator_handshake: Vec<u8>,
    ) -> Result<(), CoreError> {
        let identity = self.require_identity()?;
        let our_identity_pk = PublicKey::from(&identity.dh_key).to_bytes();
        let handshake = unpack_initiator_handshake(&initiator_handshake)?;
        let (mut store, messenger) = self.lock()?;
        let record_bytes = Zeroizing::new(store.get(PREKEYS_KEY)?);
        check_answerable(&unpack_prekeys(&record_bytes)?, &handshake)?;
        messenger
            .record_provisional_handshake(
                &mut store,
                our_identity_pk,
                session_id,
                &ProvisionalHandshake {
                    peer_identity_pk: handshake.identity_pk.to_bytes(),
                    handshake: initiator_handshake,
                },
                &ValidatedRecord {
                    key: PREKEYS_KEY.into(),
                    value: record_bytes,
                },
            )
            .map_err(|e| CoreError::messaging(session_id, e))
    }
}

// Plain (non-exported) impl block: helpers here are NOT visible to UniFFI,
// unlike methods inside the `#[uniffi::export] impl ArciumCore` block above,
// where export applies to every method regardless of Rust-level visibility.
impl ArciumCore {
    /// Locks the store, then the messenger (the only lock order used).
    #[allow(clippy::type_complexity)]
    fn lock(
        &self,
    ) -> Result<
        (
            std::sync::MutexGuard<'_, EncryptedStore>,
            std::sync::MutexGuard<'_, Messenger>,
        ),
        CoreError,
    > {
        let poisoned = |_| CoreError::Storage {
            msg: "mutex poisoned".into(),
        };
        let store = self.store.lock().map_err(poisoned)?;
        let messenger = self.messenger.lock().map_err(|_| CoreError::Storage {
            msg: "mutex poisoned".into(),
        })?;
        Ok((store, messenger))
    }

    /// Whether the session under `session_id` is a responder session an
    /// older build stored on receipt of a handshake, untouched since
    /// (`Messenger::is_legacy_unconfirmed`). Read-only: it decides nothing
    /// and changes nothing; `establish_session_responder` is what may retire
    /// such a session, after its own checks.
    pub(crate) fn is_legacy_unconfirmed(&self, session_id: u64) -> Result<bool, CoreError> {
        let our = self.our_identity_pk()?;
        let (mut store, messenger) = self.lock()?;
        messenger
            .is_legacy_unconfirmed(&mut store, our, session_id)
            .map_err(|e| CoreError::messaging(session_id, e))
    }

    /// Records `initiator_handshake`, received from the peer of this
    /// device's own unconfirmed initiator session, or of an established
    /// session (a possible restart, option B), under `session_id`, beside
    /// that session (`Messenger::record_handshake_beside`,
    /// docs/S2-B2-DURABLE-MESSAGING.md section 4c). It is checked against
    /// this device's prekeys first, by the rules of
    /// `establish_session_responder`, and refused with the same errors when
    /// it cannot be answered. Nothing is consumed and no session changes.
    /// The record has no authority: nothing is derived from it until a
    /// message authenticates under it (`beside_authenticates`).
    pub(crate) fn record_handshake_beside(
        &self,
        session_id: u64,
        initiator_handshake: &[u8],
    ) -> Result<(), CoreError> {
        let identity = self.require_identity()?;
        let our_identity_pk = PublicKey::from(&identity.dh_key).to_bytes();
        let handshake = unpack_initiator_handshake(initiator_handshake)?;
        let (mut store, messenger) = self.lock()?;
        let record_bytes = Zeroizing::new(store.get(PREKEYS_KEY)?);
        check_answerable(&unpack_prekeys(&record_bytes)?, &handshake)?;
        messenger
            .record_handshake_beside(
                &mut store,
                our_identity_pk,
                session_id,
                &ProvisionalHandshake {
                    peer_identity_pk: handshake.identity_pk.to_bytes(),
                    handshake: initiator_handshake.to_vec(),
                },
            )
            .map_err(|e| CoreError::messaging(session_id, e))
    }

    /// Replaces this device's one-time prekey once, the first time a build
    /// with option B runs on a store, and records that it did, in one
    /// transaction. Earlier builds kept the prekey when their own session
    /// was confirmed, so a genuine handshake of a contact built from it,
    /// which this device never saw (withheld by the relay during a
    /// simultaneous start the contact then gave up), could still be
    /// answered, and with its first message replace an established session
    /// (`docs/NET-MESSAGING.md` section 8). After this, as after every
    /// confirmation, it cannot. The cost: another contact's first contact
    /// or restart in flight under the old prekey is refused once and made
    /// again, its texts reading `NotDelivered` (a restart a contact made
    /// while this device ran an earlier build is one). The previous signed
    /// prekey goes too (`PrekeyRecord::renew_one_time_prekey`), and the
    /// round's rotation check then rotates the signed prekey ((E),
    /// `plan_rotation`).
    /// With no prekey record yet, only the mark is written. A mark that
    /// cannot be read counts as written: it must not stop every round.
    pub(crate) fn replace_prekey_once(&self) -> Result<(), CoreError> {
        let mut store = self.store.lock().map_err(|_| CoreError::Storage {
            msg: "mutex poisoned".into(),
        })?;
        match store.get(PREKEY_RENEWED_KEY) {
            Ok(_) | Err(StorageError::Decryption) => return Ok(()),
            Err(StorageError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        let tx = store.transaction()?;
        // Read again under the write lock: another connection to this
        // database may have done it meanwhile.
        match tx.get(PREKEY_RENEWED_KEY) {
            Ok(_) | Err(StorageError::Decryption) => return Ok(()),
            Err(StorageError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        match tx.get(PREKEYS_KEY) {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                let mut record = unpack_prekeys(&bytes)?;
                if record.opk.is_some() {
                    record.renew_one_time_prekey();
                    tx.put(PREKEYS_KEY, &pack_prekeys(&record))?;
                }
            }
            Err(StorageError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        tx.put(PREKEY_RENEWED_KEY, &[1])?;
        tx.commit()?;
        Ok(())
    }

    /// Creates this device's prekey record if none exists, or rotates its
    /// signed prekey if that is due at `now` (Unix seconds of this device's
    /// clock; `plan_rotation`, tracker R-6), in one transaction that reads
    /// the record again under the write lock, so two instances on one
    /// database create it once and rotate it once. Nothing is written when
    /// nothing is due; `true` when it wrote. A record that cannot be read is
    /// an error: the round fails, as its export would.
    pub(crate) fn maintain_prekeys(&self, now: u64) -> Result<bool, CoreError> {
        let identity = self.require_identity()?;
        let mut store = self.store.lock().map_err(|_| CoreError::Storage {
            msg: "mutex poisoned".into(),
        })?;
        // Most rounds have nothing to do: a plain read first, so they take
        // no write lock (as before rotation existed).
        match store.get(PREKEYS_KEY) {
            Ok(bytes) => {
                if plan_rotation(&unpack_prekeys(&Zeroizing::new(bytes))?, now).is_none() {
                    return Ok(false);
                }
            }
            Err(StorageError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        #[cfg(test)]
        prekey_hooks::after_plain_read();
        // Dropping `tx` on an early return rolls it back.
        let tx = store.transaction()?;
        let record = match tx.get(PREKEYS_KEY) {
            Ok(bytes) => {
                let mut record = unpack_prekeys(&Zeroizing::new(bytes))?;
                let Some(rotation) = plan_rotation(&record, now) else {
                    return Ok(false);
                };
                rotate_signed_prekey(&mut record, &identity, rotation);
                record
            }
            Err(StorageError::NotFound) => PrekeyRecord::new(&identity),
            Err(e) => return Err(e.into()),
        };
        #[cfg(test)]
        prekey_hooks::before_maintenance_write();
        tx.put(PREKEYS_KEY, &pack_prekeys(&record))?;
        tx.commit()?;
        Ok(true)
    }

    /// Records that the relay accepted a bundle naming the signed prekey
    /// `spk` at `now`, if that is the current signed prekey and no
    /// acceptance of it was recorded yet: from then on it ages
    /// (`plan_rotation`). Opens a transaction only when it writes, and reads
    /// the record again inside it.
    pub(crate) fn note_prekeys_published(
        &self,
        spk: &[u8; SPK_ID_LEN],
        now: u64,
    ) -> Result<(), CoreError> {
        let due = |record: &PrekeyRecord| {
            record.published_at == PUBLISHED_NOT_YET
                && spk_id(record.signed_prekey_pk().as_bytes()) == *spk
        };
        #[cfg(test)]
        if prekey_hooks::fail_note() {
            return Err(CoreError::Storage {
                msg: "test: the publication note fails".into(),
            });
        }
        let mut store = self.store.lock().map_err(|_| CoreError::Storage {
            msg: "mutex poisoned".into(),
        })?;
        if !due(&unpack_prekeys(&Zeroizing::new(store.get(PREKEYS_KEY)?))?) {
            return Ok(());
        }
        let tx = store.transaction()?;
        let mut record = unpack_prekeys(&Zeroizing::new(tx.get(PREKEYS_KEY)?))?;
        if !due(&record) {
            return Ok(());
        }
        // 0 means "not yet": a clock before 1970 still records a publication.
        record.published_at = now.max(PUBLISHED_LONG_AGO);
        tx.put(PREKEYS_KEY, &pack_prekeys(&record))?;
        tx.commit()?;
        Ok(())
    }

    /// Whether `handshake` from `peer` is the handshake this device's latest
    /// responder session with `peer` came from, in any encoding that derives
    /// the same keys ([`handshake_identity`], [`accepted_handshake_key`]).
    /// `false` if it does not parse, and if no such session was recorded:
    /// none exists, an older build stored it, or the record cannot be read
    /// (which must not stop a round).
    pub(crate) fn is_accepted_handshake(&self, peer: &[u8; 32], handshake: &[u8]) -> Result<bool, CoreError> {
        let Ok(parsed) = unpack_initiator_handshake(handshake) else {
            return Ok(false);
        };
        let store = self.store.lock().map_err(|_| CoreError::Storage {
            msg: "mutex poisoned".into(),
        })?;
        match store.get(&accepted_handshake_key(peer)) {
            Ok(bytes) => Ok(bytes.as_slice() == handshake_identity(&parsed)),
            Err(StorageError::NotFound | StorageError::Decryption) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Whether `wire`, a message from `peer` that did not decrypt under this
    /// device's own session under `session_id`, authenticates as `peer`'s
    /// first message under a handshake recorded beside that session. X3DH
    /// runs from the recorded handshake against the prekeys held now,
    /// checked again by the same rules as for a promotion, with the one-time
    /// prekey only read, and the message is decrypted on that result in
    /// memory (`Messenger::first_message_authenticates`). Nothing is written
    /// or consumed: the session, the recorded handshake and the prekey
    /// record stay exactly as they are.
    ///
    /// `false` when no handshake is recorded beside the session, when it
    /// names another peer, and when it can no longer be answered (its
    /// one-time prekey was consumed, or its signed prekey is neither the
    /// current nor the previous one): without that key no message can
    /// authenticate under it here.
    pub(crate) fn beside_authenticates(
        &self,
        session_id: u64,
        peer: &[u8; 32],
        wire: &[u8],
    ) -> Result<bool, CoreError> {
        let identity = self.require_identity()?;
        let (store, messenger) = self.lock()?;
        let map = |e| CoreError::messaging(session_id, e);
        let Some(provisional) = messenger
            .provisional_handshake(&store, session_id)
            .map_err(map)?
        else {
            return Ok(false);
        };
        if provisional.peer_identity_pk != *peer {
            return Ok(false);
        }
        let handshake = unpack_initiator_handshake(&provisional.handshake)?;
        if handshake.identity_pk.to_bytes() != *peer {
            return Ok(false);
        }
        let record = unpack_prekeys(&Zeroizing::new(store.get(PREKEYS_KEY)?))?;
        let Ok(which) = check_answerable(&record, &handshake) else {
            return Ok(false);
        };
        let our_identity_pk = PublicKey::from(&identity.dh_key);
        let session = responder_session(
            &identity,
            our_identity_pk,
            record.signed_prekey(which)?,
            record.opk.as_ref().map(|(_, sk)| sk),
            &handshake,
        )?;
        messenger
            .first_message_authenticates(our_identity_pk.to_bytes(), session, wire)
            .map_err(map)
    }

    /// A `HANDSHAKE_REFUSAL_V1` from this device for `handshake`,
    /// which `initiator_dh_pk` sent and this device could not answer.
    /// `None` if `initiator_dh_pk` is of low order: no tag can be made for
    /// it, and no refusal is sent.
    pub(crate) fn make_handshake_refusal(
        &self,
        initiator_dh_pk: [u8; 32],
        handshake: &[u8],
        reason: RefusalReason,
    ) -> Result<Option<Vec<u8>>, CoreError> {
        let identity = self.require_identity()?;
        let refuser_dh_pk = PublicKey::from(&identity.dh_key).to_bytes();
        let refusal = HandshakeRefusal {
            refuser_dh_pk,
            initiator_dh_pk,
            handshake_hash: handshake_hash(handshake),
            reason,
        };
        let fields = refusal.fields();
        let tag = core_crypto::refusal_mac::refusal_tag(
            &identity.dh_key,
            &initiator_dh_pk,
            &refuser_dh_pk,
            &initiator_dh_pk,
            &fields,
        );
        Ok(tag.map(|tag| [&fields[..], &tag[..]].concat()))
    }

    /// The refusal `bytes` if it is a refusal by `refuser_dh_pk` of a
    /// handshake from this device whose tag checks; see
    /// [`HandshakeRefusal::open`].
    pub(crate) fn open_handshake_refusal(
        &self,
        bytes: &[u8],
        refuser_dh_pk: &[u8; 32],
    ) -> Result<Option<HandshakeRefusal>, CoreError> {
        let identity = self.require_identity()?;
        Ok(HandshakeRefusal::open(bytes, &identity.dh_key, refuser_dh_pk))
    }

    /// Writes the X25519 of this device's identity secret with `public` into
    /// `out`, a buffer the caller owns and wipes (the relay client's), and
    /// returns `true`. `false`, with `out` untouched, if the output is all
    /// zeros (`public` is of low order): anyone could compute that value.
    /// For the mailbox authentication of a `RELAY_PROTOCOL_V2` relay, where
    /// `public` is the relay's auth key (docs/NET-MESSAGING.md, section 3);
    /// the relay crate separates that derivation from every other use of the
    /// identity key by its own HKDF salt and label. The identity secret never
    /// leaves this type. Not exported: this impl block is not
    /// `#[uniffi::export]`, and `tests::ack_probe` keeps it so.
    pub(crate) fn identity_dh(&self, public: &[u8; 32], out: &mut [u8; 32]) -> Result<bool, CoreError> {
        let identity = self.require_identity()?;
        // `SharedSecret` wipes itself on drop.
        let shared = identity.dh_key.diffie_hellman(&PublicKey::from(*public));
        if !shared.was_contributory() {
            return Ok(false);
        }
        out.copy_from_slice(shared.as_bytes());
        Ok(true)
    }

    fn our_identity_pk(&self) -> Result<[u8; 32], CoreError> {
        Ok(PublicKey::from(&self.require_identity()?.dh_key).to_bytes())
    }

    fn require_identity(&self) -> Result<Arc<Identity>, CoreError> {
        self.load_identity()?
            .ok_or_else(|| CoreError::InvalidKey { msg: "no identity saved — call save_identity first".into() })
    }
}

/// Test aids for the prekey maintenance of a round (tracker R-6), per
/// thread, each one-shot: a closure run after maintenance's read without a
/// transaction, before its transaction begins; a closure run inside the
/// maintenance transaction just before it writes; and a failure of the
/// publication note.
#[cfg(test)]
pub(crate) mod prekey_hooks {
    use std::cell::{Cell, RefCell};

    type Hook = Box<dyn FnOnce()>;

    thread_local! {
        static BEFORE_WRITE: RefCell<Option<Hook>> = RefCell::new(None);
        static AFTER_PLAIN_READ: RefCell<Option<Hook>> = RefCell::new(None);
        static FAIL_NOTE: Cell<bool> = const { Cell::new(false) };
    }

    /// Runs once, in maintenance that found something due, after its read
    /// without a transaction and before its transaction begins.
    pub(crate) fn set_after_plain_read(hook: impl FnOnce() + 'static) {
        AFTER_PLAIN_READ.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }

    pub(super) fn after_plain_read() {
        if let Some(hook) = AFTER_PLAIN_READ.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }

    pub(crate) fn set_before_maintenance_write(hook: impl FnOnce() + 'static) {
        BEFORE_WRITE.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }

    pub(super) fn before_maintenance_write() {
        if let Some(hook) = BEFORE_WRITE.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }

    pub(crate) fn fail_next_note() {
        FAIL_NOTE.with(|f| f.set(true));
    }

    pub(super) fn fail_note() -> bool {
        FAIL_NOTE.with(|f| f.replace(false))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
