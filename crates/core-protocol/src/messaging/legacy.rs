//! Responder sessions stored by builds before ARCIUM-SESSION-CONFIRMATION-001.
//!
//! Those builds stored a responder session as soon as a handshake arrived:
//! `session:v1/<peer>` at generation 0 with the ratchet exactly as
//! `DoubleRatchet::init_bob` creates it, and `handle:v1/<handle>`. Until a
//! message from the peer authenticated under it, that session carried
//! nothing but an unauthenticated handshake's result — yet it held the
//! peer's slot, and every later handshake from the peer was refused.
//!
//! Such a session, and only such a session, is retired when a later
//! handshake from the same peer is recorded: in one transaction its session
//! and handle records are deleted and the new handshake is recorded as
//! provisional ([`Messenger::record_provisional_handshake`]). From there the
//! ordinary first-contact rules apply. A session that has authenticated a
//! message from the peer, has sent anything, or is not exactly in that
//! shape is never retired. Specification: `docs/S2-B2-DURABLE-MESSAGING.md`,
//! section 4b.
//!
//! What retirement does not touch: the prekey record (the one-time prekey the
//! old session consumed stays consumed), `seen:` and `sendid:` records, and
//! everything outside this peer's session, handle and provisional records.

use core_storage::{EncryptedStore, StorageError};
use zeroize::Zeroizing;

use super::helpers::{commit_repeatable, keys_under};
use super::records::*;
use super::{MessagingError, Messenger, ValidatedRecord};
use crate::checkpoint::session_storage_key;
use crate::durable::Conflict;

impl Messenger {
    /// Whether the session under `handle` is a legacy unconfirmed responder
    /// session ([`DurableSession::is_legacy_unconfirmed`](crate::durable::DurableSession::is_legacy_unconfirmed)):
    /// the only kind a later handshake may retire. Read-only.
    ///
    /// `Ok(false)` when there is no session, and when the stored session
    /// cannot be read or is bound to other identities: a record that does
    /// not decode is never eligible. Durable obligations (pending messages,
    /// a stored initiator handshake) are not checked here; the retirement
    /// checks them.
    pub fn is_legacy_unconfirmed(
        &self,
        store: &mut EncryptedStore,
        our_identity_pk: [u8; 32],
        handle: u64,
    ) -> Result<bool, MessagingError> {
        match self.load(store, our_identity_pk, handle) {
            Ok((session, _)) => Ok(session.is_legacy_unconfirmed()),
            Err(
                MessagingError::NoSession { .. }
                | MessagingError::MissingSession { .. }
                | MessagingError::InvalidSession(_),
            ) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Retires the legacy session under `handle` and records `provisional`
    /// (encoded) in its place. Called by
    /// [`record_provisional_handshake`](Self::record_provisional_handshake)
    /// once the handle is known to name the handshake's peer.
    ///
    /// Refused, with nothing written:
    /// - [`MessagingError::Unresolved`] while a commit on the handle has an
    ///   unknown outcome in this instance;
    /// - [`MessagingError::AlreadyExists`] for any session that is not
    ///   legacy unconfirmed, including one that cannot be read;
    /// - [`MessagingError::SessionNotRetirable`] for a legacy-shaped session
    ///   with pending outgoing or incoming messages, a stored initiator
    ///   handshake, or a provisional record already beside it;
    /// - [`MessagingError::Conflict`] if the session, its handle or
    ///   `validated_against` changed since they were read here.
    pub(super) fn retire_legacy(
        &self,
        store: &mut EncryptedStore,
        our_identity_pk: [u8; 32],
        handle: u64,
        provisional: &[u8],
        validated_against: &ValidatedRecord,
    ) -> Result<(), MessagingError> {
        self.require_resolved(handle)?;
        if validated_against.key.starts_with("session:") {
            return Err(MessagingError::InvalidRecord("validated record key"));
        }
        let (session, peer) = match self.load(store, our_identity_pk, handle) {
            Ok(loaded) => loaded,
            Err(MessagingError::MissingSession { .. } | MessagingError::InvalidSession(_)) => {
                return Err(MessagingError::AlreadyExists { handle })
            }
            Err(e) => return Err(e),
        };
        if !session.is_legacy_unconfirmed() {
            return Err(MessagingError::AlreadyExists { handle });
        }
        // Obligations that only a transition of this very session record can
        // add: `send` writes the outbox and `receive` the inbox in the same
        // transaction as a new session record. So if the record is still the
        // one loaded above when the transaction below checks it, there are
        // still none.
        if !keys_under(store, OUTBOX_NAMESPACE, &outbox_prefix(&peer))?.is_empty() {
            return Err(MessagingError::SessionNotRetirable("pending outgoing messages"));
        }
        if !keys_under(store, INBOX_NAMESPACE, &inbox_prefix(&peer))?.is_empty() {
            return Err(MessagingError::SessionNotRetirable("pending incoming messages"));
        }
        #[cfg(test)]
        super::race_hook::run();

        let session_key = session_storage_key(&peer);
        let tx = store.transaction().map_err(MessagingError::NotCommitted)?;
        // Exactly the record classified above (SHA-256 of its bytes).
        match tx.get(&session_key).map(Zeroizing::new) {
            Ok(record) if session.holds_record(&record) => {}
            Ok(_) | Err(StorageError::NotFound | StorageError::Decryption) => {
                return Err(MessagingError::Conflict(Conflict::RecordChanged))
            }
            Err(e) => return Err(MessagingError::Store(e)),
        }
        match tx.get(&handle_key(handle)).map(Zeroizing::new) {
            Ok(bytes) if *bytes == **encode_handle(&peer) => {}
            Ok(_) | Err(StorageError::NotFound | StorageError::Decryption) => {
                return Err(MessagingError::Conflict(Conflict::RecordChanged))
            }
            Err(e) => return Err(MessagingError::Store(e)),
        }
        for (key, reason) in [
            (handshake_key(&peer), "an initiator handshake is stored"),
            (provisional_key(handle), "a provisional handshake is already recorded"),
        ] {
            match tx.get(&key) {
                Err(StorageError::NotFound) => {}
                Ok(_) | Err(StorageError::Decryption) => {
                    return Err(MessagingError::SessionNotRetirable(reason))
                }
                Err(e) => return Err(MessagingError::Store(e)),
            }
        }
        match tx.get(&validated_against.key).map(Zeroizing::new) {
            Ok(bytes) if *bytes == *validated_against.value => {}
            Ok(_) | Err(StorageError::NotFound | StorageError::Decryption) => {
                return Err(MessagingError::Conflict(Conflict::RecordChanged))
            }
            Err(e) => return Err(MessagingError::Store(e)),
        }
        tx.delete(&session_key)
            .map_err(MessagingError::NotCommitted)?;
        tx.delete(&handle_key(handle))
            .map_err(MessagingError::NotCommitted)?;
        tx.put(&provisional_key(handle), provisional)
            .map_err(MessagingError::NotCommitted)?;
        #[cfg(test)]
        crate::durable::test_hooks::crash_point("retire_before_commit");
        commit_repeatable(tx)?;
        #[cfg(test)]
        crate::durable::test_hooks::crash_point("retire_after_commit");
        Ok(())
    }
}

/// Whether one consistent read shows that the legacy session of `peer`
/// under `handle` was retired and that none of `artifact_keys` — the records
/// of a receive staged on it whose commit outcome is unknown — exists: no
/// session record, no handle record, a provisional handshake from `peer`
/// recorded under `handle`.
///
/// Under that reading the receive did not take effect: had it committed, the
/// session would have a receiving chain and could not have been retired, and
/// its inbox or seen record would exist (retirement deletes neither). This
/// rests on the store not having been replaced by an older copy.
pub(super) fn retired_since(
    store: &mut EncryptedStore,
    handle: u64,
    peer: &[u8; 32],
    artifact_keys: &[String],
) -> Result<bool, MessagingError> {
    let tx = store.transaction().map_err(MessagingError::Store)?;
    let absent = |key: &str| match tx.get(key) {
        Err(StorageError::NotFound) => Ok(true),
        Ok(_) | Err(StorageError::Decryption) => Ok(false),
        Err(e) => Err(MessagingError::Store(e)),
    };
    for key in [session_storage_key(peer), handle_key(handle)]
        .iter()
        .chain(artifact_keys)
    {
        if !absent(key)? {
            return Ok(false);
        }
    }
    let recorded = match tx.get(&provisional_key(handle)) {
        Ok(bytes) => decode_provisional(&bytes).is_ok_and(|p| p.peer_identity_pk == *peer),
        Err(StorageError::NotFound | StorageError::Decryption) => false,
        Err(e) => return Err(MessagingError::Store(e)),
    };
    // Read only: dropping the transaction rolls it back.
    Ok(recorded)
}
