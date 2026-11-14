//! A handshake recorded beside this device's own unconfirmed session (R-13,
//! option A of `docs/SESSION-RECOVERY-OPTIONS.md`). Specification:
//! `docs/S2-B2-DURABLE-MESSAGING.md`, section 4c.
//!
//! When both devices start a session with each other, each receives the
//! other's handshake while it holds an unconfirmed initiator session of its
//! own. A handshake is public bytes, so it proves nothing about who sent
//! it. It is recorded under the same key a responder's provisional
//! handshake uses (`hsin:v1/<handle>`), with the same lack of authority: a
//! later handshake replaces it, and it never becomes a session while ours
//! exists. The only thing it is used for is to check, without storing or
//! consuming anything, whether a message from the peer that does not
//! decrypt under our session authenticates as the peer's first message
//! under it ([`Messenger::first_message_authenticates`]). Only that needs
//! the peer's identity secret.
//!
//! It goes when our session is confirmed (a message from the peer committed
//! on it: [`discard_beside`] in [`Messenger::receive`]), removed
//! ([`Messenger::remove_session`]) or forgotten ([`Messenger::forget_peer`]).

use core_crypto::ratchet::{Header, HEADER_SIZE};
use core_storage::{EncryptedStore, StorageError};
use zeroize::Zeroizing;

use super::helpers::{commit_repeatable, stage_error};
use super::records::*;
use super::{MessagingError, Messenger, ProvisionalHandshake};
use crate::checkpoint::{session_storage_key, SessionRole};
use crate::durable::{Conflict, ProvisionalSession, SideWrite, StageError};
use crate::Session;

impl Messenger {
    /// Records `provisional` — a handshake from the peer of the session under
    /// `handle`, not authenticated by anything — beside that session, which
    /// must be this device's own initiator session on which nothing from the
    /// peer has been received yet. Replaces a handshake recorded there
    /// before; recording the same one again changes nothing. Creates
    /// nothing, consumes nothing and leaves the session record as it is.
    ///
    /// Refused, with nothing written:
    /// - [`MessagingError::Unresolved`] while a commit on the handle has an
    ///   unknown outcome in this instance;
    /// - [`MessagingError::NoSession`] if no session is registered under
    ///   `handle`, [`MessagingError::HandleCollision`] if it belongs to
    ///   another peer;
    /// - [`MessagingError::AlreadyExists`] for any other session: a
    ///   responder session, one that has received a message from the peer
    ///   (the peer holds it), or one whose record cannot be read;
    /// - [`MessagingError::Conflict`] if the session or its handle changed
    ///   since they were read here (a receive committed meanwhile, for
    ///   example, which confirms the session).
    ///
    /// The checks of the session and handle records and the write are one
    /// transaction. After [`MessagingError::RepeatableOutcomeUnknown`] the
    /// call can be repeated.
    pub fn record_handshake_beside(
        &self,
        store: &mut EncryptedStore,
        our_identity_pk: [u8; 32],
        handle: u64,
        provisional: &ProvisionalHandshake,
    ) -> Result<(), MessagingError> {
        self.require_resolved(handle)?;
        let record = encode_provisional(provisional)?;
        let peer = provisional.peer_identity_pk;
        let (session, owner) = match self.load(store, our_identity_pk, handle) {
            Ok(loaded) => loaded,
            Err(MessagingError::MissingSession { .. } | MessagingError::InvalidSession(_)) => {
                return Err(MessagingError::AlreadyExists { handle })
            }
            Err(e) => return Err(e),
        };
        if owner != peer {
            return Err(MessagingError::HandleCollision { handle });
        }
        if session.role() != SessionRole::Initiator || session.has_received() {
            return Err(MessagingError::AlreadyExists { handle });
        }
        #[cfg(test)]
        super::race_hook::run();

        let tx = store.transaction().map_err(MessagingError::NotCommitted)?;
        // Exactly the record classified above (SHA-256 of its bytes): any
        // transition since, a receive that confirms it included, changed it.
        match tx.get(&session_storage_key(&peer)).map(Zeroizing::new) {
            Ok(stored) if session.holds_record(&stored) => {}
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
        let key = provisional_key(handle);
        match tx.get(&key) {
            Ok(stored) if stored == *record => return Ok(()),
            // Another handshake, or a row that no longer authenticates:
            // neither has any authority, so both are replaced.
            Ok(_) | Err(StorageError::NotFound | StorageError::Decryption) => {}
            Err(e) => return Err(MessagingError::Store(e)),
        }
        tx.put(&key, &record).map_err(MessagingError::NotCommitted)?;
        #[cfg(test)]
        crate::durable::test_hooks::crash_point("beside_before_commit");
        commit_repeatable(tx)?;
        #[cfg(test)]
        crate::durable::test_hooks::crash_point("beside_after_commit");
        Ok(())
    }

    /// Whether `wire` authenticates as the peer's first message under
    /// `session`: the responder's X3DH result for a handshake recorded
    /// beside this device's own session, held only in memory. The AEAD
    /// verifies only under keys derived with the secret of the identity key
    /// the handshake names (or with this device's own secrets), so `true`
    /// is evidence that the peer made the message. It is never a session:
    /// nothing is stored, nothing is consumed, and the decrypted plaintext
    /// and staged state are dropped (and wiped) here.
    ///
    /// `false` for anything that does not authenticate, including bytes that
    /// are not a message. An error if `session` is not one this device could
    /// have derived (its AD is not the X3DH AD of the two identities); the
    /// other staging errors are mapped as for a promotion, and a fresh
    /// session does not produce them.
    pub fn first_message_authenticates(
        &self,
        our_identity_pk: [u8; 32],
        session: Session,
        wire: &[u8],
    ) -> Result<bool, MessagingError> {
        if wire.len() < HEADER_SIZE {
            return Ok(false);
        }
        let (header_bytes, ciphertext) = wire.split_at(HEADER_SIZE);
        let Ok(header) = Header::from_bytes(header_bytes) else {
            return Ok(false);
        };
        let candidate = ProvisionalSession::new(session, SessionRole::Responder, our_identity_pk)
            .map_err(MessagingError::Checkpoint)?;
        match candidate.stage_first_decrypt(&header, ciphertext) {
            Ok(staged) => {
                drop(staged);
                Ok(true)
            }
            Err(StageError::Ratchet(_)) => Ok(false),
            Err(e) => Err(stage_error(e)),
        }
    }
}

/// The side write with which a message from `peer`, committed on its
/// session under `handle`, discards a handshake recorded beside that
/// session: once a message from the peer authenticated under our session,
/// the peer holds it, and a handshake beside it is moot.
///
/// The record is deleted only if it is still exactly the one read here, and
/// a record found absent here must still be absent at commit: so after the
/// commit none is left beside the session, also when another connection
/// recorded one in between (the commit then fails and the receive is
/// repeated). A record that names another peer (a colliding handle) is not
/// this peer's, and one that cannot be read cannot be compared; neither is
/// touched or checked (the peer's next handshake replaces an unreadable
/// one, and `forget_peer` deletes it).
pub(super) fn discard_beside(
    store: &EncryptedStore,
    handle: u64,
    peer: &[u8; 32],
) -> Result<Option<SideWrite>, MessagingError> {
    let key = provisional_key(handle);
    let write = match store.get(&key) {
        Ok(bytes) => match decode_provisional(&bytes) {
            Ok(p) if p.peer_identity_pk == *peer => SideWrite::remove(key, Zeroizing::new(bytes)),
            _ => return Ok(None),
        },
        Err(StorageError::NotFound) => SideWrite::require_absent(key),
        Err(StorageError::Decryption) => return Ok(None),
        Err(e) => return Err(MessagingError::Store(e)),
    };
    write.map(Some).map_err(MessagingError::SideWrite)
}
