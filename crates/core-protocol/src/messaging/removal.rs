//! Ending a session's obligations: [`Messenger::abandon_outgoing`] and
//! [`Messenger::remove_session`]. Specification:
//! `docs/S2-B2-DURABLE-MESSAGING.md`, section 6a.

use core_storage::{EncryptedStore, StorageError};
use zeroize::Zeroizing;

use super::helpers::{commit_repeatable, keys_under};
use super::records::*;
use super::{MessageId, MessagingError, Messenger};
use crate::checkpoint::session_storage_key;
use crate::durable::Conflict;

impl Messenger {
    /// Gives up on the pending outgoing message `id` without claiming it was
    /// delivered: it leaves the outbox, and its logical id is recorded as
    /// abandoned, so [`send`](Self::send) with that id reports
    /// [`SendOutcome::Abandoned`](super::SendOutcome::Abandoned) instead of
    /// encrypting it again. The peer may or may not have received it.
    ///
    /// Returns whether it was still pending; repeating it is harmless.
    pub fn abandon_outgoing(
        &self,
        store: &mut EncryptedStore,
        handle: u64,
        id: &MessageId,
    ) -> Result<bool, MessagingError> {
        let peer = self.require_peer(store, handle)?;
        let key = outbox_key(&peer, id);
        let tx = store.transaction().map_err(MessagingError::NotCommitted)?;
        let message = match tx.get(&key) {
            Ok(bytes) => decode_outbox(&Zeroizing::new(bytes))?,
            Err(StorageError::NotFound) => return Ok(false),
            Err(e) => return Err(MessagingError::Store(e)),
        };
        tx.delete(&key).map_err(MessagingError::NotCommitted)?;
        tx.put(
            &sendid_key(&peer, &message.client_message_id),
            &encode_id_record(ABANDONED_MAGIC, id),
        )
        .map_err(MessagingError::NotCommitted)?;
        commit_repeatable(tx)?;
        Ok(true)
    }

    /// Deletes the session under `handle` — its checkpoint, handle record
    /// and stored handshake — in one transaction, so that a new session with
    /// that peer can be created (for example after the peer refused this
    /// session's handshake). Duplicate-detection and send-id records stay.
    ///
    /// Only a session with no obligations left is removed. Refused, with
    /// nothing changed:
    /// - [`MessagingError::Unresolved`] while a commit on it has an unknown
    ///   outcome;
    /// - [`MessagingError::InvalidSession`] or
    ///   [`MessagingError::MissingSession`] if its record cannot be read;
    /// - [`MessagingError::SessionEstablished`] once it has committed a
    ///   message from the peer, which then holds the session too;
    /// - [`MessagingError::PendingOutgoing`] while outgoing messages are
    ///   neither acknowledged nor abandoned;
    /// - [`MessagingError::Conflict`] if the session changed while this ran.
    ///
    /// Local removal proves nothing about the peer: a peer that accepted the
    /// handshake keeps its session and refuses a new one for this identity.
    /// After [`MessagingError::RepeatableOutcomeUnknown`], calling this again
    /// reports [`MessagingError::NoSession`] if the removal took effect.
    pub fn remove_session(
        &mut self,
        store: &mut EncryptedStore,
        our_identity_pk: [u8; 32],
        handle: u64,
    ) -> Result<(), MessagingError> {
        self.require_resolved(handle)?;
        let (session, peer) = self.load(store, our_identity_pk, handle)?;
        if session.has_received() {
            return Err(MessagingError::SessionEstablished);
        }
        let pending = keys_under(store, OUTBOX_NAMESPACE, &outbox_prefix(&peer))?.len();
        if pending > 0 {
            return Err(MessagingError::PendingOutgoing { count: pending });
        }
        #[cfg(test)]
        super::race_hook::run();

        // Any send or receive committed since the load changed the record,
        // and only those add obligations.
        let session_key = session_storage_key(&peer);
        let tx = store.transaction().map_err(MessagingError::NotCommitted)?;
        match tx.get(&session_key).map(Zeroizing::new) {
            Ok(record) if session.holds_record(&record) => {}
            Ok(_) | Err(StorageError::NotFound) => {
                return Err(MessagingError::Conflict(Conflict::RecordChanged))
            }
            Err(e) => return Err(MessagingError::Store(e)),
        }
        for key in [session_key, handle_key(handle), handshake_key(&peer)] {
            tx.delete(&key).map_err(MessagingError::NotCommitted)?;
        }
        #[cfg(test)]
        crate::durable::test_hooks::crash_point("remove_before_commit");
        commit_repeatable(tx)?;
        #[cfg(test)]
        crate::durable::test_hooks::crash_point("remove_after_commit");
        Ok(())
    }
}
