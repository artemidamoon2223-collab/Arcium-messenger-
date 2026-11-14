//! Ending a session's obligations: [`Messenger::abandon_outgoing`] and
//! [`Messenger::remove_session`]; and discarding them on the user's explicit
//! decision: [`Messenger::forget_peer`]. Specification:
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

    /// Forgets `peer`, on the user's explicit decision to delete the contact:
    /// removes everything this store keeps for it, whatever state its
    /// session is in (established, unconfirmed, unreadable or absent).
    /// `handle` is the handle the peer's session is registered under.
    ///
    /// Removed in one transaction: the session record, the handle record,
    /// the stored initiator handshake, the provisional handshake under
    /// `handle` (unless it names another peer), every pending outgoing and
    /// incoming message of the peer, and `also_delete` — the caller's own
    /// records for the peer, which must not name a record of this module.
    /// Each pending outgoing message's send-id record is rewritten as
    /// abandoned in the same transaction, as by
    /// [`abandon_outgoing`](Self::abandon_outgoing), so [`send`](Self::send)
    /// and [`prior_send`](Self::prior_send) report it
    /// [`Abandoned`](super::SendOutcome::Abandoned), never acknowledged:
    /// only a receipt acknowledges. An outbox record that cannot be read is
    /// deleted as it is; its send-id record, if any, then reads as
    /// acknowledged (a limit of a damaged store).
    ///
    /// Kept: the `seen:` and `sendid:` records, as after
    /// [`remove_session`](Self::remove_session), so a message already seen is
    /// still a duplicate under a later session and no logical id is
    /// encrypted twice.
    ///
    /// Unlike `remove_session`, this discards obligations: texts not yet
    /// acknowledged are never sent again, and incoming messages the
    /// application has not acknowledged are gone. The peer is told nothing
    /// and keeps its own session; the two can start a new one only once both
    /// have forgotten each other.
    ///
    /// Refused, with nothing changed:
    /// - [`MessagingError::Unresolved`] while a commit on `handle` has an
    ///   unknown outcome;
    /// - [`MessagingError::HandleCollision`] if `handle` belongs to another
    ///   peer.
    ///
    /// A store transaction cannot list keys, so the pending messages are
    /// listed before it. A send or receive another connection commits in
    /// between leaves its record behind; so the listing is repeated after the
    /// commit, and whatever it finds is removed the same way in a second
    /// transaction. If records are still found after that, the call fails
    /// with [`MessagingError::Conflict`] and is to be repeated. After
    /// [`MessagingError::RepeatableOutcomeUnknown`], repeating the call is
    /// safe and reports what the store holds.
    pub fn forget_peer(
        &mut self,
        store: &mut EncryptedStore,
        handle: u64,
        peer: &[u8; 32],
        also_delete: &[String],
    ) -> Result<(), MessagingError> {
        self.require_resolved(handle)?;
        let listed = pending_keys(store, peer)?;
        forget_listed(store, handle, peer, &listed, also_delete)?;
        #[cfg(test)]
        crate::durable::test_hooks::crash_point("forget_after_commit");
        let late = pending_keys(store, peer)?;
        if late.is_empty() {
            return Ok(());
        }
        forget_listed(store, handle, peer, &late, also_delete)?;
        if pending_keys(store, peer)?.is_empty() {
            Ok(())
        } else {
            Err(MessagingError::Conflict(Conflict::RecordChanged))
        }
    }
}

/// The keys of `peer`'s pending outgoing and incoming messages.
fn pending_keys(store: &EncryptedStore, peer: &[u8; 32]) -> Result<Vec<String>, MessagingError> {
    let mut keys = keys_under(store, OUTBOX_NAMESPACE, &outbox_prefix(peer))?;
    keys.extend(keys_under(store, INBOX_NAMESPACE, &inbox_prefix(peer))?);
    Ok(keys)
}

/// One transaction of [`Messenger::forget_peer`]: deletes `peer`'s session,
/// handle and handshake records, `pending` (listed before it) and
/// `also_delete`, and marks each readable outgoing message in `pending`
/// abandoned. Nothing is written if `handle` belongs to another peer.
fn forget_listed(
    store: &mut EncryptedStore,
    handle: u64,
    peer: &[u8; 32],
    pending: &[String],
    also_delete: &[String],
) -> Result<(), MessagingError> {
    #[cfg(test)]
    super::race_hook::run();
    let tx = store.transaction().map_err(MessagingError::NotCommitted)?;
    match tx.get(&handle_key(handle)) {
        Ok(bytes) => {
            if decode_handle(&bytes).is_ok_and(|owner| owner != *peer) {
                return Err(MessagingError::HandleCollision { handle });
            }
        }
        // Absent, or unreadable: deleted with the rest.
        Err(StorageError::NotFound | StorageError::Decryption) => {}
        Err(e) => return Err(MessagingError::Store(e)),
    }
    let mut delete = vec![
        session_storage_key(peer),
        handle_key(handle),
        handshake_key(peer),
    ];
    match tx.get(&provisional_key(handle)) {
        // Another peer's handshake under a colliding handle is not this
        // peer's to delete.
        Ok(bytes) if decode_provisional(&bytes).is_ok_and(|p| p.peer_identity_pk != *peer) => {}
        Ok(_) | Err(StorageError::NotFound | StorageError::Decryption) => {
            delete.push(provisional_key(handle))
        }
        Err(e) => return Err(MessagingError::Store(e)),
    }
    for key in pending.iter().filter(|k| k.starts_with(OUTBOX_NAMESPACE)) {
        let message = match tx.get(key) {
            Ok(bytes) => decode_outbox(&Zeroizing::new(bytes)).ok(),
            // Settled by another connection since the listing, or
            // unreadable: nothing to mark.
            Err(StorageError::NotFound | StorageError::Decryption) => None,
            Err(e) => return Err(MessagingError::Store(e)),
        };
        if let Some(message) = message {
            tx.put(
                &sendid_key(peer, &message.client_message_id),
                &encode_id_record(ABANDONED_MAGIC, &message.message_id),
            )
            .map_err(MessagingError::NotCommitted)?;
        }
    }
    for key in delete.iter().chain(pending).chain(also_delete) {
        tx.delete(key).map_err(MessagingError::NotCommitted)?;
    }
    #[cfg(test)]
    crate::durable::test_hooks::crash_point("forget_before_commit");
    commit_repeatable(tx)
}
