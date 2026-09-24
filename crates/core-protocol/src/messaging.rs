//! Durable messaging: sessions addressed by a local handle, sends through an
//! outbox, receives through an inbox. Specification:
//! `docs/S2-B2-DURABLE-MESSAGING.md`.
//!
//! Every operation loads the session from the store, stages its transition on
//! a copy, and commits the new checkpoint together with the record that holds
//! the operation's output — the outbox entry for a send, the inbox entry for a
//! receive — in one conditional S1 transaction ([`DurableSession::commit_with`]).
//! The output is returned only after that commit. Nothing is cached between
//! operations, so a second [`Messenger`], connection or process on the same
//! database cannot advance a session from a generation it no longer holds: the
//! later commit is a conflict and releases nothing.
//!
//! # What this does not provide
//!
//! - Power-loss durability beyond what the store's configuration and the
//!   device's `fsync` give (`core-storage`).
//! - Rollback protection: a database file replaced by an older copy is loaded
//!   as it is.
//! - Transport or peer acknowledgement. [`Messenger::acknowledge_outgoing`] is
//!   what a transport would call once delivery is confirmed.

use std::collections::HashMap;

use core_crypto::ratchet::{Header, HEADER_SIZE};
use core_storage::{EncryptedStore, StorageError};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::checkpoint::SessionBinding;
use crate::durable::{
    CommitError, Conflict, DurableSession, OpenError, S1CheckpointStore, SideWrite,
};

/// Length of a [`MessageId`].
pub const MESSAGE_ID_LEN: usize = 32;

/// Identifies one exact message artifact: `SHA-256("ARCIUM-MESSAGE-ID-V1" ||
/// wire)`. Both peers derive the same id from the same bytes; it is never
/// transmitted and is not a MAC.
pub type MessageId = [u8; MESSAGE_ID_LEN];

const MESSAGE_ID_DOMAIN: &[u8] = b"ARCIUM-MESSAGE-ID-V1";

/// The id of the message whose wire bytes are `wire`.
pub fn message_id(wire: &[u8]) -> MessageId {
    let mut h = Sha256::new();
    h.update(MESSAGE_ID_DOMAIN);
    h.update(wire);
    h.finalize().into()
}

mod helpers;
mod records;
mod removal;
use helpers::*;
pub use records::MAX_CLIENT_MESSAGE_ID_LEN;
use records::*;

mod types;
pub use types::*;

struct Unresolved {
    attempted_generation: u64,
    /// The transition took effect if any of these records exists.
    artifact_keys: Vec<String>,
}

/// Durable messaging over an S1 [`EncryptedStore`]. Holds no session state;
/// only the set of sessions whose last commit had an unknown outcome.
#[derive(Default)]
pub struct Messenger {
    unresolved: HashMap<u64, Unresolved>,
}

impl Messenger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores a new session under `new.handle`, together with the handle
    /// record, the initial outbound bytes and `new.extra`, in one transaction.
    /// Refuses without writing anything if the peer already has a session
    /// record (valid or not) or the handle is taken.
    pub fn create_session(
        &mut self,
        store: &mut EncryptedStore,
        our_identity_pk: [u8; 32],
        new: NewSession,
    ) -> Result<(), MessagingError> {
        let NewSession {
            handle,
            session,
            role,
            initial_outbound,
            extra,
        } = new;
        let peer = session.peer_identity_pk;
        let mut side = Vec::with_capacity(2 + extra.len());
        side.push(
            SideWrite::insert(handle_key(handle), encode_handle(&peer))
                .map_err(MessagingError::SideWrite)?,
        );
        if let Some(bytes) = initial_outbound {
            side.push(
                SideWrite::insert(handshake_key(&peer), Zeroizing::new(bytes))
                    .map_err(MessagingError::SideWrite)?,
            );
        }
        let offset = side.len();
        side.extend(extra);
        match DurableSession::create_with(
            &mut S1CheckpointStore::new(store),
            session,
            role,
            our_identity_pk,
            &side,
        ) {
            Ok(_) => {
                self.unresolved.remove(&handle);
                Ok(())
            }
            Err(OpenError::AlreadyExists) => Err(classify_taken(store, handle, &peer)?),
            Err(OpenError::SideConflict { index: 0, .. }) => {
                Err(classify_taken(store, handle, &peer)?)
            }
            Err(OpenError::SideConflict { index, .. }) if index < offset => {
                Err(MessagingError::InconsistentStore(
                    "initial outbound record exists without a session",
                ))
            }
            Err(OpenError::SideConflict { index, conflict }) => {
                Err(MessagingError::ExtraConflict {
                    index: index - offset,
                    conflict,
                })
            }
            Err(OpenError::Invalid(e)) => Err(MessagingError::InvalidSession(e)),
            Err(OpenError::Store(e)) => Err(MessagingError::Store(e)),
            Err(OpenError::NotCommitted(e)) => Err(MessagingError::NotCommitted(e)),
            Err(OpenError::OutcomeUnknown(error)) => {
                self.unresolved.insert(
                    handle,
                    Unresolved {
                        attempted_generation: 0,
                        artifact_keys: vec![handle_key(handle)],
                    },
                );
                Err(MessagingError::OutcomeUnknown {
                    attempted_generation: 0,
                    error,
                })
            }
            Err(OpenError::SideWrite(e)) => Err(MessagingError::SideWrite(e)),
        }
    }

    /// The peer identity key registered for `handle`, if any.
    pub fn peer_of(
        &self,
        store: &EncryptedStore,
        handle: u64,
    ) -> Result<Option<[u8; 32]>, MessagingError> {
        match store.get(&handle_key(handle)) {
            Ok(bytes) => decode_handle(&bytes).map(Some),
            Err(StorageError::NotFound) => Ok(None),
            Err(e) => Err(MessagingError::Store(e)),
        }
    }

    /// The initial outbound bytes stored with the session, if any.
    pub fn initial_outbound(
        &self,
        store: &EncryptedStore,
        handle: u64,
    ) -> Result<Option<Vec<u8>>, MessagingError> {
        let peer = self.require_peer(store, handle)?;
        match store.get(&handshake_key(&peer)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(StorageError::NotFound) => Ok(None),
            Err(e) => Err(MessagingError::Store(e)),
        }
    }

    /// Sends the logical message `client_id` (the caller's own id for it,
    /// 1 to [`MAX_CLIENT_MESSAGE_ID_LEN`] bytes, unique per logical message).
    ///
    /// The first call encrypts `plaintext` and commits the new session state,
    /// the outbox record and the `client_id` → message mapping together, and
    /// returns the message only after that commit. Any later call with the
    /// same `client_id` encrypts nothing and returns what the first one
    /// committed — so a caller that cannot tell whether an earlier attempt
    /// took effect (an unknown commit outcome, a crash, a restart) can simply
    /// call again. The `plaintext` of a repeated call is ignored.
    pub fn send(
        &mut self,
        store: &mut EncryptedStore,
        our_identity_pk: [u8; 32],
        handle: u64,
        client_id: &[u8],
        plaintext: &[u8],
    ) -> Result<SendOutcome, MessagingError> {
        if client_id.is_empty() || client_id.len() > MAX_CLIENT_MESSAGE_ID_LEN {
            return Err(MessagingError::InvalidClientMessageId);
        }
        self.require_resolved(handle)?;
        let peer = self.require_peer(store, handle)?;
        let index_key = sendid_key(&peer, client_id);
        if let Some(prior) = read_prior_send(store, &peer, &index_key)? {
            return Ok(prior);
        }
        let (mut session, _) = self.load(store, our_identity_pk, handle)?;
        let staged = session.stage_encrypt(plaintext).map_err(stage_error)?;
        let generation = staged.generation();
        let (header, ciphertext) = staged.output();
        let mut wire = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
        wire.extend_from_slice(&header.to_bytes());
        wire.extend_from_slice(ciphertext);
        let id = message_id(&wire);
        let side = [
            SideWrite::insert(
                outbox_key(&peer, &id),
                encode_outbox(generation, &id, client_id, &wire),
            )
            .map_err(MessagingError::SideWrite)?,
            SideWrite::insert(index_key.clone(), encode_id_record(SENDID_MAGIC, &id))
                .map_err(MessagingError::SideWrite)?,
        ];
        match session.commit_with(&mut S1CheckpointStore::new(store), staged, &side) {
            Ok(_) => Ok(SendOutcome::Sent(OutgoingMessage {
                message_id: id,
                client_message_id: client_id.to_vec(),
                generation,
                wire,
            })),
            Err(e) => Err(self.commit_error(handle, generation, vec![index_key], e)),
        }
    }

    /// Decrypts `wire` and commits the new session state with an undelivered
    /// inbox record. Returns the plaintext only after that commit. A message
    /// accepted before is reported as a duplicate without touching the
    /// ratchet.
    pub fn receive(
        &mut self,
        store: &mut EncryptedStore,
        our_identity_pk: [u8; 32],
        handle: u64,
        wire: &[u8],
    ) -> Result<Received, MessagingError> {
        self.require_resolved(handle)?;
        if wire.len() < HEADER_SIZE {
            return Err(MessagingError::MalformedMessage);
        }
        let (header_bytes, ciphertext) = wire.split_at(HEADER_SIZE);
        let header =
            Header::from_bytes(header_bytes).map_err(|_| MessagingError::MalformedMessage)?;
        let id = message_id(wire);
        let (mut session, peer) = self.load(store, our_identity_pk, handle)?;
        let (key, seen) = (inbox_key(&peer, &id), seen_key(&peer, &id));
        if let Some(duplicate) = read_duplicate(store, &key, &seen, id)? {
            return Ok(duplicate);
        }
        let staged = session
            .stage_decrypt(&header, ciphertext)
            .map_err(stage_error)?;
        let generation = staged.generation();
        let record = encode_inbox(generation, &id, staged.output());
        let side = [
            SideWrite::insert(key.clone(), record).map_err(MessagingError::SideWrite)?,
            SideWrite::require_absent(seen.clone()).map_err(MessagingError::SideWrite)?,
        ];
        match session.commit_with(&mut S1CheckpointStore::new(store), staged, &side) {
            Ok(plaintext) => Ok(Received::Accepted(IncomingMessage {
                message_id: id,
                generation,
                plaintext: Zeroizing::new(plaintext),
            })),
            // Accepted (and possibly acknowledged) by another instance
            // between the check above and this commit.
            Err(CommitError::SideConflict {
                conflict: Conflict::RecordExists,
                ..
            }) => read_duplicate(store, &key, &seen, id)?
                .ok_or(MessagingError::InconsistentStore("inbox record vanished")),
            Err(e) => Err(self.commit_error(handle, generation, vec![key, seen], e)),
        }
    }

    /// Every committed outgoing message not yet acknowledged, in the order it
    /// was sent, with its stored bytes.
    pub fn pending_outgoing(
        &self,
        store: &EncryptedStore,
        handle: u64,
    ) -> Result<Vec<OutgoingMessage>, MessagingError> {
        let peer = self.require_peer(store, handle)?;
        let mut out = Vec::new();
        for key in keys_under(store, OUTBOX_NAMESPACE, &outbox_prefix(&peer))? {
            let bytes = Zeroizing::new(store.get(&key).map_err(MessagingError::Store)?);
            out.push(decode_outbox(&bytes)?);
        }
        out.sort_by_key(|m| m.generation);
        Ok(out)
    }

    /// Removes the outgoing message `id` once its delivery is confirmed.
    /// Returns whether it was still pending; repeating it is harmless. The
    /// `client_id` mapping stays, so resending that logical message reports
    /// it as acknowledged instead of encrypting it again.
    pub fn acknowledge_outgoing(
        &self,
        store: &EncryptedStore,
        handle: u64,
        id: &MessageId,
    ) -> Result<bool, MessagingError> {
        let peer = self.require_peer(store, handle)?;
        let key = outbox_key(&peer, id);
        match store.get(&key) {
            Ok(_) => {
                store.delete(&key).map_err(MessagingError::Store)?;
                Ok(true)
            }
            Err(StorageError::NotFound) => Ok(false),
            Err(e) => Err(MessagingError::Store(e)),
        }
    }

    /// Every committed incoming message not yet acknowledged, in the order it
    /// was received. A message can appear here again after a crash even if
    /// the application already showed it: delivery to the application is at
    /// least once, and its `message_id` is what identifies a repeat.
    pub fn pending_incoming(
        &self,
        store: &EncryptedStore,
        handle: u64,
    ) -> Result<Vec<IncomingMessage>, MessagingError> {
        let peer = self.require_peer(store, handle)?;
        let mut out = Vec::new();
        for key in keys_under(store, INBOX_NAMESPACE, &inbox_prefix(&peer))? {
            let bytes = Zeroizing::new(store.get(&key).map_err(MessagingError::Store)?);
            out.push(decode_inbox(&bytes)?);
        }
        out.sort_by_key(|m| m.generation);
        Ok(out)
    }

    /// Records that the application has durably processed the incoming
    /// message `id`: its plaintext is erased and only its id is kept (outside
    /// the listed namespace), so the same message is still recognised as a
    /// duplicate. Call it only after the message is safe on the application's
    /// side; acknowledging earlier can lose it. Returns whether it was
    /// undelivered until now; repeating it is harmless.
    pub fn acknowledge_incoming(
        &self,
        store: &mut EncryptedStore,
        handle: u64,
        id: &MessageId,
    ) -> Result<bool, MessagingError> {
        let peer = self.require_peer(store, handle)?;
        let (key, seen) = (inbox_key(&peer, id), seen_key(&peer, id));
        let tx = store.transaction().map_err(MessagingError::NotCommitted)?;
        match tx.get(&key) {
            Ok(bytes) => {
                if decode_inbox(&Zeroizing::new(bytes))?.message_id != *id {
                    return Err(MessagingError::InvalidRecord("inbox"));
                }
            }
            Err(StorageError::NotFound) => {
                return match tx.get(&seen) {
                    Ok(_) => Ok(false),
                    Err(StorageError::NotFound) => Err(MessagingError::UnknownMessage),
                    Err(e) => Err(MessagingError::Store(e)),
                }
            }
            Err(e) => return Err(MessagingError::Store(e)),
        }
        tx.delete(&key).map_err(MessagingError::NotCommitted)?;
        tx.put(&seen, &encode_id_record(SEEN_MAGIC, id))
            .map_err(MessagingError::NotCommitted)?;
        tx.commit().map_err(MessagingError::Store)?;
        Ok(true)
    }

    /// Whether `handle` has a commit with an unknown outcome pending recovery.
    pub fn unresolved_generation(&self, handle: u64) -> Option<u64> {
        self.unresolved.get(&handle).map(|u| u.attempted_generation)
    }

    /// Reports what the store holds for an unresolved session and lets it
    /// continue from there. `Ok(None)` if the session was not unresolved.
    ///
    /// The unresolved commit's output was never released, so continuing from
    /// the stored state cannot compete with anything already sent or shown.
    /// This reading reflects what the store holds now; it does not show that
    /// the state will survive a power loss or that the database file is not
    /// an older copy.
    pub fn recover(
        &mut self,
        store: &mut EncryptedStore,
        our_identity_pk: [u8; 32],
        handle: u64,
    ) -> Result<Option<Recovery>, MessagingError> {
        let Some(unresolved) = self.unresolved.get(&handle) else {
            return Ok(None);
        };
        let attempted_generation = unresolved.attempted_generation;
        let mut artifact_committed = false;
        for key in &unresolved.artifact_keys {
            match store.get(key) {
                Ok(_) => artifact_committed = true,
                Err(StorageError::NotFound) => {}
                Err(e) => return Err(MessagingError::Store(e)),
            }
        }
        let stored_generation = match self.load(store, our_identity_pk, handle) {
            Ok((session, _)) => session.generation(),
            // An unresolved creation that did not take effect.
            Err(MessagingError::NoSession { .. }) if attempted_generation == 0 => {
                self.unresolved.remove(&handle);
                return Ok(Some(Recovery {
                    attempted_generation,
                    stored_generation: 0,
                    artifact_committed: false,
                }));
            }
            Err(e) => return Err(e),
        };
        self.unresolved.remove(&handle);
        Ok(Some(Recovery {
            attempted_generation,
            stored_generation,
            artifact_committed,
        }))
    }

    // ── Internals ────────────────────────────────────────────────────────────

    fn require_resolved(&self, handle: u64) -> Result<(), MessagingError> {
        match self.unresolved.get(&handle) {
            Some(u) => Err(MessagingError::Unresolved {
                attempted_generation: u.attempted_generation,
            }),
            None => Ok(()),
        }
    }

    fn require_peer(
        &self,
        store: &EncryptedStore,
        handle: u64,
    ) -> Result<[u8; 32], MessagingError> {
        self.peer_of(store, handle)?
            .ok_or(MessagingError::NoSession { handle })
    }

    fn load(
        &self,
        store: &mut EncryptedStore,
        our_identity_pk: [u8; 32],
        handle: u64,
    ) -> Result<(DurableSession, [u8; 32]), MessagingError> {
        let peer = self.require_peer(store, handle)?;
        let binding = SessionBinding {
            our_identity_pk,
            peer_identity_pk: peer,
        };
        match DurableSession::load(&mut S1CheckpointStore::new(store), &binding) {
            Ok(Some(session)) => Ok((session, peer)),
            Ok(None) => Err(MessagingError::MissingSession { handle }),
            Err(OpenError::Invalid(e)) => Err(MessagingError::InvalidSession(e)),
            Err(OpenError::Store(e)) => Err(MessagingError::Store(e)),
            Err(_) => Err(MessagingError::InconsistentStore("unexpected load result")),
        }
    }

    fn commit_error(
        &mut self,
        handle: u64,
        attempted_generation: u64,
        artifact_keys: Vec<String>,
        e: CommitError,
    ) -> MessagingError {
        match e {
            CommitError::OutcomeUnknown(error) => {
                self.unresolved.insert(
                    handle,
                    Unresolved {
                        attempted_generation,
                        artifact_keys,
                    },
                );
                MessagingError::OutcomeUnknown {
                    attempted_generation,
                    error,
                }
            }
            CommitError::Conflict(c) => MessagingError::Conflict(c),
            CommitError::SideConflict { conflict, .. } => MessagingError::Conflict(conflict),
            CommitError::NotCommitted(e) => MessagingError::NotCommitted(e),
            CommitError::SideWrite(e) => MessagingError::SideWrite(e),
            // A fresh instance per operation is never unresolved, conflicted
            // or handed a transition staged elsewhere.
            CommitError::Unresolved { .. }
            | CommitError::Conflicted
            | CommitError::StaleTransition => {
                MessagingError::InconsistentStore("unexpected commit state")
            }
        }
    }
}

/// Lets a test act between `remove_session`'s reads and its transaction.
#[cfg(test)]
mod remove_hook {
    use std::cell::RefCell;

    thread_local! {
        static HOOK: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    }

    pub(super) fn set(f: impl FnOnce() + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    pub(super) fn run() {
        if let Some(f) = HOOK.with(|h| h.borrow_mut().take()) {
            f();
        }
    }
}

#[cfg(test)]
mod tests;
