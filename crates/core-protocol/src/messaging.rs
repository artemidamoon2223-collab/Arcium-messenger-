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
    CommitError, Conflict, DurableSession, OpenError, S1CheckpointStore, SideWrite, StageError,
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

mod records;
use records::*;

mod types;
pub use types::*;

struct Unresolved {
    attempted_generation: u64,
    artifact_key: String,
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
                        artifact_key: handle_key(handle),
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

    /// Encrypts `plaintext` and commits the new session state with the outbox
    /// record. Returns the message only after that commit.
    pub fn send(
        &mut self,
        store: &mut EncryptedStore,
        our_identity_pk: [u8; 32],
        handle: u64,
        plaintext: &[u8],
    ) -> Result<OutgoingMessage, MessagingError> {
        self.require_resolved(handle)?;
        let (mut session, peer) = self.load(store, our_identity_pk, handle)?;
        let staged = session.stage_encrypt(plaintext).map_err(stage_error)?;
        let generation = staged.generation();
        let (header, ciphertext) = staged.output();
        let mut wire = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
        wire.extend_from_slice(&header.to_bytes());
        wire.extend_from_slice(ciphertext);
        let id = message_id(&wire);
        let key = outbox_key(&peer, &id);
        let side = [
            SideWrite::insert(key.clone(), encode_outbox(generation, &id, &wire))
                .map_err(MessagingError::SideWrite)?,
        ];
        match session.commit_with(&mut S1CheckpointStore::new(store), staged, &side) {
            Ok(_) => Ok(OutgoingMessage {
                message_id: id,
                generation,
                wire,
            }),
            Err(e) => Err(self.commit_error(handle, generation, key, e)),
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
        let key = inbox_key(&peer, &id);
        if let Some(duplicate) = read_duplicate(store, &key, id)? {
            return Ok(duplicate);
        }
        let staged = session
            .stage_decrypt(&header, ciphertext)
            .map_err(stage_error)?;
        let generation = staged.generation();
        let record = encode_inbox(INBOX_PENDING, generation, &id, staged.output());
        let side = [SideWrite::insert(key.clone(), record).map_err(MessagingError::SideWrite)?];
        match session.commit_with(&mut S1CheckpointStore::new(store), staged, &side) {
            Ok(plaintext) => Ok(Received::Accepted(IncomingMessage {
                message_id: id,
                generation,
                plaintext: Zeroizing::new(plaintext),
            })),
            // Accepted by another instance between the check above and this
            // commit.
            Err(CommitError::SideConflict {
                conflict: Conflict::RecordExists,
                ..
            }) => read_duplicate(store, &key, id)?
                .ok_or(MessagingError::InconsistentStore("inbox record vanished")),
            Err(e) => Err(self.commit_error(handle, generation, key, e)),
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
    /// Returns whether it was still pending; repeating it is harmless.
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
    /// was received.
    pub fn pending_incoming(
        &self,
        store: &EncryptedStore,
        handle: u64,
    ) -> Result<Vec<IncomingMessage>, MessagingError> {
        let peer = self.require_peer(store, handle)?;
        let mut out = Vec::new();
        for key in keys_under(store, INBOX_NAMESPACE, &inbox_prefix(&peer))? {
            let bytes = Zeroizing::new(store.get(&key).map_err(MessagingError::Store)?);
            let record = decode_inbox(&bytes)?;
            if !record.acknowledged {
                out.push(record.message);
            }
        }
        out.sort_by_key(|m| m.generation);
        Ok(out)
    }

    /// Marks the incoming message `id` delivered and erases its plaintext.
    /// Its id is kept so the same message is still recognised as a duplicate.
    /// Returns whether it was undelivered until now; repeating it is harmless.
    pub fn acknowledge_incoming(
        &self,
        store: &mut EncryptedStore,
        handle: u64,
        id: &MessageId,
    ) -> Result<bool, MessagingError> {
        let peer = self.require_peer(store, handle)?;
        let key = inbox_key(&peer, id);
        let tx = store.transaction().map_err(MessagingError::NotCommitted)?;
        let bytes = match tx.get(&key) {
            Ok(b) => Zeroizing::new(b),
            Err(StorageError::NotFound) => return Err(MessagingError::UnknownMessage),
            Err(e) => return Err(MessagingError::Store(e)),
        };
        let record = decode_inbox(&bytes)?;
        if record.acknowledged {
            return Ok(false);
        }
        tx.put(
            &key,
            &encode_inbox(INBOX_ACKNOWLEDGED, record.message.generation, id, &[]),
        )
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
        let artifact_committed = match store.get(&unresolved.artifact_key) {
            Ok(_) => true,
            Err(StorageError::NotFound) => false,
            Err(e) => return Err(MessagingError::Store(e)),
        };
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
        artifact_key: String,
        e: CommitError,
    ) -> MessagingError {
        match e {
            CommitError::OutcomeUnknown(error) => {
                self.unresolved.insert(
                    handle,
                    Unresolved {
                        attempted_generation,
                        artifact_key,
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

fn stage_error(e: StageError) -> MessagingError {
    match e {
        StageError::Ratchet(e) => MessagingError::Ratchet(e),
        StageError::Checkpoint(e) => MessagingError::Checkpoint(e),
        StageError::GenerationExhausted => MessagingError::GenerationExhausted,
        StageError::Unresolved { .. } | StageError::Conflicted => {
            MessagingError::InconsistentStore("unexpected stage state")
        }
    }
}

/// After a refused creation: the handle belongs to another peer, or this
/// peer already has a session.
fn classify_taken(
    store: &EncryptedStore,
    handle: u64,
    peer: &[u8; 32],
) -> Result<MessagingError, MessagingError> {
    match store.get(&handle_key(handle)) {
        Ok(bytes) => {
            if decode_handle(&bytes)? == *peer {
                Ok(MessagingError::AlreadyExists { handle })
            } else {
                Ok(MessagingError::HandleCollision { handle })
            }
        }
        Err(StorageError::NotFound) => Ok(MessagingError::AlreadyExists { handle }),
        Err(e) => Err(MessagingError::Store(e)),
    }
}

fn read_duplicate(
    store: &EncryptedStore,
    key: &str,
    id: MessageId,
) -> Result<Option<Received>, MessagingError> {
    match store.get(key) {
        Ok(bytes) => {
            let record = decode_inbox(&Zeroizing::new(bytes))?;
            if record.message.message_id != id {
                return Err(MessagingError::InvalidRecord("inbox"));
            }
            Ok(Some(Received::Duplicate {
                message_id: id,
                undelivered: (!record.acknowledged).then_some(record.message),
            }))
        }
        Err(StorageError::NotFound) => Ok(None),
        Err(e) => Err(MessagingError::Store(e)),
    }
}

/// Keys in `namespace` that start with `prefix`.
fn keys_under(
    store: &EncryptedStore,
    namespace: &str,
    prefix: &str,
) -> Result<Vec<String>, MessagingError> {
    Ok(store
        .list_keys_with_prefix(namespace)
        .map_err(MessagingError::Store)?
        .into_iter()
        .filter(|k| k.starts_with(prefix))
        .collect())
}

#[cfg(test)]
mod tests;
