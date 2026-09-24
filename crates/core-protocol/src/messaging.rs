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

use core_crypto::ratchet::{Header, RatchetError, HEADER_SIZE};
use core_storage::{EncryptedStore, StorageError};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::checkpoint::{SessionBinding, SessionCheckpointError, SessionRole};
use crate::durable::{
    CommitError, Conflict, DurableSession, OpenError, S1CheckpointStore, SideWrite,
    SideWriteError, StageError,
};
use crate::Session;

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

// ── Store keys ────────────────────────────────────────────────────────────────

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn handle_key(handle: u64) -> String {
    format!("handle:v1/{handle:016x}")
}

fn handshake_key(peer: &[u8; 32]) -> String {
    format!("hsout:v1/{}", hex(peer))
}

const OUTBOX_NAMESPACE: &str = "outbox:";
const INBOX_NAMESPACE: &str = "inbox:";

fn outbox_prefix(peer: &[u8; 32]) -> String {
    format!("{OUTBOX_NAMESPACE}v1/{}/", hex(peer))
}

fn inbox_prefix(peer: &[u8; 32]) -> String {
    format!("{INBOX_NAMESPACE}v1/{}/", hex(peer))
}

fn outbox_key(peer: &[u8; 32], id: &MessageId) -> String {
    format!("{}{}", outbox_prefix(peer), hex(id))
}

fn inbox_key(peer: &[u8; 32], id: &MessageId) -> String {
    format!("{}{}", inbox_prefix(peer), hex(id))
}

// ── Records ───────────────────────────────────────────────────────────────────
//
// Fixed layouts, integers big-endian. Never transmitted; confidentiality and
// integrity come from the encrypted store.

const HANDLE_MAGIC: &[u8; 7] = b"ARCHNDL";
const OUTBOX_MAGIC: &[u8; 7] = b"ARCOUTB";
const INBOX_MAGIC: &[u8; 7] = b"ARCINBX";
const RECORD_VERSION: u8 = 1;

/// `HANDLE_RECORD_V1`: magic(7) version(1) peer_identity_pk(32).
fn encode_handle(peer: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(40));
    out.extend_from_slice(HANDLE_MAGIC);
    out.push(RECORD_VERSION);
    out.extend_from_slice(peer);
    out
}

fn decode_handle(bytes: &[u8]) -> Result<[u8; 32], MessagingError> {
    if bytes.len() != 40 || &bytes[..7] != HANDLE_MAGIC || bytes[7] != RECORD_VERSION {
        return Err(MessagingError::InvalidRecord("handle"));
    }
    Ok(bytes[8..40].try_into().expect("32 bytes"))
}

/// `OUTBOX_RECORD_V1`: magic(7) version(1) generation(8) id(32) len(4) wire.
fn encode_outbox(generation: u64, id: &MessageId, wire: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(52 + wire.len()));
    out.extend_from_slice(OUTBOX_MAGIC);
    out.push(RECORD_VERSION);
    out.extend_from_slice(&generation.to_be_bytes());
    out.extend_from_slice(id);
    out.extend_from_slice(&(wire.len() as u32).to_be_bytes());
    out.extend_from_slice(wire);
    out
}

fn decode_outbox(bytes: &[u8]) -> Result<OutgoingMessage, MessagingError> {
    let bad = MessagingError::InvalidRecord("outbox");
    if bytes.len() < 52 || &bytes[..7] != OUTBOX_MAGIC || bytes[7] != RECORD_VERSION {
        return Err(bad);
    }
    let generation = u64::from_be_bytes(bytes[8..16].try_into().expect("8 bytes"));
    let id: MessageId = bytes[16..48].try_into().expect("32 bytes");
    let len = u32::from_be_bytes(bytes[48..52].try_into().expect("4 bytes")) as usize;
    if bytes.len() != 52 + len {
        return Err(bad);
    }
    let wire = bytes[52..].to_vec();
    if message_id(&wire) != id {
        return Err(bad);
    }
    Ok(OutgoingMessage {
        message_id: id,
        generation,
        wire,
    })
}

const INBOX_PENDING: u8 = 0;
const INBOX_ACKNOWLEDGED: u8 = 1;

/// `INBOX_RECORD_V1`: magic(7) version(1) state(1) generation(8) id(32)
/// len(4) plaintext. An acknowledged record keeps no plaintext.
fn encode_inbox(state: u8, generation: u64, id: &MessageId, plaintext: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(53 + plaintext.len()));
    out.extend_from_slice(INBOX_MAGIC);
    out.push(RECORD_VERSION);
    out.push(state);
    out.extend_from_slice(&generation.to_be_bytes());
    out.extend_from_slice(id);
    out.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
    out.extend_from_slice(plaintext);
    out
}

struct InboxRecord {
    acknowledged: bool,
    message: IncomingMessage,
}

fn decode_inbox(bytes: &[u8]) -> Result<InboxRecord, MessagingError> {
    let bad = MessagingError::InvalidRecord("inbox");
    if bytes.len() < 53 || &bytes[..7] != INBOX_MAGIC || bytes[7] != RECORD_VERSION {
        return Err(bad);
    }
    let acknowledged = match bytes[8] {
        INBOX_PENDING => false,
        INBOX_ACKNOWLEDGED => true,
        _ => return Err(bad),
    };
    let generation = u64::from_be_bytes(bytes[9..17].try_into().expect("8 bytes"));
    let id: MessageId = bytes[17..49].try_into().expect("32 bytes");
    let len = u32::from_be_bytes(bytes[49..53].try_into().expect("4 bytes")) as usize;
    if bytes.len() != 53 + len || (acknowledged && len != 0) {
        return Err(bad);
    }
    Ok(InboxRecord {
        acknowledged,
        message: IncomingMessage {
            message_id: id,
            generation,
            plaintext: Zeroizing::new(bytes[53..].to_vec()),
        },
    })
}

// ── Public types ──────────────────────────────────────────────────────────────

/// A committed outgoing message. `wire` is exactly what must be sent, on the
/// first attempt and on every retransmission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingMessage {
    pub message_id: MessageId,
    /// The session generation this message's send committed.
    pub generation: u64,
    pub wire: Vec<u8>,
}

/// A committed incoming message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingMessage {
    pub message_id: MessageId,
    /// The session generation this message's receipt committed.
    pub generation: u64,
    pub plaintext: Zeroizing<Vec<u8>>,
}

/// The result of [`Messenger::receive`].
#[derive(Debug, PartialEq, Eq)]
pub enum Received {
    /// Newly accepted: the ratchet advanced and the message was committed as
    /// undelivered.
    Accepted(IncomingMessage),
    /// This exact message was accepted before. The ratchet was not touched.
    /// `undelivered` carries it again if it has not been acknowledged yet.
    Duplicate {
        message_id: MessageId,
        undelivered: Option<IncomingMessage>,
    },
}

/// A new session to store, from X3DH.
pub struct NewSession {
    pub handle: u64,
    pub session: Session,
    pub role: SessionRole,
    /// Bytes the peer needs to complete the handshake (the initiator's
    /// handshake), kept so they can be sent again after a restart.
    pub initial_outbound: Option<Vec<u8>>,
    /// Further records to write in the same transaction, e.g. the rotated
    /// prekey record of a responder.
    pub extra: Vec<SideWrite>,
}

/// What [`Messenger::recover`] found for an unresolved session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovery {
    /// The generation whose commit reported an unknown outcome.
    pub attempted_generation: u64,
    /// The generation the store holds now.
    pub stored_generation: u64,
    /// Whether the store holds that transition's outbox or inbox record, i.e.
    /// whether, as read now, the transition took effect.
    pub artifact_committed: bool,
}

/// Why a messaging operation failed. In every case no output was released.
#[derive(Debug)]
pub enum MessagingError {
    /// No session is registered under this handle.
    NoSession { handle: u64 },
    /// This peer already has a session (valid or not); nothing was written.
    AlreadyExists { handle: u64 },
    /// The handle is registered to a different peer; nothing was written.
    HandleCollision { handle: u64 },
    /// The handle names a peer whose session record is missing.
    MissingSession { handle: u64 },
    /// A stored session record is malformed, unsupported or bound to other
    /// identities. It is left as it is.
    InvalidSession(SessionCheckpointError),
    /// A stored handle, outbox or inbox record is malformed.
    InvalidRecord(&'static str),
    /// A record exists that only this module writes, in a state this module
    /// never leaves it in.
    InconsistentStore(&'static str),
    /// Not a message: shorter than a header, or a malformed header.
    MalformedMessage,
    /// The message does not decrypt; nothing was written.
    Ratchet(RatchetError),
    /// The transition's state cannot be persisted; nothing was written.
    Checkpoint(SessionCheckpointError),
    GenerationExhausted,
    /// The stored session is not the generation this operation loaded:
    /// another instance committed first. Nothing was written.
    Conflict(Conflict),
    /// A precondition on `NewSession::extra[index]` failed; nothing was
    /// written.
    ExtraConflict { index: usize, conflict: Conflict },
    SideWrite(SideWriteError),
    /// Reading the store failed.
    Store(StorageError),
    /// The store definitely kept nothing.
    NotCommitted(StorageError),
    /// The commit's outcome is unknown. Its output was withheld. The session
    /// refuses transitions until [`Messenger::recover`].
    OutcomeUnknown {
        attempted_generation: u64,
        error: StorageError,
    },
    /// An earlier commit on this session had an unknown outcome and has not
    /// been recovered.
    Unresolved { attempted_generation: u64 },
    /// No message with this id is recorded for this session.
    UnknownMessage,
}

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
            Err(OpenError::SideConflict { index, conflict }) => Err(MessagingError::ExtraConflict {
                index: index - offset,
                conflict,
            }),
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
        let side = [SideWrite::insert(key.clone(), encode_outbox(generation, &id, &wire))
            .map_err(MessagingError::SideWrite)?];
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
        let header = Header::from_bytes(header_bytes).map_err(|_| MessagingError::MalformedMessage)?;
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

    fn require_peer(&self, store: &EncryptedStore, handle: u64) -> Result<[u8; 32], MessagingError> {
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
mod tests {
    use super::*;
    use crate::checkpoint::session_storage_key;
    use crate::durable::test_hooks::{self, CommitFault, CRASH_AT_ENV};
    use core_crypto::ratchet::DoubleRatchet;
    use rand_core::OsRng;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Barrier};
    use x25519_dalek::{PublicKey, StaticSecret};

    const KEY: [u8; 32] = [0x24; 32];
    const ALICE_HANDLE: u64 = 0xA11CE;
    const BOB_HANDLE: u64 = 0xB0B;

    struct Pair {
        alice: Session,
        bob: Session,
        alice_pk: [u8; 32],
        bob_pk: [u8; 32],
    }

    /// Matching initiator/responder sessions with the X3DH AD layout. The
    /// root key is fixed: these tests exercise persistence, not X3DH.
    fn pair() -> Pair {
        let alice_pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes();
        let bob_pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes();
        let mut ad = alice_pk.to_vec();
        ad.extend_from_slice(&bob_pk);
        let spk = StaticSecret::random_from_rng(OsRng);
        let root = [9u8; 32];
        Pair {
            alice: Session {
                ratchet: DoubleRatchet::init_alice(root, PublicKey::from(&spk)),
                ad: ad.clone(),
                peer_identity_pk: bob_pk,
            },
            bob: Session {
                ratchet: DoubleRatchet::init_bob(root, spk),
                ad,
                peer_identity_pk: alice_pk,
            },
            alice_pk,
            bob_pk,
        }
    }

    fn new_session(handle: u64, session: Session, role: SessionRole) -> NewSession {
        NewSession {
            handle,
            session,
            role,
            initial_outbound: None,
            extra: Vec::new(),
        }
    }

    /// Alice (initiator) and Bob (responder), each in their own store.
    struct Peers {
        a: EncryptedStore,
        b: EncryptedStore,
        am: Messenger,
        bm: Messenger,
        alice_pk: [u8; 32],
        bob_pk: [u8; 32],
    }

    fn setup(a: EncryptedStore, b: EncryptedStore) -> Peers {
        let p = pair();
        let mut peers = Peers {
            a,
            b,
            am: Messenger::new(),
            bm: Messenger::new(),
            alice_pk: p.alice_pk,
            bob_pk: p.bob_pk,
        };
        peers
            .am
            .create_session(
                &mut peers.a,
                p.alice_pk,
                new_session(ALICE_HANDLE, p.alice, SessionRole::Initiator),
            )
            .unwrap();
        peers
            .bm
            .create_session(
                &mut peers.b,
                p.bob_pk,
                new_session(BOB_HANDLE, p.bob, SessionRole::Responder),
            )
            .unwrap();
        peers
    }

    fn memory_peers() -> Peers {
        setup(
            EncryptedStore::open_in_memory(KEY).unwrap(),
            EncryptedStore::open_in_memory(KEY).unwrap(),
        )
    }

    impl Peers {
        fn alice_sends(&mut self, m: &[u8]) -> OutgoingMessage {
            self.am.send(&mut self.a, self.alice_pk, ALICE_HANDLE, m).unwrap()
        }
        fn bob_sends(&mut self, m: &[u8]) -> OutgoingMessage {
            self.bm.send(&mut self.b, self.bob_pk, BOB_HANDLE, m).unwrap()
        }
        fn bob_receives(&mut self, wire: &[u8]) -> Result<Received, MessagingError> {
            self.bm.receive(&mut self.b, self.bob_pk, BOB_HANDLE, wire)
        }
        fn alice_receives(&mut self, wire: &[u8]) -> Result<Received, MessagingError> {
            self.am.receive(&mut self.a, self.alice_pk, ALICE_HANDLE, wire)
        }
    }

    fn generation(store: &mut EncryptedStore, our: [u8; 32], handle: u64) -> u64 {
        Messenger::new().load(store, our, handle).unwrap().0.generation()
    }

    fn accepted(r: Received) -> IncomingMessage {
        match r {
            Received::Accepted(m) => m,
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    // ── Outbox and inbox ──────────────────────────────────────────────────────

    #[test]
    fn a_send_is_committed_with_its_outbox_record_and_returned_unchanged() {
        let mut p = memory_peers();
        let sent = p.alice_sends(b"hello");
        assert_eq!(sent.message_id, message_id(&sent.wire));
        assert_eq!(sent.generation, 1);
        assert_eq!(generation(&mut p.a, p.alice_pk, ALICE_HANDLE), 1);

        let pending = p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap();
        assert_eq!(pending, vec![sent.clone()]);
        // Reading again returns the same bytes and advances nothing.
        assert_eq!(p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap(), pending);
        assert_eq!(generation(&mut p.a, p.alice_pk, ALICE_HANDLE), 1);

        let got = accepted(p.bob_receives(&sent.wire).unwrap());
        assert_eq!(*got.plaintext, b"hello");
        assert_eq!(got.message_id, sent.message_id, "both sides derive one id");

        assert!(p.am.acknowledge_outgoing(&p.a, ALICE_HANDLE, &sent.message_id).unwrap());
        assert!(!p.am.acknowledge_outgoing(&p.a, ALICE_HANDLE, &sent.message_id).unwrap());
        assert!(p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap().is_empty());
    }

    #[test]
    fn pending_outgoing_is_in_send_order() {
        let mut p = memory_peers();
        let sent: Vec<_> = (0u8..5).map(|i| p.alice_sends(&[i])).collect();
        assert_eq!(p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap(), sent);
    }

    #[test]
    fn a_repeated_message_is_a_duplicate_and_advances_nothing() {
        let mut p = memory_peers();
        let sent = p.alice_sends(b"once");
        let first = accepted(p.bob_receives(&sent.wire).unwrap());
        let gen = generation(&mut p.b, p.bob_pk, BOB_HANDLE);

        // Undelivered: the duplicate carries the same message again.
        match p.bob_receives(&sent.wire).unwrap() {
            Received::Duplicate {
                message_id,
                undelivered: Some(m),
            } => {
                assert_eq!(message_id, sent.message_id);
                assert_eq!(m, first);
            }
            other => panic!("expected an undelivered duplicate, got {other:?}"),
        }
        assert_eq!(p.bm.pending_incoming(&p.b, BOB_HANDLE).unwrap(), vec![first.clone()]);

        assert!(p.bm.acknowledge_incoming(&mut p.b, BOB_HANDLE, &sent.message_id).unwrap());
        assert!(!p.bm.acknowledge_incoming(&mut p.b, BOB_HANDLE, &sent.message_id).unwrap());
        assert!(p.bm.pending_incoming(&p.b, BOB_HANDLE).unwrap().is_empty());

        // Delivered: still a duplicate, now without plaintext.
        assert_eq!(
            p.bob_receives(&sent.wire).unwrap(),
            Received::Duplicate {
                message_id: sent.message_id,
                undelivered: None
            }
        );
        assert_eq!(generation(&mut p.b, p.bob_pk, BOB_HANDLE), gen);
        // The session keeps working.
        let next = p.alice_sends(b"twice");
        assert_eq!(*accepted(p.bob_receives(&next.wire).unwrap()).plaintext, b"twice");
    }

    #[test]
    fn acknowledging_an_unknown_incoming_message_is_an_error() {
        let mut p = memory_peers();
        assert!(matches!(
            p.bm.acknowledge_incoming(&mut p.b, BOB_HANDLE, &[7; 32]),
            Err(MessagingError::UnknownMessage)
        ));
    }

    #[test]
    fn a_forged_message_writes_nothing() {
        let mut p = memory_peers();
        let sent = p.alice_sends(b"real");
        let mut forged = sent.wire.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(matches!(
            p.bob_receives(&forged),
            Err(MessagingError::Ratchet(RatchetError::Decryption))
        ));
        assert_eq!(generation(&mut p.b, p.bob_pk, BOB_HANDLE), 0);
        assert!(p.bm.pending_incoming(&p.b, BOB_HANDLE).unwrap().is_empty());
        assert!(matches!(p.bob_receives(&forged[..10]), Err(MessagingError::MalformedMessage)));
        // The real one is still accepted.
        assert_eq!(*accepted(p.bob_receives(&sent.wire).unwrap()).plaintext, b"real");
    }

    #[test]
    fn out_of_order_messages_are_each_accepted_once() {
        let mut p = memory_peers();
        let m: Vec<_> = (0u8..3).map(|i| p.alice_sends(&[i])).collect();
        for i in [2, 0, 1] {
            assert_eq!(*accepted(p.bob_receives(&m[i].wire).unwrap()).plaintext, [i as u8]);
        }
        for w in &m {
            assert!(matches!(p.bob_receives(&w.wire).unwrap(), Received::Duplicate { .. }));
        }
    }

    /// The bytes on the wire are what the in-memory path produced before
    /// S2-B2: `header(40) || ciphertext`, readable by a plain ratchet.
    #[test]
    fn the_wire_format_is_unchanged() {
        let pr = pair();
        let mut a = EncryptedStore::open_in_memory(KEY).unwrap();
        let mut am = Messenger::new();
        let (bob_ad, mut bob) = (pr.bob.ad.clone(), pr.bob.ratchet);
        am.create_session(
            &mut a,
            pr.alice_pk,
            new_session(ALICE_HANDLE, pr.alice, SessionRole::Initiator),
        )
        .unwrap();
        let sent = am.send(&mut a, pr.alice_pk, ALICE_HANDLE, b"compat").unwrap();
        let header = Header::from_bytes(&sent.wire[..HEADER_SIZE]).unwrap();
        assert_eq!(
            bob.decrypt(&header, &sent.wire[HEADER_SIZE..], &bob_ad).unwrap(),
            b"compat"
        );
    }

    #[test]
    fn a_conversation_survives_reopening_both_stores() {
        let dir = tempfile::tempdir().unwrap();
        let (pa, pb) = (dir.path().join("a.db"), dir.path().join("b.db"));
        let p = setup(
            EncryptedStore::open(&pa, KEY).unwrap(),
            EncryptedStore::open(&pb, KEY).unwrap(),
        );
        let (alice_pk, bob_pk) = (p.alice_pk, p.bob_pk);
        drop(p);
        for i in 0u8..4 {
            let mut p = Peers {
                a: EncryptedStore::open(&pa, KEY).unwrap(),
                b: EncryptedStore::open(&pb, KEY).unwrap(),
                am: Messenger::new(),
                bm: Messenger::new(),
                alice_pk,
                bob_pk,
            };
            let m = p.alice_sends(&[i]);
            assert_eq!(*accepted(p.bob_receives(&m.wire).unwrap()).plaintext, [i]);
            let r = p.bob_sends(&[i, i]);
            assert_eq!(*accepted(p.alice_receives(&r.wire).unwrap()).plaintext, [i, i]);
        }
    }

    // ── Creation ──────────────────────────────────────────────────────────────

    #[test]
    fn creation_refuses_an_existing_session_and_a_taken_handle() {
        let mut p = memory_peers();
        let rival = pair();
        // Same peer, another handle: the peer already has a session.
        let mut again = rival.alice;
        again.peer_identity_pk = p.bob_pk;
        let mut ad = p.alice_pk.to_vec();
        ad.extend_from_slice(&p.bob_pk);
        again.ad = ad;
        assert!(matches!(
            p.am.create_session(&mut p.a, p.alice_pk, new_session(77, again, SessionRole::Initiator)),
            Err(MessagingError::AlreadyExists { .. })
        ));
        assert_eq!(p.am.peer_of(&p.a, 77).unwrap(), None, "nothing was written");
        // Another peer on the taken handle.
        assert!(matches!(
            p.am.create_session(
                &mut p.a,
                rival.bob_pk,
                new_session(ALICE_HANDLE, rival.bob, SessionRole::Responder)
            ),
            Err(MessagingError::HandleCollision { .. })
        ));
        assert_eq!(p.am.peer_of(&p.a, ALICE_HANDLE).unwrap(), Some(p.bob_pk));
    }

    #[test]
    fn an_invalid_stored_session_is_reported_and_never_replaced() {
        let mut p = memory_peers();
        let key = session_storage_key(&p.bob_pk);
        p.a.put(&key, b"garbage").unwrap();
        assert!(matches!(
            p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, b"x"),
            Err(MessagingError::InvalidSession(SessionCheckpointError::Truncated { .. }))
        ));
        let fresh = pair();
        let mut s = fresh.alice;
        s.peer_identity_pk = p.bob_pk;
        let mut ad = p.alice_pk.to_vec();
        ad.extend_from_slice(&p.bob_pk);
        s.ad = ad;
        assert!(matches!(
            p.am.create_session(&mut p.a, p.alice_pk, new_session(5, s, SessionRole::Initiator)),
            Err(MessagingError::AlreadyExists { .. })
        ));
        assert_eq!(p.a.get(&key).unwrap(), b"garbage");
    }

    #[test]
    fn extra_writes_commit_with_the_session_or_not_at_all() {
        let pr = pair();
        let mut s = EncryptedStore::open_in_memory(KEY).unwrap();
        s.put("prekeys/v2", b"old").unwrap();
        let mut m = Messenger::new();
        let stale = SideWrite::replace(
            "prekeys/v2".into(),
            Zeroizing::new(b"not what is stored".to_vec()),
            Zeroizing::new(b"new".to_vec()),
        )
        .unwrap();
        let mut ns = new_session(BOB_HANDLE, pr.bob, SessionRole::Responder);
        ns.extra = vec![stale];
        assert!(matches!(
            m.create_session(&mut s, pr.bob_pk, ns),
            Err(MessagingError::ExtraConflict {
                index: 0,
                conflict: Conflict::RecordChanged
            })
        ));
        assert_eq!(m.peer_of(&s, BOB_HANDLE).unwrap(), None);
        assert!(s.get(&session_storage_key(&pr.alice_pk)).is_err());
        assert_eq!(s.get("prekeys/v2").unwrap(), b"old");
    }

    #[test]
    fn a_side_write_cannot_touch_a_session_record() {
        assert_eq!(
            SideWrite::insert("session:v1/00".into(), Zeroizing::new(vec![1])).err(),
            Some(SideWriteError::ReservedKey)
        );
    }

    #[test]
    fn the_initial_handshake_is_kept_with_the_session() {
        let pr = pair();
        let mut s = EncryptedStore::open_in_memory(KEY).unwrap();
        let mut m = Messenger::new();
        let mut ns = new_session(ALICE_HANDLE, pr.alice, SessionRole::Initiator);
        ns.initial_outbound = Some(vec![1, 2, 3]);
        m.create_session(&mut s, pr.alice_pk, ns).unwrap();
        assert_eq!(m.initial_outbound(&s, ALICE_HANDLE).unwrap(), Some(vec![1, 2, 3]));
    }

    // ── Competing instances ───────────────────────────────────────────────────

    /// Two connections to one database send concurrently. Every send that
    /// returned committed a distinct generation and is in the outbox; every
    /// failure is a conflict that released nothing; the peer accepts every
    /// committed message exactly once.
    #[test]
    fn concurrent_instances_never_release_two_messages_for_one_position() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.db");
        let mut p = setup(
            EncryptedStore::open(&path, KEY).unwrap(),
            EncryptedStore::open_in_memory(KEY).unwrap(),
        );
        let alice_pk = p.alice_pk;
        let barrier = Arc::new(Barrier::new(2));
        let threads: Vec<_> = (0..2u8)
            .map(|t| {
                let (path, barrier) = (path.clone(), barrier.clone());
                std::thread::spawn(move || {
                    let mut db = EncryptedStore::open(&path, KEY).unwrap();
                    let mut m = Messenger::new();
                    let mut sent = Vec::new();
                    let mut conflicts = 0;
                    barrier.wait();
                    for i in 0..25u8 {
                        match m.send(&mut db, alice_pk, ALICE_HANDLE, &[t, i]) {
                            Ok(s) => sent.push(s),
                            Err(MessagingError::Conflict(_)) => conflicts += 1,
                            // Lock contention beyond the busy timeout: nothing written.
                            Err(MessagingError::NotCommitted(_)) => conflicts += 1,
                            Err(e) => panic!("unexpected {e:?}"),
                        }
                    }
                    (sent, conflicts)
                })
            })
            .collect();
        let mut released = Vec::new();
        for t in threads {
            released.extend(t.join().unwrap().0);
        }
        let mut generations: Vec<_> = released.iter().map(|m| m.generation).collect();
        generations.sort_unstable();
        generations.dedup();
        assert_eq!(generations.len(), released.len(), "one message per generation");

        let mut outbox = p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap();
        released.sort_by_key(|m| m.generation);
        outbox.sort_by_key(|m| m.generation);
        assert_eq!(outbox, released, "released exactly what was committed");
        for m in &released {
            assert!(matches!(p.bob_receives(&m.wire).unwrap(), Received::Accepted(_)));
        }
    }

    // ── Unknown commit outcome (simulated) ────────────────────────────────────

    #[test]
    fn an_unknown_send_outcome_releases_nothing_until_recovered() {
        for fault in [CommitFault::UnknownStored, CommitFault::UnknownLost] {
            let mut p = memory_peers();
            test_hooks::inject(fault);
            let r = p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, b"maybe");
            assert!(matches!(
                r,
                Err(MessagingError::OutcomeUnknown {
                    attempted_generation: 1,
                    ..
                })
            ));
            assert!(matches!(
                p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, b"next"),
                Err(MessagingError::Unresolved {
                    attempted_generation: 1
                })
            ));
            let rec = p.am.recover(&mut p.a, p.alice_pk, ALICE_HANDLE).unwrap().unwrap();
            let pending = p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap();
            match fault {
                CommitFault::UnknownStored => {
                    assert_eq!((rec.stored_generation, rec.artifact_committed), (1, true));
                    assert_eq!(pending.len(), 1, "the committed message is in the outbox");
                    assert_eq!(
                        *accepted(p.bob_receives(&pending[0].wire).unwrap()).plaintext,
                        b"maybe"
                    );
                }
                _ => {
                    assert_eq!((rec.stored_generation, rec.artifact_committed), (0, false));
                    assert!(pending.is_empty());
                }
            }
            assert_eq!(p.am.recover(&mut p.a, p.alice_pk, ALICE_HANDLE).unwrap(), None);
            let next = p.alice_sends(b"after");
            assert_eq!(*accepted(p.bob_receives(&next.wire).unwrap()).plaintext, b"after");
        }
    }

    #[test]
    fn an_unknown_receive_outcome_shows_nothing_until_recovered() {
        for fault in [CommitFault::UnknownStored, CommitFault::UnknownLost] {
            let mut p = memory_peers();
            let sent = p.alice_sends(b"in");
            test_hooks::inject(fault);
            assert!(matches!(
                p.bob_receives(&sent.wire),
                Err(MessagingError::OutcomeUnknown { .. })
            ));
            assert!(matches!(
                p.bob_receives(&sent.wire),
                Err(MessagingError::Unresolved { .. })
            ));
            let rec = p.bm.recover(&mut p.b, p.bob_pk, BOB_HANDLE).unwrap().unwrap();
            let pending = p.bm.pending_incoming(&p.b, BOB_HANDLE).unwrap();
            match fault {
                CommitFault::UnknownStored => {
                    assert!(rec.artifact_committed);
                    assert_eq!(*pending[0].plaintext, b"in");
                    assert!(matches!(
                        p.bob_receives(&sent.wire).unwrap(),
                        Received::Duplicate { .. }
                    ));
                }
                _ => {
                    assert!(!rec.artifact_committed);
                    assert!(pending.is_empty());
                    assert_eq!(*accepted(p.bob_receives(&sent.wire).unwrap()).plaintext, b"in");
                }
            }
        }
    }

    #[test]
    fn a_failed_commit_leaves_the_session_usable_and_consumes_no_position() {
        let mut p = memory_peers();
        test_hooks::inject(CommitFault::NotCommitted);
        assert!(matches!(
            p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, b"lost"),
            Err(MessagingError::NotCommitted(_))
        ));
        assert!(p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap().is_empty());
        let sent = p.alice_sends(b"kept");
        let header = Header::from_bytes(&sent.wire[..HEADER_SIZE]).unwrap();
        assert_eq!(header.n, 0, "the failed attempt used no chain position");
        assert_eq!(*accepted(p.bob_receives(&sent.wire).unwrap()).plaintext, b"kept");
    }

    // ── Process termination ───────────────────────────────────────────────────
    //
    // The child is this test binary, re-run to execute only `crash_child`. It
    // performs one operation on a file database and dies by `abort()` —
    // either inside the store transaction (`CRASH_AT_ENV`) or right after the
    // operation returned. The parent then reopens the database. These are real
    // process deaths on the host OS; they are not power-loss tests.

    const CHILD_ENV: &str = "ARCIUM_MSG_CHILD";
    const DIR_ENV: &str = "ARCIUM_MSG_DIR";

    struct Fixture {
        dir: PathBuf,
        alice_pk: [u8; 32],
        bob_pk: [u8; 32],
    }

    fn fixture(dir: &Path) -> Fixture {
        let p = setup(
            EncryptedStore::open(dir.join("a.db"), KEY).unwrap(),
            EncryptedStore::open(dir.join("b.db"), KEY).unwrap(),
        );
        std::fs::write(dir.join("ids"), [p.alice_pk, p.bob_pk].concat()).unwrap();
        Fixture {
            dir: dir.to_path_buf(),
            alice_pk: p.alice_pk,
            bob_pk: p.bob_pk,
        }
    }

    impl Fixture {
        fn peers(&self) -> Peers {
            Peers {
                a: EncryptedStore::open(self.dir.join("a.db"), KEY).unwrap(),
                b: EncryptedStore::open(self.dir.join("b.db"), KEY).unwrap(),
                am: Messenger::new(),
                bm: Messenger::new(),
                alice_pk: self.alice_pk,
                bob_pk: self.bob_pk,
            }
        }
    }

    #[test]
    fn crash_child() {
        let (Ok(scenario), Ok(dir)) = (std::env::var(CHILD_ENV), std::env::var(DIR_ENV)) else {
            return; // Not a child run.
        };
        let dir = PathBuf::from(dir);
        let ids = std::fs::read(dir.join("ids")).unwrap();
        let fx = Fixture {
            dir: dir.clone(),
            alice_pk: ids[..32].try_into().unwrap(),
            bob_pk: ids[32..].try_into().unwrap(),
        };
        let mut p = fx.peers();
        match scenario.as_str() {
            "send" => {
                let m = p.alice_sends(b"crash");
                // Published: the caller had the bytes and handed them on.
                std::fs::write(dir.join("published"), &m.wire).unwrap();
            }
            "receive" => {
                let wire = std::fs::read(dir.join("wire")).unwrap();
                accepted(p.bob_receives(&wire).unwrap());
            }
            "create" => {
                let pr = pair();
                let mut ns = new_session(42, pr.bob, SessionRole::Responder);
                ns.extra = vec![SideWrite::replace(
                    "prekeys/v2".into(),
                    Zeroizing::new(b"old".to_vec()),
                    Zeroizing::new(b"rotated".to_vec()),
                )
                .unwrap()];
                std::fs::write(dir.join("created_peer"), pr.alice_pk).unwrap();
                p.bm.create_session(&mut p.b, pr.bob_pk, ns).unwrap();
            }
            other => panic!("unknown scenario {other}"),
        }
        // Died after the operation returned, before acknowledging anything.
        std::process::abort();
    }

    /// Runs `scenario` in a child process that dies at `point`
    /// (`before_commit`, `after_commit`, or `after_return`).
    #[cfg(unix)]
    fn run_child(fx: &Fixture, scenario: &str, point: &str) {
        use std::os::unix::process::ExitStatusExt;
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", "messaging::tests::crash_child", "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, scenario)
            .env(DIR_ENV, &fx.dir);
        if point != "after_return" {
            cmd.env(CRASH_AT_ENV, point);
        }
        let status = cmd.status().unwrap();
        assert_eq!(status.signal(), Some(6), "child must die by abort(): {status:?}");
    }

    #[cfg(unix)]
    #[test]
    fn process_killed_before_commit_of_a_send_leaves_no_trace() {
        let dir = tempfile::tempdir().unwrap();
        let fx = fixture(dir.path());
        run_child(&fx, "send", "before_commit");
        let mut p = fx.peers();
        assert_eq!(generation(&mut p.a, p.alice_pk, ALICE_HANDLE), 0);
        assert!(p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap().is_empty());
        let m = p.alice_sends(b"retry");
        assert_eq!(Header::from_bytes(&m.wire[..HEADER_SIZE]).unwrap().n, 0);
        assert_eq!(*accepted(p.bob_receives(&m.wire).unwrap()).plaintext, b"retry");
    }

    #[cfg(unix)]
    #[test]
    fn process_killed_after_commit_of_a_send_keeps_the_message_for_resending() {
        for point in ["after_commit", "after_return"] {
            let dir = tempfile::tempdir().unwrap();
            let fx = fixture(dir.path());
            run_child(&fx, "send", point);
            let mut p = fx.peers();
            assert_eq!(generation(&mut p.a, p.alice_pk, ALICE_HANDLE), 1, "{point}");
            let pending = p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap();
            assert_eq!(pending.len(), 1, "{point}");
            if point == "after_return" {
                let published = std::fs::read(dir.path().join("published")).unwrap();
                assert_eq!(pending[0].wire, published, "byte-identical across the crash");
            }
            // Resend twice (e.g. delivery unknown): same bytes, one acceptance.
            drop(p);
            let mut p = fx.peers();
            let again = p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap();
            assert_eq!(again, pending);
            assert_eq!(*accepted(p.bob_receives(&again[0].wire).unwrap()).plaintext, b"crash");
            assert!(matches!(p.bob_receives(&pending[0].wire).unwrap(), Received::Duplicate { .. }));
            // The conversation continues in both directions.
            let r = p.bob_sends(b"reply");
            assert_eq!(*accepted(p.alice_receives(&r.wire).unwrap()).plaintext, b"reply");
            let m = p.alice_sends(b"more");
            assert_eq!(*accepted(p.bob_receives(&m.wire).unwrap()).plaintext, b"more");
        }
    }

    #[cfg(unix)]
    #[test]
    fn process_killed_during_a_receive_loses_nothing_and_accepts_once() {
        for point in ["before_commit", "after_commit", "after_return"] {
            let dir = tempfile::tempdir().unwrap();
            let fx = fixture(dir.path());
            let wire = fx.peers().alice_sends(b"inbound").wire;
            std::fs::write(dir.path().join("wire"), &wire).unwrap();
            run_child(&fx, "receive", point);
            let mut p = fx.peers();
            let pending = p.bm.pending_incoming(&p.b, BOB_HANDLE).unwrap();
            if point == "before_commit" {
                assert_eq!(generation(&mut p.b, p.bob_pk, BOB_HANDLE), 0);
                assert!(pending.is_empty());
                assert_eq!(*accepted(p.bob_receives(&wire).unwrap()).plaintext, b"inbound");
            } else {
                assert_eq!(generation(&mut p.b, p.bob_pk, BOB_HANDLE), 1, "{point}");
                assert_eq!(*pending[0].plaintext, b"inbound", "committed, undelivered");
                assert!(matches!(
                    p.bob_receives(&wire).unwrap(),
                    Received::Duplicate {
                        undelivered: Some(_),
                        ..
                    }
                ));
                assert_eq!(generation(&mut p.b, p.bob_pk, BOB_HANDLE), 1);
                p.bm.acknowledge_incoming(&mut p.b, BOB_HANDLE, &pending[0].message_id)
                    .unwrap();
            }
            let r = p.bob_sends(b"back");
            assert_eq!(*accepted(p.alice_receives(&r.wire).unwrap()).plaintext, b"back");
        }
    }

    /// The responder shape: prekey rotation and session creation are one
    /// transaction, so a crash leaves both or neither.
    #[cfg(unix)]
    #[test]
    fn process_killed_during_session_creation_leaves_both_records_or_neither() {
        for point in ["before_commit", "after_commit"] {
            let dir = tempfile::tempdir().unwrap();
            let fx = fixture(dir.path());
            fx.peers().b.put("prekeys/v2", b"old").unwrap();
            run_child(&fx, "create", point);
            let p = fx.peers();
            let created: [u8; 32] = std::fs::read(dir.path().join("created_peer"))
                .unwrap()
                .try_into()
                .unwrap();
            let handle = p.bm.peer_of(&p.b, 42).unwrap();
            let session = p.b.get(&session_storage_key(&created));
            let prekeys = p.b.get("prekeys/v2").unwrap();
            if point == "before_commit" {
                assert_eq!(handle, None);
                assert!(matches!(session, Err(StorageError::NotFound)));
                assert_eq!(prekeys, b"old", "prekey not consumed");
            } else {
                assert_eq!(handle, Some(created));
                assert!(session.is_ok());
                assert_eq!(prekeys, b"rotated");
            }
        }
    }
}
