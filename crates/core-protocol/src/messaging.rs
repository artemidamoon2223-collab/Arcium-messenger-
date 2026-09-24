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
    CommitError, Conflict, DurableSession, OpenError, S1CheckpointStore, SideWrite, SideWriteError,
    StageError,
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
fn encode_inbox(
    state: u8,
    generation: u64,
    id: &MessageId,
    plaintext: &[u8],
) -> Zeroizing<Vec<u8>> {
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
    NoSession {
        handle: u64,
    },
    /// This peer already has a session (valid or not); nothing was written.
    AlreadyExists {
        handle: u64,
    },
    /// The handle is registered to a different peer; nothing was written.
    HandleCollision {
        handle: u64,
    },
    /// The handle names a peer whose session record is missing.
    MissingSession {
        handle: u64,
    },
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
    ExtraConflict {
        index: usize,
        conflict: Conflict,
    },
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
    Unresolved {
        attempted_generation: u64,
    },
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
