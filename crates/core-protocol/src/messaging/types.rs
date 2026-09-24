//! Public types of [`super`].

use core_crypto::ratchet::RatchetError;
use core_storage::StorageError;
use zeroize::Zeroizing;

use super::MessageId;
use crate::checkpoint::{SessionCheckpointError, SessionRole};
use crate::durable::{Conflict, SideWrite, SideWriteError};
use crate::Session;

// ── Public types ──────────────────────────────────────────────────────────────

/// A committed outgoing message. `wire` is exactly what must be sent, on the
/// first attempt and on every retransmission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingMessage {
    pub message_id: MessageId,
    /// The caller's id for this logical message, as given to
    /// [`Messenger::send`](super::Messenger::send).
    pub client_message_id: Vec<u8>,
    /// The session generation this message's send committed.
    pub generation: u64,
    pub wire: Vec<u8>,
}

/// The result of [`Messenger::send`](super::Messenger::send).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendOutcome {
    /// Newly encrypted and committed with its outbox record.
    Sent(OutgoingMessage),
    /// This logical message was sent before and is still pending: the stored
    /// message, byte for byte. Nothing was encrypted and the ratchet did not
    /// move.
    AlreadyPending(OutgoingMessage),
    /// This logical message was sent before and has been acknowledged.
    /// Nothing was encrypted.
    AlreadyAcknowledged { message_id: MessageId },
    /// This logical message was sent before and then abandoned
    /// ([`Messenger::abandon_outgoing`](super::Messenger::abandon_outgoing)):
    /// the peer may or may not have it. Nothing was encrypted; sending the
    /// content again takes a new logical id.
    Abandoned { message_id: MessageId },
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
    /// An acknowledgement, abandonment or removal may or may not have taken
    /// effect. Repeating the call is safe and reports what the store holds.
    RepeatableOutcomeUnknown(StorageError),
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
    /// A caller's logical message id must be 1 to
    /// [`MAX_CLIENT_MESSAGE_ID_LEN`](super::MAX_CLIENT_MESSAGE_ID_LEN) bytes.
    InvalidClientMessageId,
    /// The session has committed a message from the peer, so the peer holds
    /// it: removing it locally would leave the peer with a session this side
    /// no longer has. Nothing was changed.
    SessionEstablished,
    /// The session has outgoing messages that are neither acknowledged nor
    /// abandoned. Nothing was changed.
    PendingOutgoing {
        count: usize,
    },
}
