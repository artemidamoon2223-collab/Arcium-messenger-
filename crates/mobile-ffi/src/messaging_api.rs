//! The durable messaging surface of [`ArciumCore`] (S2-B2): sending,
//! receiving, pending messages, acknowledgements and recovery. Every call goes
//! through `core_protocol::messaging::Messenger`, which commits the session
//! state together with the operation's record before anything is returned.
//! Specification: `docs/S2-B2-DURABLE-MESSAGING.md`.

use zeroize::Zeroizing;

use core_protocol::messaging::{self, MessagingError, Received};

use crate::{ArciumCore, CoreError};

impl CoreError {
    /// Maps a messaging failure on `session_id` onto the FFI error surface.
    pub(crate) fn messaging(session_id: u64, e: MessagingError) -> Self {
        use MessagingError as M;
        match e {
            M::NoSession { .. } => CoreError::NoSession { session_id },
            M::AlreadyExists { .. } => CoreError::SessionAlreadyExists { session_id },
            M::HandleCollision { .. } => CoreError::SessionIdCollision { session_id },
            M::MissingSession { .. } => CoreError::InvalidSessionState {
                session_id,
                msg: "handle is registered but its session record is missing".into(),
            },
            M::InvalidSession(e) => CoreError::InvalidSessionState {
                session_id,
                msg: e.to_string(),
            },
            M::InvalidRecord(what) => CoreError::InvalidSessionState {
                session_id,
                msg: format!("corrupt {what} record"),
            },
            M::InconsistentStore(what) => CoreError::InvalidSessionState {
                session_id,
                msg: what.into(),
            },
            M::MalformedMessage => CoreError::Crypto {
                msg: "malformed message".into(),
            },
            M::Ratchet(e) => CoreError::from(e),
            M::Checkpoint(e) => CoreError::Crypto { msg: e.to_string() },
            M::GenerationExhausted => CoreError::Crypto {
                msg: "session generation exhausted".into(),
            },
            M::Conflict(_) => CoreError::SessionConflict { session_id },
            M::ExtraConflict { .. } | M::SideWrite(_) => CoreError::Storage {
                msg: "conflicting write".into(),
            },
            M::Store(e) | M::NotCommitted(e) => CoreError::from(e),
            M::OutcomeUnknown {
                attempted_generation,
                ..
            } => CoreError::CommitOutcomeUnknown {
                session_id,
                attempted_generation,
            },
            M::Unresolved {
                attempted_generation,
            } => CoreError::SessionUnresolved {
                session_id,
                attempted_generation,
            },
            M::UnknownMessage => CoreError::UnknownMessage { session_id },
        }
    }
}

// ── Durable messaging records ─────────────────────────────────────────────────

/// A committed outgoing message. `wire` is exactly what must be sent — on
/// the first attempt and on every retransmission.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OutgoingMessage {
    /// 32-byte id of this exact message; both peers derive the same one.
    pub message_id: Vec<u8>,
    /// `header(40) || ciphertext`, the unchanged wire format.
    pub wire: Vec<u8>,
}

/// A committed incoming message.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IncomingMessage {
    pub message_id: Vec<u8>,
    pub plaintext: Vec<u8>,
}

/// The result of `receive_message`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ReceiveResult {
    /// Newly accepted and committed as undelivered. Show it, then call
    /// `acknowledge_incoming`.
    Accepted { message: IncomingMessage },
    /// Accepted before; the ratchet was not touched. `undelivered` carries it
    /// again if it was never acknowledged.
    Duplicate {
        message_id: Vec<u8>,
        undelivered: Option<IncomingMessage>,
    },
}

/// What `recover_session` found for a session whose commit outcome was
/// unknown.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RecoveryReport {
    pub attempted_generation: u64,
    pub stored_generation: u64,
    /// Whether, as the store reads now, the unresolved operation took effect
    /// (its outbox / inbox / session record exists).
    pub artifact_committed: bool,
}

fn outgoing(m: messaging::OutgoingMessage) -> OutgoingMessage {
    OutgoingMessage {
        message_id: m.message_id.to_vec(),
        wire: m.wire,
    }
}

fn incoming(m: messaging::IncomingMessage) -> IncomingMessage {
    IncomingMessage {
        message_id: m.message_id.to_vec(),
        plaintext: m.plaintext.to_vec(),
    }
}

fn message_id_arg(session_id: u64, id: &[u8]) -> Result<messaging::MessageId, CoreError> {
    id.try_into()
        .map_err(|_| CoreError::UnknownMessage { session_id })
}

#[uniffi::export]
impl ArciumCore {
    /// The handshake stored with the initiator session under `session_id`,
    /// for sending again after a restart. `None` for a responder session.
    pub fn initiator_handshake(&self, session_id: u64) -> Result<Option<Vec<u8>>, CoreError> {
        let (store, messenger) = self.lock()?;
        messenger
            .initial_outbound(&store, session_id)
            .map_err(|e| CoreError::messaging(session_id, e))
    }

    /// Whether a session is stored under `session_id`.
    pub fn has_session(&self, session_id: u64) -> Result<bool, CoreError> {
        let (store, messenger) = self.lock()?;
        Ok(messenger
            .peer_of(&store, session_id)
            .map_err(|e| CoreError::messaging(session_id, e))?
            .is_some())
    }

    /// Encrypts `plaintext` for the session under `session_id`. The new
    /// session state and the outbox record holding the returned bytes are
    /// committed together before this returns; nothing is returned otherwise.
    ///
    /// The message stays in `pending_outgoing` until `acknowledge_outgoing`.
    /// To resend, send those stored bytes again — never call this again for
    /// the same logical message.
    pub fn send_message(
        &self,
        session_id: u64,
        plaintext: Vec<u8>,
    ) -> Result<OutgoingMessage, CoreError> {
        let our = self.our_identity_pk()?;
        let plaintext = Zeroizing::new(plaintext);
        let (mut store, mut messenger) = self.lock()?;
        messenger
            .send(&mut store, our, session_id, &plaintext)
            .map(outgoing)
            .map_err(|e| CoreError::messaging(session_id, e))
    }

    /// Every committed, unacknowledged outgoing message for `session_id`, in
    /// send order, with the exact bytes to (re)send.
    pub fn pending_outgoing(&self, session_id: u64) -> Result<Vec<OutgoingMessage>, CoreError> {
        let (store, messenger) = self.lock()?;
        messenger
            .pending_outgoing(&store, session_id)
            .map(|v| v.into_iter().map(outgoing).collect())
            .map_err(|e| CoreError::messaging(session_id, e))
    }

    /// Removes an outgoing message once its delivery is confirmed. Returns
    /// whether it was still pending; repeating it is harmless.
    pub fn acknowledge_outgoing(
        &self,
        session_id: u64,
        message_id: Vec<u8>,
    ) -> Result<bool, CoreError> {
        let id = message_id_arg(session_id, &message_id)?;
        let (store, messenger) = self.lock()?;
        messenger
            .acknowledge_outgoing(&store, session_id, &id)
            .map_err(|e| CoreError::messaging(session_id, e))
    }

    /// Decrypts `message` (the `wire` bytes of a peer's `OutgoingMessage`).
    ///
    /// A new message advances the session and is committed as undelivered
    /// before its plaintext is returned; it stays in `pending_incoming` until
    /// `acknowledge_incoming`. A message received before returns `Duplicate`
    /// and advances nothing. A forged message fails and writes nothing (F-1).
    pub fn receive_message(
        &self,
        session_id: u64,
        message: Vec<u8>,
    ) -> Result<ReceiveResult, CoreError> {
        let our = self.our_identity_pk()?;
        let (mut store, mut messenger) = self.lock()?;
        let received = messenger
            .receive(&mut store, our, session_id, &message)
            .map_err(|e| CoreError::messaging(session_id, e))?;
        Ok(match received {
            Received::Accepted(m) => ReceiveResult::Accepted {
                message: incoming(m),
            },
            Received::Duplicate {
                message_id,
                undelivered,
            } => ReceiveResult::Duplicate {
                message_id: message_id.to_vec(),
                undelivered: undelivered.map(incoming),
            },
        })
    }

    /// Every committed incoming message for `session_id` not yet
    /// acknowledged, in receive order.
    pub fn pending_incoming(&self, session_id: u64) -> Result<Vec<IncomingMessage>, CoreError> {
        let (store, messenger) = self.lock()?;
        messenger
            .pending_incoming(&store, session_id)
            .map(|v| v.into_iter().map(incoming).collect())
            .map_err(|e| CoreError::messaging(session_id, e))
    }

    /// Marks an incoming message delivered and erases its stored plaintext.
    /// Returns whether it was undelivered until now; repeating it is harmless.
    pub fn acknowledge_incoming(
        &self,
        session_id: u64,
        message_id: Vec<u8>,
    ) -> Result<bool, CoreError> {
        let id = message_id_arg(session_id, &message_id)?;
        let (mut store, messenger) = self.lock()?;
        messenger
            .acknowledge_incoming(&mut store, session_id, &id)
            .map_err(|e| CoreError::messaging(session_id, e))
    }

    /// After `CommitOutcomeUnknown`: reports what the store holds for the
    /// session and lets it continue from there. `None` if it was not
    /// unresolved. The unresolved operation's output was never released, so
    /// continuing cannot compete with anything sent or shown. This reflects
    /// what the store reads now; it proves nothing about power loss.
    pub fn recover_session(&self, session_id: u64) -> Result<Option<RecoveryReport>, CoreError> {
        let our = self.our_identity_pk()?;
        let (mut store, mut messenger) = self.lock()?;
        Ok(messenger
            .recover(&mut store, our, session_id)
            .map_err(|e| CoreError::messaging(session_id, e))?
            .map(|r| RecoveryReport {
                attempted_generation: r.attempted_generation,
                stored_generation: r.stored_generation,
                artifact_committed: r.artifact_committed,
            }))
    }
}
