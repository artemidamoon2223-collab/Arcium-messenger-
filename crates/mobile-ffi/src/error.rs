//! `CoreError`, the error every exported call returns, and its conversions.

use super::*;

#[derive(Debug, Error, uniffi::Error)]
pub enum CoreError {
    #[error("storage error: {msg}")]
    Storage { msg: String },
    #[error("invalid master key: {msg}")]
    InvalidKey { msg: String },
    #[error("handshake error: {msg}")]
    Handshake { msg: String },
    #[error("no session for id {session_id}")]
    NoSession { session_id: u64 },
    /// A session for this id and this same peer already exists. Establishing
    /// again would discard the live Double Ratchet, so it is refused rather
    /// than silently resetting it.
    #[error("session {session_id} already established with this peer")]
    SessionAlreadyExists { session_id: u64 },
    /// This id already belongs to a *different* peer — a 64-bit handle
    /// collision. Overwriting would hand one contact's ratchet to another.
    #[error("session id {session_id} is already held by a different peer")]
    SessionIdCollision { session_id: u64 },
    #[error("ratchet error: {msg}")]
    Crypto { msg: String },
    /// The bytes are not a well-formed `PREKEY_BUNDLE_V1`: wrong length, a
    /// non-zero reserved byte, unknown flag bits, or a non-canonical
    /// representation of "no one-time prekey".
    #[error("invalid prekey bundle: {msg}")]
    InvalidPrekeyBundle { msg: String },
    /// The bytes are not a well-formed `INITIATOR_HANDSHAKE_V1`.
    #[error("invalid handshake: {msg}")]
    InvalidHandshake { msg: String },
    /// The peer is speaking a protocol version or cipher suite this build does
    /// not implement. Distinct from a malformed structure: the bytes parsed far
    /// enough to name what they are.
    #[error("unsupported protocol version {version} / cipher suite {suite}")]
    UnsupportedProtocolVersion { version: u8, suite: u8 },
    /// The signed-prekey signature did not verify over
    /// `SIGNED_PREKEY_OBJECT_V1`. The bundle is not authentic — its parts do not
    /// belong together — so it must not be used, and refetching will not help.
    #[error("signed prekey signature is not valid for this bundle")]
    BadSignedPrekeySignature,
    /// The named one-time prekey is not the currently usable one: it was either
    /// already consumed (a replay, or an honest retry of a completed handshake)
    /// or never existed here. Both mean the same thing to the caller — fetch a
    /// fresh bundle — and this build keeps no history that could tell them apart.
    #[error("one-time prekey {opk_id} is not available")]
    OneTimePrekeyUnavailable { opk_id: u64 },
    /// A one-time prekey is currently published, but the handshake declined to
    /// use one. Refusing is what prevents a silent downgrade: the one-time
    /// prekey fields are outside the signature, so an attacker who strips them
    /// from a bundle in flight would otherwise get a weaker X3DH accepted.
    #[error("this handshake must use the currently published one-time prekey")]
    OneTimePrekeyRequired,
    /// The handshake names a signed prekey this device no longer holds:
    /// neither the current one nor the previous one, or the previous one
    /// after the one-time prekey it was published with changed. The peer's
    /// bundle predates a rotation; fetching a fresh one resolves it.
    #[error("signed prekey is stale")]
    StaleSignedPrekey,
    /// Another instance on the same database committed this session first.
    /// Nothing was written and nothing was released; calling again works
    /// from the newer state.
    #[error("session {session_id} was advanced by another instance; nothing was written")]
    SessionConflict { session_id: u64 },
    /// The commit of this operation reported an error after which the store
    /// may or may not hold it. Its output was withheld. The session refuses
    /// further operations until `recover_session`.
    #[error("commit outcome unknown for session {session_id} (generation {attempted_generation})")]
    CommitOutcomeUnknown { session_id: u64, attempted_generation: u64 },
    /// An earlier commit on this session had an unknown outcome; call
    /// `recover_session` first.
    #[error("session {session_id} is unresolved (generation {attempted_generation}); call recover_session")]
    SessionUnresolved { session_id: u64, attempted_generation: u64 },
    /// A stored session or message record is corrupt, unsupported or bound to
    /// other identities. It is left untouched and is never replaced by a new
    /// session.
    #[error("stored state for session {session_id} is invalid: {msg}")]
    InvalidSessionState { session_id: u64, msg: String },
    /// No message with this id is recorded for this session.
    #[error("unknown message for session {session_id}")]
    UnknownMessage { session_id: u64 },
    /// A client message id must be 1 to 64 bytes, and not one the network
    /// layer reserves for its own messages (see `send_message`).
    #[error("client message id must be 1 to 64 bytes and not reserved")]
    InvalidClientMessageId,
    /// The session has accepted a message from the peer, so the peer holds
    /// it too; it cannot be removed locally (only deleting the contact,
    /// `delete_contact`, discards it). Nothing changed.
    #[error("session {session_id} is established and cannot be removed")]
    SessionEstablished { session_id: u64 },
    /// The session has outgoing messages that are neither acknowledged nor
    /// abandoned. Only the network layer does either, on the peer's receipt,
    /// in `resolve_session_conflict`, or in `delete_contact`. Nothing changed.
    #[error("session {session_id} has {count} pending outgoing messages")]
    PendingOutgoing { session_id: u64, count: u64 },
    /// An acknowledgement, abandonment or removal may or may not have taken
    /// effect. Repeating the same call is safe and reports what is stored.
    #[error("outcome unknown for an operation on session {session_id}; repeat it")]
    RepeatableOutcomeUnknown { session_id: u64 },
    /// The relay could not be reached, or the connection failed; whether the
    /// last request took effect is unknown. Nothing local was lost.
    #[error("network: {msg}")]
    Network { msg: String },
    /// Not a `CONTACT_CARD_V1`.
    #[error("invalid contact card: {msg}")]
    InvalidContactCard { msg: String },
    /// A different card is already pinned for this identity. Nothing changed.
    #[error("a different card is already pinned for this identity")]
    ContactIdentityChanged,
    /// The peer is not a pinned contact.
    #[error("unknown contact")]
    UnknownContact,
    /// The relay has no prekey bundle for the peer.
    #[error("the peer has no published prekey bundle")]
    PeerBundleUnavailable,
    /// The peer's published bundle names identity keys other than its pinned
    /// card's. Nothing was created.
    #[error("the published bundle does not match the pinned contact card")]
    PeerIdentityMismatch,
    /// An argument outside what the call accepts (a name, a text, an id), or
    /// a request the current state does not allow. Nothing changed.
    #[error("invalid argument: {msg}")]
    InvalidArgument { msg: String },
    /// An identity record is stored but cannot be used: it does not decrypt,
    /// or it is not the 64-byte identity format. It is neither "no identity"
    /// nor replaced; nothing changed.
    #[error("the stored identity cannot be read: {msg}")]
    IdentityUnreadable { msg: String },
    /// `save_identity` found an identity already stored. Identities are
    /// created once and never replaced; nothing changed. `load_identity`
    /// returns the stored one.
    #[error("an identity is already stored")]
    IdentityAlreadyExists,
}

impl From<StorageError> for CoreError {
    fn from(e: StorageError) -> Self {
        CoreError::Storage { msg: e.to_string() }
    }
}

impl From<X3dhError> for CoreError {
    fn from(e: X3dhError) -> Self {
        CoreError::Handshake { msg: e.to_string() }
    }
}

impl From<RatchetError> for CoreError {
    fn from(e: RatchetError) -> Self {
        CoreError::Crypto { msg: e.to_string() }
    }
}
