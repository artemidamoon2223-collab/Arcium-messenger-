use core_crypto::ratchet::{DoubleRatchet, RatchetError};
use core_crypto::spk_id::{spk_id, SPK_ID_LEN};
use core_crypto::x3dh::{
    signed_prekey_object_v1, x3dh_initiate, x3dh_respond, PrekeyBundle, X3dhError, CIPHER_SUITE,
    PROTOCOL_VERSION,
};
use core_protocol::checkpoint::SessionRole;
use core_protocol::durable::SideWrite;
use core_protocol::messaging::{
    FirstContact, Messenger, MessagingError, NewSession, ProvisionalHandshake, Received,
    ValidatedRecord,
};
use core_protocol::Session;
use core_storage::{EncryptedStore, StorageError};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

mod contacts;
mod messaging_api;
pub(crate) mod network;
mod plaintext;
pub use messaging_api::{IncomingMessage, OutgoingMessage, ReceiveResult, RecoveryReport, SendResult};
pub use plaintext::{PlaintextBytes, PlaintextText};

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

// ── Local session handles ─────────────────────────────────────────────────────

/// Derives the caller's own lookup handle for the session with the peer whose
/// 32-byte X25519 identity public key is `peer_identity_pk`, so the platform
/// layer never has to reimplement a hash to obtain the `u64` this API's session
/// methods take.
///
/// The handle is local: it is transmitted nowhere, and the peer may pick a
/// different one for the same session. It is also a truncation, so it is not
/// collision-free — but the caller does not have to police that: an occupied
/// handle is never overwritten. `establish_session_*` fails with
/// `SessionIdCollision` when a different peer already holds it, and with
/// `SessionAlreadyExists` when the same peer does.
///
/// This is deliberately **not** `hash_contact`, which hashes a phone number for
/// PSI and is pinned to the deployed circuit; see `core_crypto::session_handle`.
#[uniffi::export]
pub fn local_session_handle(peer_identity_pk: Vec<u8>) -> Result<u64, CoreError> {
    let pk: [u8; 32] = peer_identity_pk.as_slice().try_into().map_err(|_| CoreError::InvalidKey {
        msg: format!(
            "expected a 32-byte peer identity public key, got {}",
            peer_identity_pk.len()
        ),
    })?;
    Ok(core_crypto::session_handle::local_session_handle(&pk))
}

// ── Identity ──────────────────────────────────────────────────────────────────

#[derive(uniffi::Object)]
pub struct Identity {
    signing_key: SigningKey,
    dh_key: StaticSecret,
}

#[uniffi::export]
impl Identity {
    #[uniffi::constructor]
    pub fn generate() -> Arc<Self> {
        Arc::new(Self {
            signing_key: SigningKey::generate(&mut OsRng),
            dh_key: StaticSecret::random_from_rng(OsRng),
        })
    }

    /// Returns the 32-byte Ed25519 verifying (public) key.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }

    /// Returns the 32-byte X25519 DH public key (used for X3DH key agreement).
    /// Distinct from `public_key_bytes()`, which is the Ed25519 signing key.
    pub fn dh_public_key_bytes(&self) -> Vec<u8> {
        PublicKey::from(&self.dh_key).as_bytes().to_vec()
    }
}

// ── ArciumCore ────────────────────────────────────────────────────────────────

const IDENTITY_KEY: &str = "identity/v1";
/// The Ed25519 signing secret, then the X25519 secret.
const IDENTITY_RECORD_LEN: usize = 64;

/// Classifies a read of `IDENTITY_KEY`: only a missing record is `Ok(None)`.
fn identity_from_record(read: Result<Vec<u8>, StorageError>) -> Result<Option<Arc<Identity>>, CoreError> {
    let bytes = match read {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(StorageError::NotFound) => return Ok(None),
        Err(StorageError::Decryption) => {
            return Err(CoreError::IdentityUnreadable {
                msg: "the record does not decrypt".into(),
            })
        }
        Err(e) => return Err(e.into()),
    };
    if bytes.len() != IDENTITY_RECORD_LEN {
        return Err(CoreError::IdentityUnreadable {
            msg: format!("the record is {} bytes, expected {IDENTITY_RECORD_LEN}", bytes.len()),
        });
    }
    let mut sk_bytes = Zeroizing::new([0u8; 32]);
    let mut dh_bytes = Zeroizing::new([0u8; 32]);
    sk_bytes.copy_from_slice(&bytes[..32]);
    dh_bytes.copy_from_slice(&bytes[32..]);
    Ok(Some(Arc::new(Identity {
        signing_key: SigningKey::from_bytes(&sk_bytes),
        dh_key: StaticSecret::from(*dh_bytes),
    })))
}

// The prekey record. The key moved to `v2` when `ARCIUM_X3DH_FORMAT_V1` changed
// the record's contents: a v1 record cannot be reinterpreted, so it simply stops
// being found. The key did not move again for `PERSISTED_PREKEY_RECORD_V3`
// (tracker R-6): every writer, the one-time-prekey replacement of option B and
// the conditional writes name this one record, and the V2 value it may hold is
// read in place. The V2 parser cannot be aimed at as a downgrade: a V2 record
// reads as published long ago, so its only effect is a rotation at the next
// round (`plan_rotation`).
const PREKEYS_KEY: &str = "prekeys/v2";

/// The [`handshake_identity`] of the handshake this device's responder
/// session with the peer came from (32 bytes), written in the transaction
/// that stores the session (`accept_first_message`) and replaced by the
/// next one. The network layer reads it to tell the contact's late
/// retransmission of that handshake, which it never refuses, from a restart
/// it can no longer answer, which it does (option B; `docs/NET-MESSAGING.md`
/// section 10, "Reset"). Not removed with the session: an older value only
/// names a handshake whose session is gone. Removed with the contact.
pub(crate) fn accepted_handshake_key(peer: &[u8; 32]) -> String {
    let hex: String = peer.iter().map(|b| format!("{b:02x}")).collect();
    format!("hsacc:v1/{hex}")
}

/// What makes two initiator handshakes the same for [`accepted_handshake_key`]:
/// they derive the same keys here. Not the bytes: the ephemeral key has
/// encodings that X25519 reads as the same point (the ignored top bit), and
/// points that differ from it by a low-order point, which every clamped
/// scalar, so every DH this device makes with it, cancels. A relay can put
/// any of them in place of the initiator's, and the session made from it is
/// the initiator's session (review of option B). So the ephemeral key
/// enters as its X25519 with a fixed public scalar, which is equal for
/// exactly those keys; the other fields enter as they are, since the
/// parser and the pinned card fix their bytes. A fresh handshake has a
/// fresh ephemeral key, so it never matches.
fn handshake_identity(handshake: &InitiatorHandshakeV1) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let ephemeral = StaticSecret::from([1u8; 32]).diffie_hellman(&handshake.ephemeral_pk);
    let opk = handshake.opk_id.map_or([0u8; 9], |id| {
        let mut b = [1u8; 9];
        b[1..].copy_from_slice(&id.to_be_bytes());
        b
    });
    Sha256::new()
        .chain_update(b"ARCIUM-ACCEPTED-HANDSHAKE-V1")
        .chain_update(handshake.identity_pk.as_bytes())
        .chain_update(ephemeral.as_bytes())
        .chain_update(handshake.spk_id)
        .chain_update(opk)
        .finalize()
        .into()
}

/// The side write recording `handshake` as the one the responder session
/// with `peer` about to be stored came from ([`accepted_handshake_key`]). It
/// replaces the record of an earlier session only if that is still the
/// record read here. A record that cannot be read (damaged, or tampered
/// with) is deleted first and the new one inserted: until then late copies
/// of the handshake are refused, as for a session an older build stored.
fn accepted_handshake_write(
    store: &mut EncryptedStore,
    peer: &[u8; 32],
    handshake: &InitiatorHandshakeV1,
) -> Result<SideWrite, CoreError> {
    let key = accepted_handshake_key(peer);
    let value = Zeroizing::new(handshake_identity(handshake).to_vec());
    let write = match store.get(&key) {
        Ok(old) => SideWrite::replace(key, Zeroizing::new(old), value),
        Err(StorageError::NotFound) => SideWrite::insert(key, value),
        Err(StorageError::Decryption) => {
            store.delete(&key)?;
            SideWrite::insert(key, value)
        }
        Err(e) => return Err(e.into()),
    };
    write.map_err(|_| CoreError::Storage {
        msg: "accepted-handshake key is reserved".into(),
    })
}

/// Marks a store whose one-time prekey was replaced once for option B
/// ([`ArciumCore::replace_prekey_once`]).
const PREKEY_RENEWED_KEY: &str = "prekeys/renewed-b0";

// ── ARCIUM_X3DH_FORMAT_V1 ─────────────────────────────────────────────────────
//
// Three fixed-width structures. Fixed width is deliberate: the pre-v1 formats had
// two valid lengths each and branched on a flag while parsing, which is the shape
// that lets a length check and a field offset disagree. Here every structure has
// exactly one length, "absent" is encoded as an all-zero region that is *checked*,
// and the flag only says how to interpret bytes that are always present.
//
// Every multi-byte integer is big-endian.

/// `PREKEY_BUNDLE_V1`, exactly 204 bytes.
///
/// ```text
///   0   1  protocol_version = 0x01
///   1   1  cipher_suite     = 0x01
///   2   1  flags            bit0 = has_otp, bits 1..7 = 0
///   3   1  reserved         = 0x00
///   4  32  identity_dh_pk         ┐
///  36  32  signing_pk             ├ covered by spk_signature
///  68  32  signed_prekey_pk       ┘
/// 100  64  spk_signature
/// 164   8  opk_id (u64 big-endian)   ┐ zero when has_otp = 0
/// 172  32  opk_pk                    ┘
/// ```
pub const PREKEY_BUNDLE_V1_LEN: usize = 204;
/// `INITIATOR_HANDSHAKE_V1`, exactly 84 bytes.
///
/// ```text
///   0   1  protocol_version = 0x01
///   1   1  cipher_suite     = 0x01
///   2   1  flags            bit0 = used_otp, bits 1..7 = 0
///   3   1  reserved         = 0x00
///   4  32  initiator_identity_dh_pk
///  36  32  initiator_ephemeral_pk
///  68   8  spk_id
///  76   8  opk_id (u64 big-endian)   zero when used_otp = 0
/// ```
pub const INITIATOR_HANDSHAKE_V1_LEN: usize = 84;
/// `PERSISTED_PREKEY_RECORD_V2`, exactly 138 bytes. Never transmitted. Read,
/// no longer written: the first write of the record replaces it with V3.
///
/// ```text
///   0   1  record_version = 0x01
///   1  32  signed_prekey_sk
///  33  64  spk_signature
///  97   1  flags   bit0 = opk_present, bits 1..7 = 0
///  98   8  opk_id (u64 big-endian)   ┐ zero when opk_present = 0
/// 106  32  opk_sk                    ┘
/// ```
const PREKEY_RECORD_V2_LEN: usize = 138;
const RECORD_VERSION: u8 = 0x01;
/// `PERSISTED_PREKEY_RECORD_V3`, exactly 186 bytes. Never transmitted. Its
/// first 138 bytes have the V2 layout.
///
/// ```text
///   0   1  record_version = 0x02
///   1  32  signed_prekey_sk        the current signed prekey
///  33  64  spk_signature           of the current one, over SIGNED_PREKEY_OBJECT_V1
///  97   1  flags   bit0 = opk_present, bit1 = prev_present, bit2 = born_present,
///                  bits 3..7 = 0
///  98   8  opk_id (u64 big-endian)   ┐ zero when opk_present = 0
/// 106  32  opk_sk                    ┘
/// 138   8  published_at (u64 big-endian): Unix seconds of this device's clock
///          when the relay first accepted a bundle naming the current signed
///          prekey; 0 = not yet, 1 = long ago (read from V2)
/// 146   8  born_opk_id (u64 big-endian): the one-time prekey held when the
///          current signed prekey was made; zero when born_present = 0
/// 154  32  prev_signed_prekey_sk   zero when prev_present = 0
/// ```
///
/// A previous signed prekey is held only together with the one-time prekey
/// the current one was made with (prev_present requires opk_present,
/// born_present and born_opk_id = opk_id); any other record is corrupt. It
/// keeps no signature: it is never published again.
const PREKEY_RECORD_V3_LEN: usize = 186;
const RECORD_VERSION_V3: u8 = 0x02;
/// Bit 1 of a V3 record's flags: a previous signed prekey is held.
const FLAG_PREV: u8 = 0b0000_0010;
/// Bit 2 of a V3 record's flags: `born_opk_id` is set.
const FLAG_BORN: u8 = 0b0000_0100;
/// `published_at` of a signed prekey the relay has not accepted yet. It
/// never ages (`plan_rotation`).
const PUBLISHED_NOT_YET: u64 = 0;
/// `published_at` of a signed prekey read from a V2 record: published at
/// an unknown time, so due for rotation at once.
const PUBLISHED_LONG_AGO: u64 = 1;
/// How long a signed prekey stays current after the relay first accepted
/// it, and how long it then stays the previous one (tracker R-6): 7 days,
/// the relay's envelope lifetime.
pub(crate) const SIGNED_PREKEY_PERIOD_SECS: u64 = 7 * 24 * 60 * 60;

/// Bit 0 of a `flags` byte: "a one-time prekey is present / was used".
const FLAG_OTP: u8 = 0b0000_0001;

/// Rejects any flag bit this version does not define. Unknown bits are refused
/// rather than masked off so a future version cannot be silently downgraded into
/// this one by a peer that sets them.
fn check_flags(flags: u8, what: &str) -> Result<bool, CoreError> {
    if flags & !FLAG_OTP != 0 {
        return Err(match what {
            "bundle" => CoreError::InvalidPrekeyBundle {
                msg: format!("unknown flag bits set: {flags:#04x}"),
            },
            _ => CoreError::InvalidHandshake {
                msg: format!("unknown flag bits set: {flags:#04x}"),
            },
        });
    }
    Ok(flags & FLAG_OTP != 0)
}

/// Checks the version/suite header shared by both wire structures.
fn check_version_and_suite(version: u8, suite: u8) -> Result<(), CoreError> {
    if version != PROTOCOL_VERSION || suite != CIPHER_SUITE {
        return Err(CoreError::UnsupportedProtocolVersion { version, suite });
    }
    Ok(())
}

/// A freshly generated one-time prekey and its opaque identifier.
///
/// The identifier is random rather than a counter on purpose: a bundle is public,
/// so a monotonic value would publish how many sessions this device has accepted.
fn new_one_time_prekey() -> (u64, StaticSecret) {
    let mut id = [0u8; 8];
    OsRng.fill_bytes(&mut id);
    (u64::from_be_bytes(id), StaticSecret::random_from_rng(OsRng))
}

/// Which signed prekey of a [`PrekeyRecord`] answers a handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Spk {
    /// The one the published bundle names.
    Current,
    /// The one before it, kept for one period after a rotation.
    Previous,
}

/// A parsed prekey record (`PERSISTED_PREKEY_RECORD_V3`, or V2 read in
/// place). Every secret in it wipes itself on drop.
struct PrekeyRecord {
    signed_prekey_sk: StaticSecret,
    signature: Signature,
    /// The currently published one-time prekey, if any.
    opk: Option<(u64, StaticSecret)>,
    /// When the relay first accepted a bundle naming the current signed
    /// prekey ([`PUBLISHED_NOT_YET`], [`PUBLISHED_LONG_AGO`]).
    published_at: u64,
    /// The one-time prekey id held when the current signed prekey was made.
    born_opk: Option<u64>,
    /// The signed prekey before the current one.
    prev: Option<StaticSecret>,
}

impl PrekeyRecord {
    /// A new record for `identity`: a new signed prekey and a new one-time
    /// prekey, not yet published, no previous signed prekey.
    fn new(identity: &Identity) -> Self {
        let (signed_prekey_sk, signature) = new_signed_prekey(identity);
        let opk = new_one_time_prekey();
        Self {
            signed_prekey_sk,
            signature,
            born_opk: Some(opk.0),
            opk: Some(opk),
            published_at: PUBLISHED_NOT_YET,
            prev: None,
        }
    }

    /// This record's current signed-prekey public key.
    fn signed_prekey_pk(&self) -> PublicKey {
        PublicKey::from(&self.signed_prekey_sk)
    }

    /// The id of the one-time prekey held, if any.
    fn opk_id(&self) -> Option<u64> {
        self.opk.as_ref().map(|(id, _)| *id)
    }

    /// The secret of the signed prekey `which`.
    fn signed_prekey(&self, which: Spk) -> Result<&StaticSecret, CoreError> {
        match which {
            Spk::Current => Ok(&self.signed_prekey_sk),
            Spk::Previous => self.prev.as_ref().ok_or(CoreError::StaleSignedPrekey),
        }
    }

    /// Publishes a new one-time prekey in place of the one held. The
    /// previous signed prekey goes with it: it answers only together with
    /// the one-time prekey it was published with (`check_answerable`).
    fn renew_one_time_prekey(&mut self) {
        self.opk = Some(new_one_time_prekey());
        self.prev = None;
    }
}

/// A new signed prekey for `identity` and its signature over
/// `SIGNED_PREKEY_OBJECT_V1`.
fn new_signed_prekey(identity: &Identity) -> (StaticSecret, Signature) {
    let signed_prekey_sk = StaticSecret::random_from_rng(OsRng);
    let object = signed_prekey_object_v1(
        &PublicKey::from(&identity.dh_key),
        &identity.signing_key.verifying_key(),
        &PublicKey::from(&signed_prekey_sk),
    );
    let signature = identity.signing_key.sign(&object);
    (signed_prekey_sk, signature)
}

/// Serializes `record` as `PERSISTED_PREKEY_RECORD_V3`.
fn pack_prekeys(record: &PrekeyRecord) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![0u8; PREKEY_RECORD_V3_LEN]);
    out[0] = RECORD_VERSION_V3;
    out[1..33].copy_from_slice(record.signed_prekey_sk.as_bytes());
    out[33..97].copy_from_slice(&record.signature.to_bytes());
    let mut flags = 0;
    if let Some((id, sk)) = &record.opk {
        flags |= FLAG_OTP;
        out[98..106].copy_from_slice(&id.to_be_bytes());
        out[106..138].copy_from_slice(sk.as_bytes());
    }
    out[138..146].copy_from_slice(&record.published_at.to_be_bytes());
    if let Some(id) = record.born_opk {
        flags |= FLAG_BORN;
        out[146..154].copy_from_slice(&id.to_be_bytes());
    }
    if let Some(sk) = &record.prev {
        flags |= FLAG_PREV;
        out[154..186].copy_from_slice(sk.as_bytes());
    }
    out[97] = flags;
    // Absent regions stay zero from the initial fill.
    out
}

/// Parses a prekey record: V3, or V2 read as published long ago, born with
/// its one-time prekey and without a previous signed prekey.
fn unpack_prekeys(bytes: &[u8]) -> Result<PrekeyRecord, CoreError> {
    let corrupt = |msg: String| CoreError::Storage { msg };
    let (len, known_flags) = match bytes.first() {
        Some(&RECORD_VERSION) => (PREKEY_RECORD_V2_LEN, FLAG_OTP),
        Some(&RECORD_VERSION_V3) => (PREKEY_RECORD_V3_LEN, FLAG_OTP | FLAG_PREV | FLAG_BORN),
        Some(other) if [PREKEY_RECORD_V2_LEN, PREKEY_RECORD_V3_LEN].contains(&bytes.len()) => {
            return Err(corrupt(format!("unknown prekey record version {other:#04x}")));
        }
        _ => {
            return Err(corrupt(format!(
                "corrupt prekey record: {} bytes, expected {PREKEY_RECORD_V3_LEN}",
                bytes.len()
            )));
        }
    };
    if bytes.len() != len {
        return Err(corrupt(format!(
            "corrupt prekey record: {} bytes, expected {len} for version {:#04x}",
            bytes.len(),
            bytes[0]
        )));
    }
    let zero = |range: std::ops::Range<usize>, what: &str| {
        if bytes[range].iter().any(|b| *b != 0) {
            return Err(corrupt(format!(
                "corrupt prekey record: {what} absent but its bytes are not zero"
            )));
        }
        Ok(())
    };
    let u64_at = |at: usize| u64::from_be_bytes(bytes[at..at + 8].try_into().expect("checked length"));
    let secret_at = |at: usize| {
        let sk: Zeroizing<[u8; 32]> =
            Zeroizing::new(bytes[at..at + 32].try_into().expect("checked length"));
        StaticSecret::from(*sk)
    };

    let flags = bytes[97];
    if flags & !known_flags != 0 {
        return Err(corrupt(format!(
            "corrupt prekey record: unknown flag bits {flags:#04x}"
        )));
    }
    let sig_bytes: [u8; 64] = bytes[33..97].try_into().expect("checked length");
    let opk = if flags & FLAG_OTP != 0 {
        Some((u64_at(98), secret_at(106)))
    } else {
        zero(98..138, "one-time prekey")?;
        None
    };
    let opk_id = opk.as_ref().map(|(id, _)| *id);
    let (published_at, born_opk, prev) = if len == PREKEY_RECORD_V2_LEN {
        (PUBLISHED_LONG_AGO, opk_id, None)
    } else {
        let born_opk = if flags & FLAG_BORN != 0 {
            Some(u64_at(146))
        } else {
            zero(146..154, "birth one-time prekey")?;
            None
        };
        let prev = if flags & FLAG_PREV != 0 {
            if opk_id.is_none() || born_opk != opk_id {
                return Err(corrupt(
                    "corrupt prekey record: a previous signed prekey without the one-time prekey it was published with".into(),
                ));
            }
            Some(secret_at(154))
        } else {
            zero(154..186, "previous signed prekey")?;
            None
        };
        (u64_at(138), born_opk, prev)
    };
    Ok(PrekeyRecord {
        signed_prekey_sk: secret_at(1),
        signature: Signature::from_bytes(&sig_bytes),
        opk,
        published_at,
        born_opk,
        prev,
    })
}

/// A rotation of the signed prekey that is due ([`plan_rotation`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rotation {
    /// Whether the current signed prekey becomes the previous one.
    keep_previous: bool,
}

/// Whether the signed prekey of `record` is due for rotation at `now`
/// (Unix seconds of this device's clock), and how (tracker R-6):
/// - (E) the one-time prekey changed since the current signed prekey was
///   made: rotate, and keep no previous key. Every bundle this device
///   published pairs a signed prekey with the one-time prekey held then,
///   and a handshake is answered only with the one-time prekey it names
///   (X-6), so no honest handshake can be answered under either key any
///   more.
/// - (T) the relay accepted the current one `SIGNED_PREKEY_PERIOD_SECS` or
///   more ago, in either direction of the clock: rotate, and keep the
///   current one as the previous one if the one-time prekey it was
///   published with is held. A key never accepted does not age.
fn plan_rotation(record: &PrekeyRecord, now: u64) -> Option<Rotation> {
    if record.opk_id() != record.born_opk {
        return Some(Rotation { keep_previous: false });
    }
    if record.published_at != PUBLISHED_NOT_YET
        && now.abs_diff(record.published_at) >= SIGNED_PREKEY_PERIOD_SECS
    {
        return Some(Rotation {
            keep_previous: record.opk.is_some(),
        });
    }
    None
}

/// Applies `rotation` to `record`: a new signed prekey made for
/// `identity`, not yet published, born with the one-time prekey held. The
/// old previous key is dropped (and wiped), and so is the old current one
/// unless it is kept as the previous one.
fn rotate_signed_prekey(record: &mut PrekeyRecord, identity: &Identity, rotation: Rotation) {
    let (signed_prekey_sk, signature) = new_signed_prekey(identity);
    let old = std::mem::replace(&mut record.signed_prekey_sk, signed_prekey_sk);
    record.signature = signature;
    record.prev = rotation.keep_previous.then_some(old);
    record.born_opk = record.opk_id();
    record.published_at = PUBLISHED_NOT_YET;
}

fn bytes_to_pubkey(b: &[u8]) -> Result<PublicKey, CoreError> {
    let arr: [u8; 32] = b.try_into().map_err(|_| CoreError::Handshake {
        msg: "expected a 32-byte public key".into(),
    })?;
    Ok(PublicKey::from(arr))
}

/// Serializes a `PREKEY_BUNDLE_V1`.
fn pack_prekey_bundle(
    identity_dh_pk: &PublicKey,
    signing_pk: &VerifyingKey,
    signed_prekey_pk: &PublicKey,
    signature: &Signature,
    opk: Option<(u64, PublicKey)>,
) -> Vec<u8> {
    let mut out = vec![0u8; PREKEY_BUNDLE_V1_LEN];
    out[0] = PROTOCOL_VERSION;
    out[1] = CIPHER_SUITE;
    out[3] = 0x00; // reserved
    out[4..36].copy_from_slice(identity_dh_pk.as_bytes());
    out[36..68].copy_from_slice(&signing_pk.to_bytes());
    out[68..100].copy_from_slice(signed_prekey_pk.as_bytes());
    out[100..164].copy_from_slice(&signature.to_bytes());
    if let Some((id, pk)) = opk {
        out[2] = FLAG_OTP;
        out[164..172].copy_from_slice(&id.to_be_bytes());
        out[172..204].copy_from_slice(pk.as_bytes());
    }
    out
}

fn unpack_prekey_bundle(bytes: &[u8]) -> Result<PrekeyBundle, CoreError> {
    if bytes.len() != PREKEY_BUNDLE_V1_LEN {
        return Err(CoreError::InvalidPrekeyBundle {
            msg: format!(
                "expected {PREKEY_BUNDLE_V1_LEN} bytes, got {}",
                bytes.len()
            ),
        });
    }
    check_version_and_suite(bytes[0], bytes[1])?;
    let has_otp = check_flags(bytes[2], "bundle")?;
    if bytes[3] != 0 {
        return Err(CoreError::InvalidPrekeyBundle {
            msg: format!("reserved byte must be zero, got {:#04x}", bytes[3]),
        });
    }

    let identity_pk = bytes_to_pubkey(&bytes[4..36])?;
    let signing_pk_bytes: [u8; 32] = bytes[36..68].try_into().expect("checked length");
    let signing_pk =
        VerifyingKey::from_bytes(&signing_pk_bytes).map_err(|_| CoreError::InvalidPrekeyBundle {
            msg: "invalid signing public key".into(),
        })?;
    let signed_prekey_pk = bytes_to_pubkey(&bytes[68..100])?;
    let sig_bytes: [u8; 64] = bytes[100..164].try_into().expect("checked length");
    let signed_prekey_signature = Signature::from_bytes(&sig_bytes);

    let (one_time_prekey_id, one_time_prekey_pk) = if has_otp {
        let id = u64::from_be_bytes(bytes[164..172].try_into().expect("checked length"));
        (Some(id), Some(bytes_to_pubkey(&bytes[172..204])?))
    } else {
        // "Absent" has exactly one encoding. Accepting arbitrary trailing bytes
        // would leave a channel that rides along inside an authentic bundle.
        if bytes[164..204].iter().any(|b| *b != 0) {
            return Err(CoreError::InvalidPrekeyBundle {
                msg: "one-time prekey absent but its bytes are not zero".into(),
            });
        }
        (None, None)
    };

    Ok(PrekeyBundle {
        identity_pk,
        signing_pk,
        signed_prekey_pk,
        signed_prekey_signature,
        one_time_prekey_pk,
        one_time_prekey_id,
    })
}

/// Parsed `INITIATOR_HANDSHAKE_V1`.
struct InitiatorHandshakeV1 {
    identity_pk: PublicKey,
    ephemeral_pk: PublicKey,
    spk_id: [u8; SPK_ID_LEN],
    /// The one-time prekey the initiator says it used, if any.
    opk_id: Option<u64>,
}

fn pack_initiator_handshake(
    identity_pk: &PublicKey,
    ephemeral_pk: &PublicKey,
    spk_id: &[u8; SPK_ID_LEN],
    opk_id: Option<u64>,
) -> Vec<u8> {
    let mut out = vec![0u8; INITIATOR_HANDSHAKE_V1_LEN];
    out[0] = PROTOCOL_VERSION;
    out[1] = CIPHER_SUITE;
    out[3] = 0x00; // reserved
    out[4..36].copy_from_slice(identity_pk.as_bytes());
    out[36..68].copy_from_slice(ephemeral_pk.as_bytes());
    out[68..76].copy_from_slice(spk_id);
    if let Some(id) = opk_id {
        out[2] = FLAG_OTP;
        out[76..84].copy_from_slice(&id.to_be_bytes());
    }
    out
}

fn unpack_initiator_handshake(bytes: &[u8]) -> Result<InitiatorHandshakeV1, CoreError> {
    if bytes.len() != INITIATOR_HANDSHAKE_V1_LEN {
        return Err(CoreError::InvalidHandshake {
            msg: format!(
                "expected {INITIATOR_HANDSHAKE_V1_LEN} bytes, got {}",
                bytes.len()
            ),
        });
    }
    check_version_and_suite(bytes[0], bytes[1])?;
    let used_otp = check_flags(bytes[2], "handshake")?;
    if bytes[3] != 0 {
        return Err(CoreError::InvalidHandshake {
            msg: format!("reserved byte must be zero, got {:#04x}", bytes[3]),
        });
    }

    let identity_pk = bytes_to_pubkey(&bytes[4..36])?;
    let ephemeral_pk = bytes_to_pubkey(&bytes[36..68])?;
    let spk_id: [u8; SPK_ID_LEN] = bytes[68..76].try_into().expect("checked length");

    let opk_id = if used_otp {
        Some(u64::from_be_bytes(
            bytes[76..84].try_into().expect("checked length"),
        ))
    } else {
        if bytes[76..84].iter().any(|b| *b != 0) {
            return Err(CoreError::InvalidHandshake {
                msg: "one-time prekey not used but its id is not zero".into(),
            });
        }
        None
    };

    // R-24: a low-order key would make X3DH refuse the handshake later, when
    // its first message arrives; refusing it here drops it on receipt, so it
    // is never recorded and no message waits on it.
    for (pk, what) in [(&identity_pk, "identity"), (&ephemeral_pk, "ephemeral")] {
        if has_low_order(pk) {
            return Err(CoreError::InvalidHandshake {
                msg: format!("the initiator {what} key has low order"),
            });
        }
    }

    Ok(InitiatorHandshakeV1 {
        identity_pk,
        ephemeral_pk,
        spk_id,
        opk_id,
    })
}

/// Whether `pk` encodes an X25519 point of low order (order 1, 2, 4 or 8):
/// exactly the keys for which every X25519 output is zero. The scalar is a
/// public constant. A clamped scalar is 8·k′ with 2^251 ≤ k′ < 2^252, so it
/// sends every point of order dividing 8 to zero, and no other point: k′ is
/// below the large prime orders of the curve and of its twist.
pub(crate) fn has_low_order(pk: &PublicKey) -> bool {
    !StaticSecret::from([1u8; 32]).diffie_hellman(pk).was_contributory()
}

// ── HANDSHAKE_REFUSAL_V1 ──────────────────────────────────────────────────────
//
// A responder that cannot answer an initiator's handshake (the prekeys it names
// were consumed or rotated) tells the initiator so. The initiator checks it
// against the pinned contact and against the handshake it actually sent, and
// only then gives up its own unconfirmed session (docs/NET-MESSAGING.md,
// section 6).
//
// ```text
//  0  32  refuser_identity_dh_pk
// 32  32  initiator_identity_dh_pk
// 64  32  sha256(INITIATOR_HANDSHAKE_V1 bytes)
// 96   1  reason   1 = one-time prekey unavailable, 2 = one-time prekey
//                  required, 3 = stale signed prekey
// 97  32  tag      core_crypto::refusal_mac over bytes 0..97
// ```
//
// The tag is a MAC keyed by a static DH of the two identity keys, not a
// signature: only the two parties can make or check it, and the initiator
// could have made it alone. So a refusal, which anyone can elicit with a forged
// handshake naming a contact, is no proof to a third party that the refuser
// has that contact pinned (review finding F-144-1).

/// The authenticated fields of `HANDSHAKE_REFUSAL_V1`.
const REFUSAL_FIELDS_LEN: usize = 3 * 32 + 1;
/// `HANDSHAKE_REFUSAL_V1`: the fields, then the tag.
pub(crate) const HANDSHAKE_REFUSAL_V1_LEN: usize =
    REFUSAL_FIELDS_LEN + core_crypto::refusal_mac::REFUSAL_TAG_LEN;

/// Why a handshake could not be answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefusalReason {
    OneTimePrekeyUnavailable = 1,
    OneTimePrekeyRequired = 2,
    StaleSignedPrekey = 3,
}

impl RefusalReason {
    /// The reason for a refusal error of `establish_session_responder`; `None`
    /// for every other error, which is not a statement about the handshake.
    pub(crate) fn of(e: &CoreError) -> Option<Self> {
        match e {
            CoreError::OneTimePrekeyUnavailable { .. } => Some(Self::OneTimePrekeyUnavailable),
            CoreError::OneTimePrekeyRequired => Some(Self::OneTimePrekeyRequired),
            CoreError::StaleSignedPrekey => Some(Self::StaleSignedPrekey),
            _ => None,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::OneTimePrekeyUnavailable),
            2 => Some(Self::OneTimePrekeyRequired),
            3 => Some(Self::StaleSignedPrekey),
            _ => None,
        }
    }
}

/// A `HANDSHAKE_REFUSAL_V1` whose tag checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HandshakeRefusal {
    pub refuser_dh_pk: [u8; 32],
    pub initiator_dh_pk: [u8; 32],
    pub handshake_hash: [u8; 32],
    pub reason: RefusalReason,
}

impl HandshakeRefusal {
    fn fields(&self) -> [u8; REFUSAL_FIELDS_LEN] {
        let mut out = [0u8; REFUSAL_FIELDS_LEN];
        out[0..32].copy_from_slice(&self.refuser_dh_pk);
        out[32..64].copy_from_slice(&self.initiator_dh_pk);
        out[64..96].copy_from_slice(&self.handshake_hash);
        out[96] = self.reason as u8;
        out
    }

    /// Parses `bytes` as a refusal by `refuser_dh_pk` of a handshake from
    /// the holder of `own_sk`, and checks its tag. `None` for anything else:
    /// a wrong length, an unknown reason, another refuser or initiator named
    /// in the fields, a tag that does not check (made by anyone but the two
    /// parties, or for other fields), a low-order refuser key. Says nothing
    /// about which handshake it names; the caller compares the hash.
    fn open(bytes: &[u8], own_sk: &StaticSecret, refuser_dh_pk: &[u8; 32]) -> Option<Self> {
        if bytes.len() != HANDSHAKE_REFUSAL_V1_LEN {
            return None;
        }
        let (fields, tag) = bytes.split_at(REFUSAL_FIELDS_LEN);
        let key = |r: std::ops::Range<usize>| -> [u8; 32] { fields[r].try_into().expect("32 bytes") };
        let refusal = Self {
            refuser_dh_pk: key(0..32),
            initiator_dh_pk: key(32..64),
            handshake_hash: key(64..96),
            reason: RefusalReason::from_byte(fields[96])?,
        };
        let own_pk = PublicKey::from(own_sk).to_bytes();
        if refusal.refuser_dh_pk != *refuser_dh_pk || refusal.initiator_dh_pk != own_pk {
            return None;
        }
        core_crypto::refusal_mac::verify_refusal_tag(
            own_sk,
            refuser_dh_pk,
            refuser_dh_pk,
            &own_pk,
            fields,
            tag,
        )
        .then_some(refusal)
    }
}

/// sha256 of a handshake, as a refusal names it.
pub(crate) fn handshake_hash(handshake: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(handshake).into()
}

/// The encrypted store and the durable messaging state machine over it.
///
/// Sessions live only in the store: every messaging call loads the session,
/// stages its transition, and commits the new state together with the
/// operation's outbox or inbox record before returning anything
/// (`core_protocol::messaging`, spec `docs/S2-B2-DURABLE-MESSAGING.md`).
/// Nothing about a session is cached here, so a second `ArciumCore` on the
/// same file cannot advance a session from a state it no longer holds.
///
/// Lock order: `store`, then `messenger`. `messenger` only records which
/// sessions have an unresolved commit.
#[derive(uniffi::Object)]
pub struct ArciumCore {
    store: Mutex<EncryptedStore>,
    messenger: Mutex<Messenger>,
}

#[uniffi::export]
impl ArciumCore {
    #[uniffi::constructor]
    pub fn new(storage_path: String, master_key: Vec<u8>) -> Result<Arc<Self>, CoreError> {
        // Wrap immediately so the caller-supplied master key is zeroized on
        // every exit path (F-8) — the Kotlin side already zeros its own copy
        // (PR #48's MasterKeyProvider), this covers what the Rust side holds.
        let master_key = Zeroizing::new(master_key);
        // Borrowed, not copied: the store makes the one copy it keeps, in its
        // own wiping owner, so no plain 32-byte array of the key exists here.
        let key: &[u8; 32] = master_key.as_slice().try_into().map_err(|_| CoreError::InvalidKey {
            msg: "expected exactly 32 bytes".into(),
        })?;
        let store = EncryptedStore::open_with_key(&storage_path, key)?;
        Ok(Arc::new(Self {
            store: Mutex::new(store),
            messenger: Mutex::new(Messenger::with_confirm_hook(Box::new(replace_prekey_on_confirm))),
        }))
    }

    /// Stores `identity` as this store's identity, only if it has none.
    ///
    /// Create-only: one transaction reads the identity record and writes
    /// only when there is none. Nothing is written when
    ///
    /// - an identity is stored and readable: `IdentityAlreadyExists`;
    /// - an identity record is stored but unreadable: `IdentityUnreadable`;
    /// - the store cannot be read or written: `Storage`.
    ///
    /// A `Storage` error from the final commit can leave the outcome unknown:
    /// the identity may have been stored (see `StoreTransaction::commit`).
    /// Calling again never replaces it: it returns `IdentityAlreadyExists` if
    /// the first call took effect, and `load_identity` returns that identity.
    pub fn save_identity(&self, identity: Arc<Identity>) -> Result<(), CoreError> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(IDENTITY_RECORD_LEN));
        bytes.extend_from_slice(identity.signing_key.as_bytes());
        bytes.extend_from_slice(identity.dh_key.as_bytes());
        let mut store = self
            .store
            .lock()
            .map_err(|_| CoreError::Storage { msg: "mutex poisoned".into() })?;
        // Dropping `tx` on any early return rolls it back; nothing is written.
        let tx = store.transaction()?;
        if identity_from_record(tx.get(IDENTITY_KEY))?.is_some() {
            return Err(CoreError::IdentityAlreadyExists);
        }
        tx.put(IDENTITY_KEY, &bytes)?;
        tx.commit()?;
        Ok(())
    }

    /// The stored identity. `Ok(None)` only when the store holds no identity
    /// record under this master key; a record that is stored but cannot be
    /// read is `IdentityUnreadable`, and a store that cannot be read is
    /// `Storage` — neither is reported as "no identity".
    ///
    /// The store finds records by a name derived from the master key, so
    /// `Ok(None)` does not show that the database file holds no identity
    /// under some other key.
    pub fn load_identity(&self) -> Result<Option<Arc<Identity>>, CoreError> {
        // A poisoned mutex must not panic across the FFI boundary.
        let store = self
            .store
            .lock()
            .map_err(|_| CoreError::Storage { msg: "mutex poisoned".into() })?;
        identity_from_record(store.get(IDENTITY_KEY))
    }

    /// Generates this device's signed prekey and one one-time prekey, signs the
    /// signed prekey over `SIGNED_PREKEY_OBJECT_V1`, and persists everything.
    ///
    /// Calling this again replaces both prekeys, and drops a previous signed
    /// prekey: a hard reset. Every bundle already handed out then names a
    /// signed prekey and a one-time prekey this device no longer holds, so
    /// handshakes built from those bundles are refused with
    /// `StaleSignedPrekey` / `OneTimePrekeyUnavailable` rather than silently
    /// deriving a key the peer cannot match.
    ///
    /// The network layer does not call it: it creates the record if none
    /// exists and rotates the signed prekey itself, at the start of every
    /// round (`ArciumCore::maintain_prekeys`, tracker R-6). Every answered
    /// handshake uses a one-time prekey (X-6). Once that prekey is replaced,
    /// the secrets this device keeps no longer derive the keys of a first
    /// message under it: the first message accepted under it replaces it,
    /// and so does the receive that confirms this device's own initiator
    /// session (`replace_prekey_on_confirm`). Until then they do, for any
    /// first contact under the prekey held, until the signed prekey it names
    /// is rotated out (`docs/NET-MESSAGING.md` section 8).
    pub fn establish_prekeys(&self) -> Result<(), CoreError> {
        let identity = self.require_identity()?;
        let record = PrekeyRecord::new(&identity);
        self.store
            .lock()
            .map_err(|_| CoreError::Storage {
                msg: "mutex poisoned".into(),
            })?
            .put(PREKEYS_KEY, &pack_prekeys(&record))?;
        Ok(())
    }

    /// Pure read of the already-persisted prekey material as a
    /// `PREKEY_BUNDLE_V1` (D3) — generates nothing and consumes nothing, so two
    /// calls return identical bytes. Fails if no prekey record exists yet.
    ///
    /// The network layer exports the bundle only to publish it, right after
    /// the rotation check of the round (`NetworkMessenger::put_bundle`). The
    /// rotation after a one-time-prekey change ((E), `plan_rotation`) relies
    /// on that: a bundle exported at any other time could pair the current
    /// signed prekey with a one-time prekey made since, and a handshake
    /// built from it would be refused once and made again. The exported
    /// calls that skip the round (this one, `establish_session_responder`,
    /// `receive_message`) neither rotate nor publish; no release code path
    /// on Android calls them (instrumentation tests and the debug crash
    /// provider do).
    pub fn export_prekey_bundle(&self) -> Result<Vec<u8>, CoreError> {
        let identity = self.require_identity()?;
        // The decrypted record holds the signed-prekey and one-time-prekey
        // secrets in the clear; wipe the buffer on every exit path (F-8), as
        // load_identity already does for the identity blob.
        let record_bytes = Zeroizing::new(
            self.store
                .lock()
                .map_err(|_| CoreError::Storage {
                    msg: "mutex poisoned".into(),
                })?
                .get(PREKEYS_KEY)?,
        );
        let record = unpack_prekeys(&record_bytes)?;

        Ok(pack_prekey_bundle(
            &PublicKey::from(&identity.dh_key),
            &identity.signing_key.verifying_key(),
            &record.signed_prekey_pk(),
            &record.signature,
            record.opk.as_ref().map(|(id, sk)| (*id, PublicKey::from(sk))),
        ))
    }

    /// Establishes a session as the X3DH initiator ("Alice") against a peer's
    /// `PREKEY_BUNDLE_V1`. Returns the 84-byte `INITIATOR_HANDSHAKE_V1` the peer
    /// needs for `establish_session_responder`.
    ///
    /// The signature over the bundle is checked before any Diffie-Hellman runs,
    /// so a bundle whose parts do not belong together never contributes key
    /// material.
    pub fn establish_session_initiator(
        &self,
        session_id: u64,
        peer_bundle: Vec<u8>,
    ) -> Result<Vec<u8>, CoreError> {
        let identity = self.require_identity()?;
        let bundle = unpack_prekey_bundle(&peer_bundle)?;
        let our_identity_pk = PublicKey::from(&identity.dh_key);

        // x3dh_initiate verifies the signed-prekey object first; surface that as
        // its own error rather than as a generic handshake failure.
        let alice_session =
            x3dh_initiate(&identity.dh_key, our_identity_pk, &bundle).map_err(|e| match e {
                X3dhError::BadSignature => CoreError::BadSignedPrekeySignature,
                other => CoreError::from(other),
            })?;

        let ratchet = DoubleRatchet::init_alice(
            &alice_session.root_key,
            alice_session.their_signed_prekey_pk,
        );
        // The root key's useful life ended with the ratchet; it is wiped here,
        // not at the end of the function, which commits to the store below.
        drop(alice_session.root_key);
        // The peer recorded as owner is the identity taken from the bundle —
        // the same key X3DH just ran against — so ownership cannot disagree
        // with the cryptography.
        let session = Session {
            ratchet,
            ad: alice_session.ad.clone(),
            peer_identity_pk: bundle.identity_pk.to_bytes(),
        };
        let handshake = pack_initiator_handshake(
            &our_identity_pk,
            &alice_session.ephemeral_pk,
            &spk_id(bundle.signed_prekey_pk.as_bytes()),
            bundle.one_time_prekey_id,
        );

        // The session, its handle and the handshake are committed together;
        // the handshake is returned only after that commit, and can be read
        // again with `initiator_handshake` if it is lost before being sent.
        let (mut store, mut messenger) = self.lock()?;
        messenger
            .create_session(
                &mut store,
                our_identity_pk.to_bytes(),
                NewSession {
                    handle: session_id,
                    session,
                    role: SessionRole::Initiator,
                    initial_outbound: Some(handshake.clone()),
                    extra: Vec::new(),
                },
            )
            .map_err(|e| CoreError::messaging(session_id, e))?;
        Ok(handshake)
    }

    /// Records the 84-byte `INITIATOR_HANDSHAKE_V1` an initiator ("Alice")
    /// produced, as the X3DH responder ("Bob"). **This creates no session.**
    ///
    /// Receiving a handshake is not authentication: its bytes are public and
    /// anyone can send them. So the handshake is only validated against this
    /// device's prekeys and recorded as *provisional* under `session_id`.
    /// Nothing is consumed, no handle is taken, `has_session` stays false, and
    /// a later handshake for this handle replaces it. The session is created
    /// by `receive_message(session_id, …)` when the initiator's first message
    /// authenticates under the keys this handshake derives — only that proves
    /// the initiator holds the secret of the identity key the handshake names.
    /// That same transaction consumes the one-time prekey.
    ///
    /// # Prekey rules
    ///
    /// The handshake names which signed prekey and which one-time prekey it
    /// used. This device answers from its own record, never from what the
    /// handshake asserts:
    ///
    /// | stored state | `used_otp` | named `opk_id` | outcome |
    /// |---|---|---|---|
    /// | any | any | any | `StaleSignedPrekey` if `spk_id` names neither the current signed prekey nor the previous one, or the previous one while the one-time prekey it was published with is no longer held |
    /// | one-time prekey held | yes | matches | recorded; consumed when the first message authenticates |
    /// | one-time prekey held | yes | differs | `OneTimePrekeyUnavailable` |
    /// | one-time prekey held | no | — | `OneTimePrekeyRequired` |
    /// | none held | no | — | `OneTimePrekeyRequired` |
    /// | none held | yes | any | `OneTimePrekeyUnavailable` |
    ///
    /// A one-time prekey error never falls back to the weaker no-`dh4` path: that
    /// would let anyone who can edit bytes in flight choose the weaker handshake.
    /// The same rules are checked again when the first message arrives, against
    /// the prekeys held then. The one-time-prekey rows apply alike under the
    /// current and the previous signed prekey (tracker R-6: a rotation keeps
    /// the previous one for one period, `plan_rotation`).
    ///
    /// Because a consumed identifier is replaced rather than remembered,
    /// replaying a handshake whose session was created names an identifier
    /// that is no longer current and is refused. That is the whole of the
    /// replay property claimed here. A handshake without a one-time prekey
    /// would have none (its root key re-derives identically on every replay),
    /// so it is never answered, also when this device holds no one-time
    /// prekey (tracker X-6); the wire format keeps the form, and an initiator
    /// still builds it from a bundle without one, which is then refused.
    ///
    /// # Refusals
    ///
    /// Once a session exists — authenticated, or started here as initiator —
    /// a handshake never replaces it: `SessionAlreadyExists` for this peer,
    /// `SessionIdCollision` if the handle belongs to another peer. Nothing is
    /// written and nothing is consumed. (A restart by the peer, option B, is
    /// recorded beside the session instead, and the network layer replaces
    /// the session only once its first message authenticates there.)
    ///
    /// # Sessions stored by older builds
    ///
    /// Builds before this one stored a responder session on receipt of a
    /// handshake. If this peer's session under `session_id` is exactly such a
    /// session with nothing done to it since — no message from the peer
    /// authenticated, nothing sent, nothing pending — it has no more
    /// authority than a recorded handshake: it is deleted with its handle
    /// and this handshake recorded in its place, in one transaction, only
    /// after this handshake passed the prekey rules above and only while the
    /// prekey record is still the one it passed them against. The one-time
    /// prekey the old session consumed stays consumed. Any other session is
    /// refused as above.
    pub fn establish_session_responder(
        &self,
        session_id: u64,
        initiator_handshake: Vec<u8>,
    ) -> Result<(), CoreError> {
        let identity = self.require_identity()?;
        let our_identity_pk = PublicKey::from(&identity.dh_key).to_bytes();
        let handshake = unpack_initiator_handshake(&initiator_handshake)?;
        let (mut store, messenger) = self.lock()?;
        let record_bytes = Zeroizing::new(store.get(PREKEYS_KEY)?);
        check_answerable(&unpack_prekeys(&record_bytes)?, &handshake)?;
        messenger
            .record_provisional_handshake(
                &mut store,
                our_identity_pk,
                session_id,
                &ProvisionalHandshake {
                    peer_identity_pk: handshake.identity_pk.to_bytes(),
                    handshake: initiator_handshake,
                },
                &ValidatedRecord {
                    key: PREKEYS_KEY.into(),
                    value: record_bytes,
                },
            )
            .map_err(|e| CoreError::messaging(session_id, e))
    }
}

/// Whether this device can answer `handshake` from its prekey `record` (the
/// table on `establish_session_responder`), and under which signed prekey.
/// Consumes nothing.
///
/// The current signed prekey is preferred when both would match (a
/// collision of the 8-byte ids). The previous one answers only while the
/// one-time prekey held is the one the current signed prekey was made with:
/// the one-time prekey every bundle naming the previous one was published
/// with is then gone (every writer that replaces the one-time prekey drops
/// the previous key too, `PrekeyRecord::renew_one_time_prekey`; this check
/// does not rely on it).
fn check_answerable(
    record: &PrekeyRecord,
    handshake: &InitiatorHandshakeV1,
) -> Result<Spk, CoreError> {
    let names = |sk: &StaticSecret| spk_id(PublicKey::from(sk).as_bytes()) == handshake.spk_id;
    let which = if names(&record.signed_prekey_sk) {
        Spk::Current
    } else if record.prev.as_ref().is_some_and(names)
        && record.opk.is_some()
        && record.opk_id() == record.born_opk
    {
        Spk::Previous
    } else {
        return Err(CoreError::StaleSignedPrekey);
    };
    match (record.opk_id(), handshake.opk_id) {
        (Some(held), Some(named)) if held == named => Ok(which),
        (Some(_), Some(named)) | (None, Some(named)) => {
            Err(CoreError::OneTimePrekeyUnavailable { opk_id: named })
        }
        // Without a one-time prekey nothing stops an exact replay of the
        // handshake and its first message (tracker X-6), so one is required
        // whether or not this device holds one.
        (Some(_), None) | (None, None) => Err(CoreError::OneTimePrekeyRequired),
    }
}

/// The responder's session for `handshake`: X3DH with this device's
/// identity, its signed prekey `signed_prekey_sk` (the current or the
/// previous one, as `check_answerable` chose) and the one-time prekey
/// `opk` the handshake names (if any), and the Double Ratchet initialised
/// from the root key. Shared by the promotion (`accept_first_message`, which
/// has taken `opk` out of the prekey record) and the check beside an own
/// session (`ArciumCore::beside_authenticates`, which only reads it), so
/// both derive exactly the same keys.
fn responder_session(
    identity: &Identity,
    our_identity_pk: PublicKey,
    signed_prekey_sk: &StaticSecret,
    opk: Option<&StaticSecret>,
    handshake: &InitiatorHandshakeV1,
) -> Result<Session, CoreError> {
    let bob_session = x3dh_respond(
        &identity.dh_key,
        our_identity_pk,
        signed_prekey_sk,
        opk,
        handshake.identity_pk,
        handshake.ephemeral_pk,
    )?;
    let ratchet = DoubleRatchet::init_bob(&bob_session.root_key, signed_prekey_sk.clone());
    // This runs for every candidate first message, including ones that will
    // not authenticate. The ratchet holds its own copy and wipes it on drop;
    // this one is wiped now rather than after a store commit.
    drop(bob_session.root_key);
    // Owner is the initiator identity this handshake was answered for, not
    // anything the caller asserted separately.
    Ok(Session {
        ratchet,
        ad: bob_session.ad.clone(),
        peer_identity_pk: handshake.identity_pk.to_bytes(),
    })
}

/// Creates the responder session for `provisional` from the initiator's
/// first message `wire`, if it authenticates (see `establish_session_responder`).
///
/// X3DH runs again from the provisional handshake against the prekeys held
/// now, which are checked again first. The session is stored — together with
/// the prekey record with a new one-time prekey in place of the one it used
/// and without a previous signed prekey, only if that record is still
/// byte-identical to the one read here — only if `wire` decrypts under it;
/// otherwise nothing is written. Under the previous signed prekey, its
/// secret is taken out of the record and wiped when this returns. The
/// signed prekey is not rotated here: the next round does, because the
/// one-time prekey changed ((E), `plan_rotation`).
fn accept_first_message(
    identity: &Identity,
    store: &mut EncryptedStore,
    messenger: &mut Messenger,
    session_id: u64,
    provisional: ProvisionalHandshake,
    wire: &[u8],
) -> Result<Received, CoreError> {
    let handshake = unpack_initiator_handshake(&provisional.handshake)?;
    if handshake.identity_pk.to_bytes() != provisional.peer_identity_pk {
        return Err(CoreError::InvalidSessionState {
            session_id,
            msg: "provisional handshake does not match its peer".into(),
        });
    }
    let record_bytes = Zeroizing::new(store.get(PREKEYS_KEY)?);
    let mut record = unpack_prekeys(&record_bytes)?;
    let our_identity_pk = PublicKey::from(&identity.dh_key);
    let which = match check_answerable(&record, &handshake) {
        Ok(which) => which,
        Err(refused) => {
            // Another instance on this database may have created the session
            // from this handshake since it was read here, consuming its prekey.
            // The message then belongs to that session.
            return match messenger.peer_of(store, session_id) {
                Ok(Some(_)) => messenger
                    .receive(store, our_identity_pk.to_bytes(), session_id, wire)
                    .map_err(|e| CoreError::messaging(session_id, e)),
                Ok(None) => Err(refused),
                Err(e) => Err(CoreError::messaging(session_id, e)),
            };
        }
    };
    let taken = record.opk.take().map(|(_, sk)| sk);
    // Out of the record before it is packed: the record written with the
    // session holds no previous signed prekey (`renew_one_time_prekey`).
    let previous = record.prev.take();
    let renewed = taken.is_some().then(|| {
        record.renew_one_time_prekey();
        pack_prekeys(&record)
    });
    let signed_prekey_sk = match which {
        Spk::Current => &record.signed_prekey_sk,
        Spk::Previous => previous.as_ref().ok_or(CoreError::StaleSignedPrekey)?,
    };

    let session = responder_session(
        identity,
        our_identity_pk,
        signed_prekey_sk,
        taken.as_ref(),
        &handshake,
    )?;
    let mut extra = match renewed {
        Some(new_record) => vec![SideWrite::replace(PREKEYS_KEY.into(), record_bytes, new_record)
            .map_err(|_| CoreError::Storage {
                msg: "prekey record key is reserved".into(),
            })?],
        None => Vec::new(),
    };
    extra.push(accepted_handshake_write(store, &provisional.peer_identity_pk, &handshake)?);
    let first = FirstContact {
        handle: session_id,
        session,
        provisional,
        extra,
    };
    match messenger.accept_first_message(store, our_identity_pk.to_bytes(), first, wire) {
        Ok(received) => Ok(received),
        // The prekey record (or the accepted-handshake record) changed since
        // it was read: another first message consumed the one-time prekey
        // first.
        Err(MessagingError::ExtraConflict { .. }) => Err(CoreError::OneTimePrekeyUnavailable {
            opk_id: handshake.opk_id.unwrap_or_default(),
        }),
        Err(e) => Err(CoreError::messaging(session_id, e)),
    }
}

/// The side write replacing this device's one-time prekey when its own
/// initiator session is confirmed: the first message from the peer
/// committed on it (`Messenger::with_confirm_hook`). The previous signed
/// prekey goes with it (`PrekeyRecord::renew_one_time_prekey`). The prekey
/// record held now is compared at commit, as when a first message consumes
/// a prekey.
///
/// Why: a handshake stays answerable for as long as the one-time prekey it
/// names is the published one and the signed prekey it names is held, and a
/// signed prekey is held for up to about two periods of rounds that
/// publish the bundle (tracker R-6, `plan_rotation`). Replacing the one-time prekey here makes every
/// handshake built from a bundle this device published before its session
/// with the peer was established unanswerable at once:
/// - a handshake of the peer recorded beside this session, whose first
///   message may have authenticated here, read with the prekey but never
///   accepted (a simultaneous start this device's session won), so that a
///   later leak of the store does not read those messages;
/// - a handshake of the peer this device never saw (withheld, or given up
///   by the peer), so that it and its first message, replayed later, cannot
///   replace the established session (option B): only a restart the peer
///   makes from a bundle published after this point can.
///
/// The cost: another contact's handshake that names the replaced prekey is
/// refused and that contact starts again, as after a first message consumed
/// it; so is a contact's restart of an established session (the network
/// layer refuses it, `record_restart`). Nothing when no prekey record is
/// held or it cannot be read.
fn replace_prekey_on_confirm(
    store: &EncryptedStore,
    _beside: Option<&ProvisionalHandshake>,
) -> Result<Vec<SideWrite>, MessagingError> {
    let bytes = match store.get(PREKEYS_KEY) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(StorageError::NotFound | StorageError::Decryption) => return Ok(Vec::new()),
        Err(e) => return Err(MessagingError::Store(e)),
    };
    let Ok(mut record) = unpack_prekeys(&bytes) else {
        return Ok(Vec::new());
    };
    if record.opk.is_none() {
        return Ok(Vec::new());
    }
    record.renew_one_time_prekey();
    let write = SideWrite::replace(PREKEYS_KEY.into(), bytes, pack_prekeys(&record))
        .map_err(MessagingError::SideWrite)?;
    Ok(vec![write])
}

// Plain (non-exported) impl block: helpers here are NOT visible to UniFFI,
// unlike methods inside the `#[uniffi::export] impl ArciumCore` block above,
// where export applies to every method regardless of Rust-level visibility.
impl ArciumCore {
    /// Locks the store, then the messenger (the only lock order used).
    #[allow(clippy::type_complexity)]
    fn lock(
        &self,
    ) -> Result<
        (
            std::sync::MutexGuard<'_, EncryptedStore>,
            std::sync::MutexGuard<'_, Messenger>,
        ),
        CoreError,
    > {
        let poisoned = |_| CoreError::Storage {
            msg: "mutex poisoned".into(),
        };
        let store = self.store.lock().map_err(poisoned)?;
        let messenger = self.messenger.lock().map_err(|_| CoreError::Storage {
            msg: "mutex poisoned".into(),
        })?;
        Ok((store, messenger))
    }

    /// Whether the session under `session_id` is a responder session an
    /// older build stored on receipt of a handshake, untouched since
    /// (`Messenger::is_legacy_unconfirmed`). Read-only: it decides nothing
    /// and changes nothing; `establish_session_responder` is what may retire
    /// such a session, after its own checks.
    pub(crate) fn is_legacy_unconfirmed(&self, session_id: u64) -> Result<bool, CoreError> {
        let our = self.our_identity_pk()?;
        let (mut store, messenger) = self.lock()?;
        messenger
            .is_legacy_unconfirmed(&mut store, our, session_id)
            .map_err(|e| CoreError::messaging(session_id, e))
    }

    /// Records `initiator_handshake`, received from the peer of this
    /// device's own unconfirmed initiator session, or of an established
    /// session (a possible restart, option B), under `session_id`, beside
    /// that session (`Messenger::record_handshake_beside`,
    /// docs/S2-B2-DURABLE-MESSAGING.md section 4c). It is checked against
    /// this device's prekeys first, by the rules of
    /// `establish_session_responder`, and refused with the same errors when
    /// it cannot be answered. Nothing is consumed and no session changes.
    /// The record has no authority: nothing is derived from it until a
    /// message authenticates under it (`beside_authenticates`).
    pub(crate) fn record_handshake_beside(
        &self,
        session_id: u64,
        initiator_handshake: &[u8],
    ) -> Result<(), CoreError> {
        let identity = self.require_identity()?;
        let our_identity_pk = PublicKey::from(&identity.dh_key).to_bytes();
        let handshake = unpack_initiator_handshake(initiator_handshake)?;
        let (mut store, messenger) = self.lock()?;
        let record_bytes = Zeroizing::new(store.get(PREKEYS_KEY)?);
        check_answerable(&unpack_prekeys(&record_bytes)?, &handshake)?;
        messenger
            .record_handshake_beside(
                &mut store,
                our_identity_pk,
                session_id,
                &ProvisionalHandshake {
                    peer_identity_pk: handshake.identity_pk.to_bytes(),
                    handshake: initiator_handshake.to_vec(),
                },
            )
            .map_err(|e| CoreError::messaging(session_id, e))
    }

    /// Replaces this device's one-time prekey once, the first time a build
    /// with option B runs on a store, and records that it did, in one
    /// transaction. Earlier builds kept the prekey when their own session
    /// was confirmed, so a genuine handshake of a contact built from it,
    /// which this device never saw (withheld by the relay during a
    /// simultaneous start the contact then gave up), could still be
    /// answered, and with its first message replace an established session
    /// (`docs/NET-MESSAGING.md` section 8). After this, as after every
    /// confirmation, it cannot. The cost: another contact's first contact
    /// or restart in flight under the old prekey is refused once and made
    /// again, its texts reading `NotDelivered` (a restart a contact made
    /// while this device ran an earlier build is one). The previous signed
    /// prekey goes too (`PrekeyRecord::renew_one_time_prekey`), and the
    /// round's rotation check then rotates the signed prekey ((E),
    /// `plan_rotation`).
    /// With no prekey record yet, only the mark is written. A mark that
    /// cannot be read counts as written: it must not stop every round.
    pub(crate) fn replace_prekey_once(&self) -> Result<(), CoreError> {
        let mut store = self.store.lock().map_err(|_| CoreError::Storage {
            msg: "mutex poisoned".into(),
        })?;
        match store.get(PREKEY_RENEWED_KEY) {
            Ok(_) | Err(StorageError::Decryption) => return Ok(()),
            Err(StorageError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        let tx = store.transaction()?;
        // Read again under the write lock: another connection to this
        // database may have done it meanwhile.
        match tx.get(PREKEY_RENEWED_KEY) {
            Ok(_) | Err(StorageError::Decryption) => return Ok(()),
            Err(StorageError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        match tx.get(PREKEYS_KEY) {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                let mut record = unpack_prekeys(&bytes)?;
                if record.opk.is_some() {
                    record.renew_one_time_prekey();
                    tx.put(PREKEYS_KEY, &pack_prekeys(&record))?;
                }
            }
            Err(StorageError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        tx.put(PREKEY_RENEWED_KEY, &[1])?;
        tx.commit()?;
        Ok(())
    }

    /// Creates this device's prekey record if none exists, or rotates its
    /// signed prekey if that is due at `now` (Unix seconds of this device's
    /// clock; `plan_rotation`, tracker R-6), in one transaction that reads
    /// the record again under the write lock, so two instances on one
    /// database create it once and rotate it once. Nothing is written when
    /// nothing is due; `true` when it wrote. A record that cannot be read is
    /// an error: the round fails, as its export would.
    pub(crate) fn maintain_prekeys(&self, now: u64) -> Result<bool, CoreError> {
        let identity = self.require_identity()?;
        let mut store = self.store.lock().map_err(|_| CoreError::Storage {
            msg: "mutex poisoned".into(),
        })?;
        // Most rounds have nothing to do: a plain read first, so they take
        // no write lock (as before rotation existed).
        match store.get(PREKEYS_KEY) {
            Ok(bytes) => {
                if plan_rotation(&unpack_prekeys(&Zeroizing::new(bytes))?, now).is_none() {
                    return Ok(false);
                }
            }
            Err(StorageError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        #[cfg(test)]
        prekey_hooks::after_plain_read();
        // Dropping `tx` on an early return rolls it back.
        let tx = store.transaction()?;
        let record = match tx.get(PREKEYS_KEY) {
            Ok(bytes) => {
                let mut record = unpack_prekeys(&Zeroizing::new(bytes))?;
                let Some(rotation) = plan_rotation(&record, now) else {
                    return Ok(false);
                };
                rotate_signed_prekey(&mut record, &identity, rotation);
                record
            }
            Err(StorageError::NotFound) => PrekeyRecord::new(&identity),
            Err(e) => return Err(e.into()),
        };
        #[cfg(test)]
        prekey_hooks::before_maintenance_write();
        tx.put(PREKEYS_KEY, &pack_prekeys(&record))?;
        tx.commit()?;
        Ok(true)
    }

    /// Records that the relay accepted a bundle naming the signed prekey
    /// `spk` at `now`, if that is the current signed prekey and no
    /// acceptance of it was recorded yet: from then on it ages
    /// (`plan_rotation`). Opens a transaction only when it writes, and reads
    /// the record again inside it.
    pub(crate) fn note_prekeys_published(
        &self,
        spk: &[u8; SPK_ID_LEN],
        now: u64,
    ) -> Result<(), CoreError> {
        let due = |record: &PrekeyRecord| {
            record.published_at == PUBLISHED_NOT_YET
                && spk_id(record.signed_prekey_pk().as_bytes()) == *spk
        };
        #[cfg(test)]
        if prekey_hooks::fail_note() {
            return Err(CoreError::Storage {
                msg: "test: the publication note fails".into(),
            });
        }
        let mut store = self.store.lock().map_err(|_| CoreError::Storage {
            msg: "mutex poisoned".into(),
        })?;
        if !due(&unpack_prekeys(&Zeroizing::new(store.get(PREKEYS_KEY)?))?) {
            return Ok(());
        }
        let tx = store.transaction()?;
        let mut record = unpack_prekeys(&Zeroizing::new(tx.get(PREKEYS_KEY)?))?;
        if !due(&record) {
            return Ok(());
        }
        // 0 means "not yet": a clock before 1970 still records a publication.
        record.published_at = now.max(PUBLISHED_LONG_AGO);
        tx.put(PREKEYS_KEY, &pack_prekeys(&record))?;
        tx.commit()?;
        Ok(())
    }

    /// Whether `handshake` from `peer` is the handshake this device's latest
    /// responder session with `peer` came from, in any encoding that derives
    /// the same keys ([`handshake_identity`], [`accepted_handshake_key`]).
    /// `false` if it does not parse, and if no such session was recorded:
    /// none exists, an older build stored it, or the record cannot be read
    /// (which must not stop a round).
    pub(crate) fn is_accepted_handshake(&self, peer: &[u8; 32], handshake: &[u8]) -> Result<bool, CoreError> {
        let Ok(parsed) = unpack_initiator_handshake(handshake) else {
            return Ok(false);
        };
        let store = self.store.lock().map_err(|_| CoreError::Storage {
            msg: "mutex poisoned".into(),
        })?;
        match store.get(&accepted_handshake_key(peer)) {
            Ok(bytes) => Ok(bytes.as_slice() == handshake_identity(&parsed)),
            Err(StorageError::NotFound | StorageError::Decryption) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Whether `wire`, a message from `peer` that did not decrypt under this
    /// device's own session under `session_id`, authenticates as `peer`'s
    /// first message under a handshake recorded beside that session. X3DH
    /// runs from the recorded handshake against the prekeys held now,
    /// checked again by the same rules as for a promotion, with the one-time
    /// prekey only read, and the message is decrypted on that result in
    /// memory (`Messenger::first_message_authenticates`). Nothing is written
    /// or consumed: the session, the recorded handshake and the prekey
    /// record stay exactly as they are.
    ///
    /// `false` when no handshake is recorded beside the session, when it
    /// names another peer, and when it can no longer be answered (its
    /// one-time prekey was consumed, or its signed prekey is neither the
    /// current nor the previous one): without that key no message can
    /// authenticate under it here.
    pub(crate) fn beside_authenticates(
        &self,
        session_id: u64,
        peer: &[u8; 32],
        wire: &[u8],
    ) -> Result<bool, CoreError> {
        let identity = self.require_identity()?;
        let (store, messenger) = self.lock()?;
        let map = |e| CoreError::messaging(session_id, e);
        let Some(provisional) = messenger
            .provisional_handshake(&store, session_id)
            .map_err(map)?
        else {
            return Ok(false);
        };
        if provisional.peer_identity_pk != *peer {
            return Ok(false);
        }
        let handshake = unpack_initiator_handshake(&provisional.handshake)?;
        if handshake.identity_pk.to_bytes() != *peer {
            return Ok(false);
        }
        let record = unpack_prekeys(&Zeroizing::new(store.get(PREKEYS_KEY)?))?;
        let Ok(which) = check_answerable(&record, &handshake) else {
            return Ok(false);
        };
        let our_identity_pk = PublicKey::from(&identity.dh_key);
        let session = responder_session(
            &identity,
            our_identity_pk,
            record.signed_prekey(which)?,
            record.opk.as_ref().map(|(_, sk)| sk),
            &handshake,
        )?;
        messenger
            .first_message_authenticates(our_identity_pk.to_bytes(), session, wire)
            .map_err(map)
    }

    /// A `HANDSHAKE_REFUSAL_V1` from this device for `handshake`,
    /// which `initiator_dh_pk` sent and this device could not answer.
    /// `None` if `initiator_dh_pk` is of low order: no tag can be made for
    /// it, and no refusal is sent.
    pub(crate) fn make_handshake_refusal(
        &self,
        initiator_dh_pk: [u8; 32],
        handshake: &[u8],
        reason: RefusalReason,
    ) -> Result<Option<Vec<u8>>, CoreError> {
        let identity = self.require_identity()?;
        let refuser_dh_pk = PublicKey::from(&identity.dh_key).to_bytes();
        let refusal = HandshakeRefusal {
            refuser_dh_pk,
            initiator_dh_pk,
            handshake_hash: handshake_hash(handshake),
            reason,
        };
        let fields = refusal.fields();
        let tag = core_crypto::refusal_mac::refusal_tag(
            &identity.dh_key,
            &initiator_dh_pk,
            &refuser_dh_pk,
            &initiator_dh_pk,
            &fields,
        );
        Ok(tag.map(|tag| [&fields[..], &tag[..]].concat()))
    }

    /// The refusal `bytes` if it is a refusal by `refuser_dh_pk` of a
    /// handshake from this device whose tag checks; see
    /// [`HandshakeRefusal::open`].
    pub(crate) fn open_handshake_refusal(
        &self,
        bytes: &[u8],
        refuser_dh_pk: &[u8; 32],
    ) -> Result<Option<HandshakeRefusal>, CoreError> {
        let identity = self.require_identity()?;
        Ok(HandshakeRefusal::open(bytes, &identity.dh_key, refuser_dh_pk))
    }

    /// Writes the X25519 of this device's identity secret with `public` into
    /// `out`, a buffer the caller owns and wipes (the relay client's), and
    /// returns `true`. `false`, with `out` untouched, if the output is all
    /// zeros (`public` is of low order): anyone could compute that value.
    /// For the mailbox authentication of a `RELAY_PROTOCOL_V2` relay, where
    /// `public` is the relay's auth key (docs/NET-MESSAGING.md, section 3);
    /// the relay crate separates that derivation from every other use of the
    /// identity key by its own HKDF salt and label. The identity secret never
    /// leaves this type. Not exported: this impl block is not
    /// `#[uniffi::export]`, and `tests::ack_probe` keeps it so.
    pub(crate) fn identity_dh(&self, public: &[u8; 32], out: &mut [u8; 32]) -> Result<bool, CoreError> {
        let identity = self.require_identity()?;
        // `SharedSecret` wipes itself on drop.
        let shared = identity.dh_key.diffie_hellman(&PublicKey::from(*public));
        if !shared.was_contributory() {
            return Ok(false);
        }
        out.copy_from_slice(shared.as_bytes());
        Ok(true)
    }

    fn our_identity_pk(&self) -> Result<[u8; 32], CoreError> {
        Ok(PublicKey::from(&self.require_identity()?.dh_key).to_bytes())
    }

    fn require_identity(&self) -> Result<Arc<Identity>, CoreError> {
        self.load_identity()?
            .ok_or_else(|| CoreError::InvalidKey { msg: "no identity saved — call save_identity first".into() })
    }
}

/// Test aids for the prekey maintenance of a round (tracker R-6), per
/// thread, each one-shot: a closure run after maintenance's read without a
/// transaction, before its transaction begins; a closure run inside the
/// maintenance transaction just before it writes; and a failure of the
/// publication note.
#[cfg(test)]
pub(crate) mod prekey_hooks {
    use std::cell::{Cell, RefCell};

    type Hook = Box<dyn FnOnce()>;

    thread_local! {
        static BEFORE_WRITE: RefCell<Option<Hook>> = RefCell::new(None);
        static AFTER_PLAIN_READ: RefCell<Option<Hook>> = RefCell::new(None);
        static FAIL_NOTE: Cell<bool> = const { Cell::new(false) };
    }

    /// Runs once, in maintenance that found something due, after its read
    /// without a transaction and before its transaction begins.
    pub(crate) fn set_after_plain_read(hook: impl FnOnce() + 'static) {
        AFTER_PLAIN_READ.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }

    pub(super) fn after_plain_read() {
        if let Some(hook) = AFTER_PLAIN_READ.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }

    pub(crate) fn set_before_maintenance_write(hook: impl FnOnce() + 'static) {
        BEFORE_WRITE.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }

    pub(super) fn before_maintenance_write() {
        if let Some(hook) = BEFORE_WRITE.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }

    pub(crate) fn fail_next_note() {
        FAIL_NOTE.with(|f| f.set(true));
    }

    pub(super) fn fail_note() -> bool {
        FAIL_NOTE.with(|f| f.replace(false))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
