use core_crypto::ratchet::{DoubleRatchet, RatchetError};
use core_crypto::spk_id::{spk_id, SPK_ID_LEN};
use core_crypto::x3dh::{
    signed_prekey_object_v1, x3dh_initiate, x3dh_respond, PrekeyBundle, X3dhError, CIPHER_SUITE,
    PROTOCOL_VERSION,
};
use core_protocol::checkpoint::SessionRole;
use core_protocol::durable::SideWrite;
use core_protocol::messaging::{Messenger, MessagingError, NewSession};
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
pub use messaging_api::{IncomingMessage, OutgoingMessage, ReceiveResult, RecoveryReport, SendResult};

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
    /// The handshake names a signed prekey that is no longer current. The peer's
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
    /// A client message id must be 1 to 64 bytes.
    #[error("client message id must be 1 to 64 bytes")]
    InvalidClientMessageId,
    /// The session has accepted a message from the peer, so the peer holds
    /// it too; it cannot be removed locally. Nothing changed.
    #[error("session {session_id} is established and cannot be removed")]
    SessionEstablished { session_id: u64 },
    /// The session has outgoing messages that are neither acknowledged nor
    /// abandoned (`abandon_outgoing`). Nothing changed.
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
// v2 is a strict cutover: `ARCIUM_X3DH_FORMAT_V1` changes the record's length and
// contents, and a v1 record cannot be reinterpreted as one. Moving the key rather
// than versioning inside the old one means a legacy record simply stops being
// found, so `export_prekey_bundle` reports "no prekeys" and the caller re-runs
// `establish_prekeys` — instead of a second parser that a downgrade could aim at.
const PREKEYS_KEY: &str = "prekeys/v2";

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
/// `PERSISTED_PREKEY_RECORD_V2`, exactly 138 bytes. Never transmitted.
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

/// Parsed `PERSISTED_PREKEY_RECORD_V2`.
struct PrekeyRecordV2 {
    signed_prekey_sk: StaticSecret,
    signature: Signature,
    /// The currently published one-time prekey, if any.
    opk: Option<(u64, StaticSecret)>,
}

impl PrekeyRecordV2 {
    /// This record's signed-prekey public key.
    fn signed_prekey_pk(&self) -> PublicKey {
        PublicKey::from(&self.signed_prekey_sk)
    }
}

fn pack_prekeys(record: &PrekeyRecordV2) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![0u8; PREKEY_RECORD_V2_LEN]);
    out[0] = RECORD_VERSION;
    out[1..33].copy_from_slice(&record.signed_prekey_sk.to_bytes());
    out[33..97].copy_from_slice(&record.signature.to_bytes());
    if let Some((id, sk)) = &record.opk {
        out[97] = FLAG_OTP;
        out[98..106].copy_from_slice(&id.to_be_bytes());
        out[106..138].copy_from_slice(&sk.to_bytes());
    }
    // When absent, bytes 98..138 stay zero from the initial fill.
    out
}

fn unpack_prekeys(bytes: &[u8]) -> Result<PrekeyRecordV2, CoreError> {
    let corrupt = |msg: String| CoreError::Storage { msg };
    if bytes.len() != PREKEY_RECORD_V2_LEN {
        return Err(corrupt(format!(
            "corrupt prekey record: {} bytes, expected {PREKEY_RECORD_V2_LEN}",
            bytes.len()
        )));
    }
    if bytes[0] != RECORD_VERSION {
        return Err(corrupt(format!(
            "unknown prekey record version {:#04x}",
            bytes[0]
        )));
    }
    let signed_sk_bytes: [u8; 32] = bytes[1..33].try_into().expect("checked length");
    let sig_bytes: [u8; 64] = bytes[33..97].try_into().expect("checked length");
    let flags = bytes[97];
    if flags & !FLAG_OTP != 0 {
        return Err(corrupt(format!(
            "corrupt prekey record: unknown flag bits {flags:#04x}"
        )));
    }
    let opk = if flags & FLAG_OTP != 0 {
        let id = u64::from_be_bytes(bytes[98..106].try_into().expect("checked length"));
        let sk_bytes: [u8; 32] = bytes[106..138].try_into().expect("checked length");
        Some((id, StaticSecret::from(sk_bytes)))
    } else {
        if bytes[98..138].iter().any(|b| *b != 0) {
            return Err(corrupt(
                "corrupt prekey record: one-time prekey absent but its bytes are not zero".into(),
            ));
        }
        None
    };
    Ok(PrekeyRecordV2 {
        signed_prekey_sk: StaticSecret::from(signed_sk_bytes),
        signature: Signature::from_bytes(&sig_bytes),
        opk,
    })
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

    Ok(InitiatorHandshakeV1 {
        identity_pk,
        ephemeral_pk,
        spk_id,
        opk_id,
    })
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
        let key: [u8; 32] = master_key.as_slice().try_into().map_err(|_| CoreError::InvalidKey {
            msg: "expected exactly 32 bytes".into(),
        })?;
        let store = EncryptedStore::open(&storage_path, key)?;
        Ok(Arc::new(Self {
            store: Mutex::new(store),
            messenger: Mutex::new(Messenger::new()),
        }))
    }

    pub fn save_identity(&self, identity: Arc<Identity>) -> Result<(), CoreError> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(64));
        bytes.extend_from_slice(identity.signing_key.as_bytes());
        bytes.extend_from_slice(&identity.dh_key.to_bytes());
        self.store
            .lock()
            .map_err(|_| CoreError::Storage { msg: "mutex poisoned".into() })?
            .put(IDENTITY_KEY, &bytes)?;
        Ok(())
    }

    pub fn load_identity(&self) -> Option<Arc<Identity>> {
        // A poisoned mutex must not panic across the FFI boundary; treat the
        // store as unavailable, consistent with save_identity's error path.
        let store = match self.store.lock() {
            Ok(guard) => guard,
            Err(_) => return None,
        };
        let bytes = match store.get(IDENTITY_KEY) {
            Ok(b) => Zeroizing::new(b),
            Err(_) => return None, // NotFound or wrong-key Decryption → None
        };
        if bytes.len() != 64 {
            return None;
        }
        let sk_bytes: [u8; 32] = bytes[..32].try_into().ok()?;
        let dh_bytes: [u8; 32] = bytes[32..].try_into().ok()?;
        Some(Arc::new(Identity {
            signing_key: SigningKey::from_bytes(&sk_bytes),
            dh_key: StaticSecret::from(dh_bytes),
        }))
    }

    /// Generates this device's signed prekey and one one-time prekey, signs the
    /// signed prekey over `SIGNED_PREKEY_OBJECT_V1`, and persists everything.
    ///
    /// Calling this again replaces both prekeys. Every bundle already handed out
    /// then names a signed prekey and a one-time prekey this device no longer
    /// holds, so handshakes built from those bundles are refused with
    /// `StaleSignedPrekey` / `OneTimePrekeyUnavailable` rather than silently
    /// deriving a key the peer cannot match.
    pub fn establish_prekeys(&self) -> Result<(), CoreError> {
        let identity = self.require_identity()?;
        let signed_prekey_sk = StaticSecret::random_from_rng(OsRng);
        let signed_prekey_pk = PublicKey::from(&signed_prekey_sk);
        let identity_dh_pk = PublicKey::from(&identity.dh_key);
        let signing_pk = identity.signing_key.verifying_key();

        let object = signed_prekey_object_v1(&identity_dh_pk, &signing_pk, &signed_prekey_pk);
        let signature = identity.signing_key.sign(&object);

        let record = PrekeyRecordV2 {
            signed_prekey_sk,
            signature,
            opk: Some(new_one_time_prekey()),
        };
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
    /// calls return identical bytes. Fails if `establish_prekeys` never ran.
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
        let alice_session = x3dh_initiate(&identity.dh_key, our_identity_pk, &bundle)
            .map_err(|X3dhError::BadSignature| CoreError::BadSignedPrekeySignature)?;

        let ratchet = DoubleRatchet::init_alice(
            alice_session.root_key,
            alice_session.their_signed_prekey_pk,
        );
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

    /// Establishes a session as the X3DH responder ("Bob") from the 84-byte
    /// `INITIATOR_HANDSHAKE_V1` the initiator produced.
    ///
    /// # Prekey state transition
    ///
    /// The handshake names which signed prekey and which one-time prekey it used.
    /// This device answers from its own record, never from what the handshake
    /// asserts, so the six outcomes are decided by comparing the two:
    ///
    /// | stored state | `used_otp` | named `opk_id` | outcome |
    /// |---|---|---|---|
    /// | any | any | any | `StaleSignedPrekey` if `spk_id` differs |
    /// | one-time prekey held | yes | matches | accept, consume it, publish a replacement |
    /// | one-time prekey held | yes | differs | `OneTimePrekeyUnavailable` |
    /// | one-time prekey held | no | — | `OneTimePrekeyRequired` |
    /// | none held | no | — | accept without `dh4` |
    /// | none held | yes | any | `OneTimePrekeyUnavailable` |
    ///
    /// A one-time prekey error never falls back to the weaker no-`dh4` path: that
    /// would let anyone who can edit bytes in flight choose the weaker handshake.
    ///
    /// Because a consumed identifier is replaced rather than remembered, replaying
    /// a handshake this device already accepted names an identifier that is no
    /// longer current and is refused. That is the whole of the replay property
    /// claimed here — it holds for every state reachable through
    /// `establish_prekeys` and this method, which always keep a one-time prekey
    /// published. It is not a general anti-replay mechanism, and the no-one-time-
    /// prekey branch above has none.
    ///
    /// # Atomicity
    ///
    /// The rotated prekey record, the new session and its handle are written in
    /// one store transaction, and the prekey record is replaced only if it is
    /// still byte-identical to the one validated here. A crash before that
    /// commit leaves the one-time prekey unconsumed and no session — the same
    /// handshake can be answered again; after it, both exist. Nothing is
    /// consumed without the session that uses it.
    ///
    /// If the session is refused because this peer already has one or the
    /// handle belongs to another peer, nothing from that transaction is written,
    /// and the one-time prekey is then consumed on its own: a prekey named by a
    /// handshake that reached this device never returns to circulation.
    pub fn establish_session_responder(
        &self,
        session_id: u64,
        initiator_handshake: Vec<u8>,
    ) -> Result<(), CoreError> {
        let identity = self.require_identity()?;
        let handshake = unpack_initiator_handshake(&initiator_handshake)?;
        let (mut store, mut messenger) = self.lock()?;

        let record_bytes = Zeroizing::new(store.get(PREKEYS_KEY)?);
        let mut record = unpack_prekeys(&record_bytes)?;
        if spk_id(record.signed_prekey_pk().as_bytes()) != handshake.spk_id {
            return Err(CoreError::StaleSignedPrekey);
        }
        // Every rejection below returns before anything is written.
        let taken = match (record.opk.take(), handshake.opk_id) {
            (Some((held_id, held_sk)), Some(named)) if held_id == named => {
                record.opk = Some(new_one_time_prekey());
                Some(held_sk)
            }
            (Some(_), Some(named)) => {
                return Err(CoreError::OneTimePrekeyUnavailable { opk_id: named })
            }
            (Some(_), None) => return Err(CoreError::OneTimePrekeyRequired),
            (None, Some(named)) => {
                return Err(CoreError::OneTimePrekeyUnavailable { opk_id: named })
            }
            (None, None) => None,
        };
        let rotated = taken.is_some().then(|| pack_prekeys(&record));

        let our_identity_pk = PublicKey::from(&identity.dh_key);
        let bob_session = x3dh_respond(
            &identity.dh_key,
            our_identity_pk,
            &record.signed_prekey_sk,
            taken.as_ref(),
            handshake.identity_pk,
            handshake.ephemeral_pk,
        );
        let ratchet = DoubleRatchet::init_bob(bob_session.root_key, record.signed_prekey_sk.clone());
        // Owner is the initiator identity this handshake was actually answered
        // for, not anything the caller asserted separately.
        let session = Session {
            ratchet,
            ad: bob_session.ad.clone(),
            peer_identity_pk: handshake.identity_pk.to_bytes(),
        };
        let extra = match &rotated {
            Some(new_record) => vec![SideWrite::replace(
                PREKEYS_KEY.into(),
                record_bytes.clone(),
                new_record.clone(),
            )
            .map_err(|_| CoreError::Storage {
                msg: "prekey record key is reserved".into(),
            })?],
            None => Vec::new(),
        };
        let created = messenger.create_session(
            &mut store,
            our_identity_pk.to_bytes(),
            NewSession {
                handle: session_id,
                session,
                role: SessionRole::Responder,
                initial_outbound: None,
                extra,
            },
        );
        match created {
            Ok(()) => Ok(()),
            // The prekey record changed since it was validated: another
            // receipt consumed the one-time prekey first.
            Err(MessagingError::ExtraConflict { .. }) => Err(CoreError::OneTimePrekeyUnavailable {
                opk_id: handshake.opk_id.unwrap_or_default(),
            }),
            Err(e @ (MessagingError::AlreadyExists { .. } | MessagingError::HandleCollision { .. })) => {
                if let Some(new_record) = rotated {
                    // Best effort: the refusal is reported whatever this does.
                    let _ = consume_prekey(&mut store, &record_bytes, &new_record);
                }
                Err(CoreError::messaging(session_id, e))
            }
            Err(e) => Err(CoreError::messaging(session_id, e)),
        }
    }
}

/// Replaces the prekey record with `rotated` if it is still `expected`.
fn consume_prekey(
    store: &mut EncryptedStore,
    expected: &[u8],
    rotated: &[u8],
) -> Result<(), StorageError> {
    let tx = store.transaction()?;
    if tx.get(PREKEYS_KEY)?.as_slice() == expected {
        tx.put(PREKEYS_KEY, rotated)?;
        tx.commit()?;
    }
    Ok(())
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

    fn our_identity_pk(&self) -> Result<[u8; 32], CoreError> {
        Ok(PublicKey::from(&self.require_identity()?.dh_key).to_bytes())
    }

    fn require_identity(&self) -> Result<Arc<Identity>, CoreError> {
        self.load_identity()
            .ok_or_else(|| CoreError::InvalidKey { msg: "no identity saved — call save_identity first".into() })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use core_crypto::ratchet::HEADER_SIZE;

    /// Test shorthands that keep the pre-S2-B2 tests below unchanged while
    /// running them on the durable path: `encrypt_message` is the committed
    /// wire bytes of a `send_message` with a fresh client message id,
    /// `decrypt_message` the plaintext of a
    /// newly accepted `receive_message`. Test-only; not part of the FFI.
    impl ArciumCore {
        fn encrypt_message(&self, session_id: u64, plaintext: Vec<u8>) -> Result<Vec<u8>, CoreError> {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(1);
            let client_id = NEXT.fetch_add(1, Ordering::Relaxed).to_be_bytes().to_vec();
            match self.send_message(session_id, client_id, plaintext)? {
                SendResult::Sent { message } => Ok(message.wire),
                other => panic!("expected a new message, got {other:?}"),
            }
        }

        fn decrypt_message(&self, session_id: u64, message: Vec<u8>) -> Result<Vec<u8>, CoreError> {
            match self.receive_message(session_id, message)? {
                ReceiveResult::Accepted { message } => Ok(message.plaintext),
                other => panic!("expected a new message, got {other:?}"),
            }
        }
    }
    use tempfile::tempdir;

    fn key32(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    #[test]
    fn identity_generates_keys() {
        let id = Identity::generate();
        assert_ne!(id.public_key_bytes(), vec![0u8; 32], "public key must not be all zeros");
    }

    #[test]
    fn identity_public_key_correct_size() {
        assert_eq!(Identity::generate().public_key_bytes().len(), 32);
    }

    #[test]
    fn identity_dh_public_key_correct_size_and_distinct_from_signing_key() {
        let id = Identity::generate();
        let dh_pk = id.dh_public_key_bytes();
        assert_eq!(dh_pk.len(), 32);
        assert_ne!(dh_pk, id.public_key_bytes(), "DH key and signing key must differ");
    }

    #[test]
    fn core_saves_and_loads_identity() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db").to_str().unwrap().to_string();

        let core = ArciumCore::new(path, key32(0)).unwrap();
        let id = Identity::generate();
        let pk = id.public_key_bytes();
        core.save_identity(id).unwrap();

        let loaded = core.load_identity().expect("identity must be present after save");
        assert_eq!(loaded.public_key_bytes(), pk);
    }

    #[test]
    fn core_with_wrong_key_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db").to_str().unwrap().to_string();

        // Save with key 0x00…
        let core = ArciumCore::new(path.clone(), key32(0)).unwrap();
        core.save_identity(Identity::generate()).unwrap();

        // Open same file with key 0x01… → Decryption fails → None
        let core2 = ArciumCore::new(path, key32(1)).unwrap();
        assert!(core2.load_identity().is_none());
    }

    #[test]
    fn core_new_rejects_short_master_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db").to_str().unwrap().to_string();
        let result = ArciumCore::new(path, vec![0u8; 16]);
        assert!(matches!(result, Err(CoreError::InvalidKey { .. })));
    }

    #[test]
    fn save_identity_returns_ok_on_success() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db").to_str().unwrap().to_string();
        let core = ArciumCore::new(path, key32(0)).unwrap();
        let result = core.save_identity(Identity::generate());
        assert!(result.is_ok(), "save_identity must return Ok on success");
    }

    #[test]
    fn save_identity_returns_err_on_poisoned_mutex() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db").to_str().unwrap().to_string();
        let core = Arc::new(ArciumCore::new(path, key32(0)).unwrap());
        // Poison the mutex by panicking while holding the lock in another thread.
        let core2 = Arc::clone(&core);
        let _ = std::thread::spawn(move || {
            let _guard = core2.store.lock().unwrap();
            panic!("poison");
        })
        .join();
        // The mutex is now poisoned; save_identity must return Err, not panic.
        let result = core.save_identity(Identity::generate());
        assert!(
            matches!(result, Err(CoreError::Storage { .. })),
            "poisoned mutex must surface as CoreError::Storage, got {:?}",
            result
        );
    }

    #[test]
    fn load_identity_returns_none_on_poisoned_mutex() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db").to_str().unwrap().to_string();
        let core = Arc::new(ArciumCore::new(path, key32(0)).unwrap());
        core.save_identity(Identity::generate()).unwrap();
        // Poison the mutex by panicking while holding the lock in another thread.
        let core2 = Arc::clone(&core);
        let _ = std::thread::spawn(move || {
            let _guard = core2.store.lock().unwrap();
            panic!("poison");
        })
        .join();
        // The mutex is now poisoned; load_identity must return None, not panic.
        assert!(
            core.load_identity().is_none(),
            "poisoned mutex must yield None, not a panic across FFI"
        );
    }

    // ── Messaging FFI surface ────────────────────────────────────────────────

    /// A structurally valid v1 handshake for a peer, with no one-time prekey
    /// named. Used where a test needs the parser to pass so a *later* stage is
    /// what fails; the identity is real, the ephemeral key is arbitrary.
    fn synthetic_handshake(identity_pk: &[u8]) -> Vec<u8> {
        let mut hs = vec![0u8; INITIATOR_HANDSHAKE_V1_LEN];
        hs[0] = 0x01;
        hs[1] = 0x01;
        hs[4..36].copy_from_slice(identity_pk);
        hs[36..68].copy_from_slice(&[9u8; 32]);
        hs
    }

    fn fresh_core(byte: u8) -> Arc<ArciumCore> {
        let dir = tempdir().unwrap();
        // Leak the tempdir so the DB file survives for the life of the test
        // (the harness's short-lived arcium-msgffi scratch clone is disposed
        // separately; this only needs to survive one test function).
        let path = dir.keep().join("db").to_str().unwrap().to_string();
        ArciumCore::new(path, key32(byte)).unwrap()
    }

    #[test]
    fn establish_prekeys_then_export_bundle_round_trips_stably() {
        let core = fresh_core(1);
        core.save_identity(Identity::generate()).unwrap();
        core.establish_prekeys().unwrap();

        let bundle1 = core.export_prekey_bundle().unwrap();
        let bundle2 = core.export_prekey_bundle().unwrap();
        assert_eq!(bundle1, bundle2, "export_prekey_bundle must be a pure read (D3), not regenerate");
        assert_eq!(
            bundle1.len(),
            PREKEY_BUNDLE_V1_LEN,
            "v1 bundles are always {PREKEY_BUNDLE_V1_LEN} bytes, with or without a one-time prekey"
        );
    }

    #[test]
    fn export_prekey_bundle_fails_before_establish_prekeys() {
        let core = fresh_core(2);
        core.save_identity(Identity::generate()).unwrap();
        assert!(core.export_prekey_bundle().is_err());
    }

    #[test]
    fn alice_to_bob_full_round_trip_recovers_exact_plaintext() {
        let session_id: u64 = 42;

        let bob = fresh_core(10);
        bob.save_identity(Identity::generate()).unwrap();
        bob.establish_prekeys().unwrap();
        let bob_bundle = bob.export_prekey_bundle().unwrap();

        let alice = fresh_core(20);
        alice.save_identity(Identity::generate()).unwrap();

        let alice_handshake_bytes = alice.establish_session_initiator(session_id, bob_bundle).unwrap();
        assert_eq!(alice_handshake_bytes.len(), INITIATOR_HANDSHAKE_V1_LEN);

        bob.establish_session_responder(session_id, alice_handshake_bytes.clone())
            .unwrap();

        let plaintext = b"hello arcium".to_vec();
        let message = alice.encrypt_message(session_id, plaintext.clone()).unwrap();

        // Ciphertext must not equal the plaintext — this is not a stub echo.
        assert_ne!(&message[HEADER_SIZE..], plaintext.as_slice());

        let recovered = bob.decrypt_message(session_id, message).unwrap();
        assert_eq!(recovered, plaintext, "Bob must recover exactly what Alice sent");
    }

    #[test]
    fn forged_message_fails_and_does_not_desync_the_session() {
        let session_id: u64 = 7;

        let bob = fresh_core(30);
        bob.save_identity(Identity::generate()).unwrap();
        bob.establish_prekeys().unwrap();
        let bob_bundle = bob.export_prekey_bundle().unwrap();

        let alice = fresh_core(40);
        alice.save_identity(Identity::generate()).unwrap();
        let handshake = alice.establish_session_initiator(session_id, bob_bundle).unwrap();
        bob.establish_session_responder(session_id, handshake.clone())
            .unwrap();

        let genuine = alice.encrypt_message(session_id, b"real message".to_vec()).unwrap();

        // Tamper one byte of the ciphertext (not the header) before Bob ever
        // sees a genuine message — this is Bob's very first decrypt, so it
        // also exercises the F-1 path at the "no dhr set yet" boundary.
        let mut forged = genuine.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0xFF;

        assert!(bob.decrypt_message(session_id, forged).is_err(), "forged ciphertext must fail authentication");

        // The genuine message, unmodified, must still decrypt correctly —
        // proof the failed forged attempt did not desync Bob's session.
        let recovered = bob.decrypt_message(session_id, genuine).unwrap();
        assert_eq!(recovered, b"real message");
    }

    #[test]
    fn multi_message_both_directions_ratchet_advances() {
        let session_id: u64 = 99;

        let bob = fresh_core(50);
        bob.save_identity(Identity::generate()).unwrap();
        bob.establish_prekeys().unwrap();
        let bob_bundle = bob.export_prekey_bundle().unwrap();

        let alice = fresh_core(60);
        alice.save_identity(Identity::generate()).unwrap();
        let handshake = alice.establish_session_initiator(session_id, bob_bundle).unwrap();
        bob.establish_session_responder(session_id, handshake.clone())
            .unwrap();

        // Alice must send first: Bob's sending chain key isn't derived until
        // his receiving DH ratchet step runs on the first inbound message.
        let m1 = alice.encrypt_message(session_id, b"one".to_vec()).unwrap();
        assert_eq!(bob.decrypt_message(session_id, m1).unwrap(), b"one");

        let m2 = alice.encrypt_message(session_id, b"two".to_vec()).unwrap();
        assert_eq!(bob.decrypt_message(session_id, m2).unwrap(), b"two");

        // Now Bob can reply — his cks was derived by the DH step above.
        let r1 = bob.encrypt_message(session_id, b"reply one".to_vec()).unwrap();
        assert_eq!(alice.decrypt_message(session_id, r1).unwrap(), b"reply one");

        let r2 = bob.encrypt_message(session_id, b"reply two".to_vec()).unwrap();
        assert_eq!(alice.decrypt_message(session_id, r2).unwrap(), b"reply two");

        let m3 = alice.encrypt_message(session_id, b"three".to_vec()).unwrap();
        assert_eq!(bob.decrypt_message(session_id, m3).unwrap(), b"three");
    }

    #[test]
    fn encrypt_and_decrypt_fail_with_no_session() {
        let core = fresh_core(70);
        core.save_identity(Identity::generate()).unwrap();
        assert!(matches!(
            core.encrypt_message(1, b"x".to_vec()),
            Err(CoreError::NoSession { session_id: 1 })
        ));
        assert!(matches!(
            core.decrypt_message(1, vec![0u8; HEADER_SIZE]),
            Err(CoreError::NoSession { session_id: 1 })
        ));
    }

    /// `session_id` is a purely local lookup handle, not part of the protocol.
    /// The two peers here deliberately pick *different* ids for the same
    /// cryptographic session — Alice 42, Bob 77 — and still exchange messages
    /// in both directions.
    ///
    /// The other round-trip tests all happen to use one id on both sides, so
    /// they cannot distinguish "the id is local" from "the id must match".
    /// This one can: if the id were bound into the handshake, the header, or
    /// the associated data, the mismatch would surface as an authentication
    /// failure rather than exact plaintext recovery.
    #[test]
    fn asymmetric_session_ids_still_round_trip_both_directions() {
        let alice_session_id: u64 = 42;
        let bob_session_id: u64 = 77;
        assert_ne!(alice_session_id, bob_session_id, "the point of this test is that they differ");

        let bob = fresh_core(80);
        bob.save_identity(Identity::generate()).unwrap();
        bob.establish_prekeys().unwrap();
        let bob_bundle = bob.export_prekey_bundle().unwrap();

        let alice = fresh_core(90);
        alice.save_identity(Identity::generate()).unwrap();

        let handshake = alice
            .establish_session_initiator(alice_session_id, bob_bundle)
            .unwrap();
        bob.establish_session_responder(bob_session_id, handshake.clone())
        .unwrap();

        // Alice must send first: Bob's sending chain key isn't derived until
        // his receiving DH ratchet step runs on the first inbound message.
        let outbound = b"from alice under id 42".to_vec();
        let message = alice
            .encrypt_message(alice_session_id, outbound.clone())
            .unwrap();
        assert_eq!(
            bob.decrypt_message(bob_session_id, message).unwrap(),
            outbound,
            "Bob must recover Alice's plaintext exactly while looking the session up under a different id",
        );

        let reply = b"from bob under id 77".to_vec();
        let reply_message = bob.encrypt_message(bob_session_id, reply.clone()).unwrap();
        assert_eq!(
            alice.decrypt_message(alice_session_id, reply_message).unwrap(),
            reply,
            "Alice must recover Bob's reply exactly under her own unrelated id",
        );

        // Each side's id is meaningless to the other: the peer's id resolves to
        // nothing locally, which is what "local handle" means in practice.
        assert!(matches!(
            alice.encrypt_message(bob_session_id, b"x".to_vec()),
            Err(CoreError::NoSession { session_id }) if session_id == bob_session_id
        ));
        assert!(matches!(
            bob.encrypt_message(alice_session_id, b"x".to_vec()),
            Err(CoreError::NoSession { session_id }) if session_id == alice_session_id
        ));
    }

    // ── local_session_handle ─────────────────────────────────────────────────

    #[test]
    fn local_session_handle_is_deterministic_and_key_dependent() {
        assert_eq!(
            local_session_handle(key32(3)).unwrap(),
            local_session_handle(key32(3)).unwrap()
        );
        assert_ne!(
            local_session_handle(key32(3)).unwrap(),
            local_session_handle(key32(4)).unwrap()
        );
    }

    #[test]
    fn local_session_handle_rejects_wrong_length() {
        for len in [0usize, 31, 33, 64] {
            assert!(
                matches!(
                    local_session_handle(vec![1u8; len]),
                    Err(CoreError::InvalidKey { .. })
                ),
                "a {len}-byte key must be rejected, not silently truncated or padded"
            );
        }
    }

    /// A handle derived for a real peer must actually address that peer's session
    /// end to end: establish under it, then encrypt/decrypt through it.
    #[test]
    fn derived_handle_addresses_a_real_session() {
        let bob = fresh_core(120);
        bob.save_identity(Identity::generate()).unwrap();
        bob.establish_prekeys().unwrap();
        let bob_bundle = bob.export_prekey_bundle().unwrap();
        // Bob's X25519 identity public key sits after the 4-byte v1 header.
        let bob_identity_pk = bob_bundle[4..36].to_vec();

        let alice = fresh_core(130);
        let alice_identity = Identity::generate();
        let alice_identity_dh_pk = alice_identity.dh_public_key_bytes();
        alice.save_identity(alice_identity).unwrap();

        // Each side derives a handle for the *other* peer; the two differ, which
        // is fine — handles are local and need not agree (see PR #75).
        let alice_handle = local_session_handle(bob_identity_pk).unwrap();
        let bob_handle = local_session_handle(alice_identity_dh_pk).unwrap();
        assert_ne!(alice_handle, bob_handle);

        let handshake = alice.establish_session_initiator(alice_handle, bob_bundle).unwrap();
        bob.establish_session_responder(bob_handle, handshake.clone())
        .unwrap();

        let plaintext = b"addressed by derived handle".to_vec();
        let message = alice.encrypt_message(alice_handle, plaintext.clone()).unwrap();
        assert_eq!(bob.decrypt_message(bob_handle, message).unwrap(), plaintext);
    }

    // ── Session ownership: no silent replacement ─────────────────────────────

    /// Builds a peer that is ready to be established against, returning its core
    /// and its exported prekey bundle.
    fn peer_with_prekeys(byte: u8) -> (Arc<ArciumCore>, Vec<u8>) {
        let core = fresh_core(byte);
        core.save_identity(Identity::generate()).unwrap();
        core.establish_prekeys().unwrap();
        let bundle = core.export_prekey_bundle().unwrap();
        (core, bundle)
    }

    /// Re-establishing the same peer under a live handle must be refused, and —
    /// the part that matters — the existing ratchet must survive intact. Before
    /// this guard the second call replaced the session outright, discarding
    /// message keys and desynchronising both devices without any error.
    #[test]
    fn duplicate_establishment_is_refused_and_the_live_ratchet_keeps_working() {
        let (bob, bob_bundle) = peer_with_prekeys(140);

        let alice = fresh_core(141);
        alice.save_identity(Identity::generate()).unwrap();
        let handle: u64 = 42;

        let handshake = alice
            .establish_session_initiator(handle, bob_bundle.clone())
            .unwrap();
        bob.establish_session_responder(handle, handshake.clone())
            .unwrap();

        // Move the ratchet forward so a reset would be observable.
        let first = b"first message, advances the ratchet".to_vec();
        let ct = alice.encrypt_message(handle, first.clone()).unwrap();
        assert_eq!(bob.decrypt_message(handle, ct).unwrap(), first);

        // Second establishment for the same peer under the same handle.
        let err = alice
            .establish_session_initiator(handle, bob_bundle)
            .expect_err("re-establishing a live session must fail");
        assert!(
            matches!(err, CoreError::SessionAlreadyExists { session_id } if session_id == handle),
            "expected SessionAlreadyExists, got {err:?}"
        );

        // The original session must still be the one in place and still usable.
        let second = b"sent after the rejected duplicate".to_vec();
        let ct2 = alice.encrypt_message(handle, second.clone()).unwrap();
        assert_eq!(
            bob.decrypt_message(handle, ct2).unwrap(),
            second,
            "the surviving session must still decrypt on the peer — a silent reset would break this"
        );
    }

    /// Two different peers deliberately given the same local id. Real SHA-256
    /// collisions are not searched for; supplying the id directly is how the
    /// insertion semantics are exercised.
    #[test]
    fn same_handle_for_a_different_peer_is_refused_and_the_first_peer_is_untouched() {
        let (bob, bob_bundle) = peer_with_prekeys(150);
        let (_carol, carol_bundle) = peer_with_prekeys(151);

        let alice = fresh_core(152);
        alice.save_identity(Identity::generate()).unwrap();
        let handle: u64 = 77;

        let handshake = alice.establish_session_initiator(handle, bob_bundle).unwrap();
        bob.establish_session_responder(handle, handshake.clone())
            .unwrap();

        let err = alice
            .establish_session_initiator(handle, carol_bundle)
            .expect_err("a different peer must not take an occupied handle");
        assert!(
            matches!(err, CoreError::SessionIdCollision { session_id } if session_id == handle),
            "expected SessionIdCollision, got {err:?}"
        );

        // Bob's session must be exactly the one still installed.
        let msg = b"bob still owns this handle".to_vec();
        let ct = alice.encrypt_message(handle, msg.clone()).unwrap();
        assert_eq!(bob.decrypt_message(handle, ct).unwrap(), msg);
    }

    /// A handshake that fails must leave no ownership behind: the id stays free,
    /// which `encrypt_message` reports as NoSession rather than as a session
    /// belonging to someone.
    #[test]
    fn failed_initiator_leaves_no_session() {
        let (_bob, mut bundle) = peer_with_prekeys(160);
        // Corrupt the signed-prekey signature (v1 places it at 100..164) so the
        // bundle is structurally valid and carries a real identity, but the
        // signed-prekey object fails to verify.
        bundle[100] ^= 0xFF;

        let alice = fresh_core(161);
        alice.save_identity(Identity::generate()).unwrap();
        let handle: u64 = 88;

        let err = alice
            .establish_session_initiator(handle, bundle)
            .expect_err("a bad signature must fail the handshake");
        assert!(
            matches!(err, CoreError::BadSignedPrekeySignature),
            "expected BadSignedPrekeySignature, got {err:?}"
        );

        assert!(
            matches!(
                alice.encrypt_message(handle, b"x".to_vec()),
                Err(CoreError::NoSession { session_id }) if session_id == handle
            ),
            "a failed handshake must not leave an owned session behind"
        );
    }

    /// Same invariant on the responder side: failing before insertion (here,
    /// because prekeys were never established) leaves the id unowned.
    #[test]
    fn failed_responder_leaves_no_session() {
        let (_alice_peer, alice_bundle) = peer_with_prekeys(170);
        let alice_identity_pk = alice_bundle[4..36].to_vec();

        // Bob has an identity but never called establish_prekeys, so the
        // responder path fails when it reads the missing prekey record.
        let bob = fresh_core(171);
        bob.save_identity(Identity::generate()).unwrap();
        let handle: u64 = 99;

        let err = bob
            .establish_session_responder(handle, synthetic_handshake(&alice_identity_pk))
            .expect_err("responder without prekeys must fail");
        assert!(
            matches!(err, CoreError::Storage { .. }),
            "expected Storage error from the missing prekey record, got {err:?}"
        );

        assert!(
            matches!(
                bob.encrypt_message(handle, b"x".to_vec()),
                Err(CoreError::NoSession { session_id }) if session_id == handle
            ),
            "a failed responder handshake must not leave an owned session behind"
        );
    }

    /// Encrypting or decrypting on an unused id must not create ownership as a
    /// side effect — a later genuine handshake on that id has to succeed.
    #[test]
    fn encrypt_or_decrypt_before_handshake_creates_no_ownership() {
        let (bob, bob_bundle) = peer_with_prekeys(180);
        let alice = fresh_core(181);
        alice.save_identity(Identity::generate()).unwrap();
        let handle: u64 = 123;

        assert!(matches!(
            alice.encrypt_message(handle, b"x".to_vec()),
            Err(CoreError::NoSession { session_id }) if session_id == handle
        ));
        assert!(matches!(
            alice.decrypt_message(handle, vec![0u8; HEADER_SIZE + 16]),
            Err(CoreError::NoSession { session_id }) if session_id == handle
        ));

        // The id must still be free, so a real handshake now works.
        let handshake = alice
            .establish_session_initiator(handle, bob_bundle)
            .expect("the id must not have been claimed by the failed calls");
        bob.establish_session_responder(handle, handshake.clone())
            .unwrap();

        let msg = b"works after the earlier failures".to_vec();
        let ct = alice.encrypt_message(handle, msg.clone()).unwrap();
        assert_eq!(bob.decrypt_message(handle, ct).unwrap(), msg);
    }

    /// Two threads racing to establish the same handle on one core: the check
    /// and the insertion happen under a single mutex, so exactly one wins and
    /// the other is refused rather than overwriting.
    #[test]
    fn concurrent_duplicate_establishment_admits_exactly_one() {
        use std::sync::mpsc;
        use std::thread;

        let (_bob, bob_bundle) = peer_with_prekeys(190);
        let alice = fresh_core(191);
        alice.save_identity(Identity::generate()).unwrap();
        let handle: u64 = 4242;

        let (tx, rx) = mpsc::channel();
        let mut handles = Vec::new();
        for _ in 0..2 {
            let core = Arc::clone(&alice);
            let bundle = bob_bundle.clone();
            let tx = tx.clone();
            handles.push(thread::spawn(move || {
                tx.send(core.establish_session_initiator(handle, bundle)).unwrap();
            }));
        }
        drop(tx);
        for h in handles {
            h.join().unwrap();
        }

        let results: Vec<_> = rx.iter().collect();
        assert_eq!(results.len(), 2);
        let successes = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(successes, 1, "exactly one establishment may win the race");
        assert!(
            results.iter().any(|r| matches!(
                r,
                Err(CoreError::SessionAlreadyExists { session_id }) if *session_id == handle
            )),
            "the loser must be refused as a duplicate, not silently overwrite: {results:?}"
        );
    }

    // ── ARCIUM_X3DH_FORMAT_V1 ────────────────────────────────────────────────

    /// Reads the persisted record straight out of the store, so a test can assert
    /// on durable state instead of inferring it from later behaviour.
    fn read_record(core: &ArciumCore) -> Vec<u8> {
        core.store.lock().unwrap().get(PREKEYS_KEY).unwrap()
    }

    fn current_opk_id(core: &ArciumCore) -> Option<u64> {
        unpack_prekeys(&read_record(core)).unwrap().opk.map(|(id, _)| id)
    }

    // ── Parsing ──────────────────────────────────────────────────────────────

    #[test]
    fn v1_lengths_are_exactly_as_frozen() {
        assert_eq!(PREKEY_BUNDLE_V1_LEN, 204);
        assert_eq!(INITIATOR_HANDSHAKE_V1_LEN, 84);
        assert_eq!(PREKEY_RECORD_V2_LEN, 138);
        assert_eq!(PREKEYS_KEY, "prekeys/v2");
        assert_eq!(IDENTITY_KEY, "identity/v1", "identity storage must not change");
    }

    /// Neighbouring lengths — including both legacy bundle sizes — must be
    /// refused. 161 and 193 are the strict-cutover cases: a pre-v1 bundle is not
    /// a v1 bundle, and accepting one would reopen everything v1 closes.
    #[test]
    fn bundle_of_any_other_length_is_rejected() {
        let (_bob, bundle) = peer_with_prekeys(200);
        let alice = fresh_core(201);
        alice.save_identity(Identity::generate()).unwrap();

        for len in [0usize, 32, 161, 193, 203, 205, 408] {
            let mut malformed = bundle.clone();
            malformed.resize(len, 0);
            let err = alice
                .establish_session_initiator(1, malformed)
                .expect_err("a wrong-length bundle must be refused");
            assert!(
                matches!(err, CoreError::InvalidPrekeyBundle { .. }),
                "expected InvalidPrekeyBundle for length {len}, got {err:?}"
            );
        }
    }

    #[test]
    fn handshake_of_any_other_length_is_rejected() {
        let (bob, _bundle) = peer_with_prekeys(202);
        for len in [0usize, 32, 64, 83, 85, 168] {
            let err = bob
                .establish_session_responder(1, vec![0u8; len])
                .expect_err("a wrong-length handshake must be refused");
            assert!(
                matches!(err, CoreError::InvalidHandshake { .. }),
                "expected InvalidHandshake for length {len}, got {err:?}"
            );
        }
    }

    #[test]
    fn wrong_protocol_version_or_suite_is_reported_as_unsupported() {
        let (bob, bundle) = peer_with_prekeys(203);
        let alice = fresh_core(204);
        alice.save_identity(Identity::generate()).unwrap();

        for (idx, label) in [(0usize, "version"), (1usize, "suite")] {
            let mut b = bundle.clone();
            b[idx] = 0x02;
            let err = alice.establish_session_initiator(1, b).expect_err(label);
            assert!(
                matches!(err, CoreError::UnsupportedProtocolVersion { .. }),
                "bundle {label}: expected UnsupportedProtocolVersion, got {err:?}"
            );

            let mut hs = vec![0u8; INITIATOR_HANDSHAKE_V1_LEN];
            hs[0] = PROTOCOL_VERSION;
            hs[1] = CIPHER_SUITE;
            hs[idx] = 0x02;
            let err = bob.establish_session_responder(1, hs).expect_err(label);
            assert!(
                matches!(err, CoreError::UnsupportedProtocolVersion { .. }),
                "handshake {label}: expected UnsupportedProtocolVersion, got {err:?}"
            );
        }
    }

    /// The reserved byte and the undefined flag bits are refused rather than
    /// ignored: a future version that uses them must not be silently downgraded
    /// into this one.
    #[test]
    fn reserved_byte_and_unknown_flag_bits_are_rejected() {
        let (bob, bundle) = peer_with_prekeys(205);
        let alice = fresh_core(206);
        alice.save_identity(Identity::generate()).unwrap();

        for (idx, value) in [(3usize, 0x01u8), (2usize, 0b1000_0001)] {
            let mut b = bundle.clone();
            b[idx] = value;
            assert!(
                matches!(
                    alice.establish_session_initiator(1, b),
                    Err(CoreError::InvalidPrekeyBundle { .. })
                ),
                "bundle byte {idx} = {value:#04x} must be refused"
            );

            let mut hs = vec![0u8; INITIATOR_HANDSHAKE_V1_LEN];
            hs[0] = PROTOCOL_VERSION;
            hs[1] = CIPHER_SUITE;
            hs[idx] = value;
            assert!(
                matches!(
                    bob.establish_session_responder(1, hs),
                    Err(CoreError::InvalidHandshake { .. })
                ),
                "handshake byte {idx} = {value:#04x} must be refused"
            );
        }
    }

    /// "No one-time prekey" has exactly one encoding. Leaving the tail free would
    /// carry a channel inside an otherwise authentic structure.
    #[test]
    fn absent_one_time_prekey_must_be_all_zero() {
        let (bob, bundle) = peer_with_prekeys(207);
        let alice = fresh_core(208);
        alice.save_identity(Identity::generate()).unwrap();

        let mut b = bundle.clone();
        b[2] = 0x00; // clear has_otp but leave the tail populated
        assert!(
            matches!(
                alice.establish_session_initiator(1, b),
                Err(CoreError::InvalidPrekeyBundle { .. })
            ),
            "bundle with has_otp=0 and a non-zero tail must be refused"
        );

        let mut hs = vec![0u8; INITIATOR_HANDSHAKE_V1_LEN];
        hs[0] = PROTOCOL_VERSION;
        hs[1] = CIPHER_SUITE;
        hs[76] = 0x01; // used_otp=0 but an id is present
        assert!(
            matches!(
                bob.establish_session_responder(1, hs),
                Err(CoreError::InvalidHandshake { .. })
            ),
            "handshake with used_otp=0 and a non-zero id must be refused"
        );
    }

    // ── Signed prekey ────────────────────────────────────────────────────────

    /// The F-2 closure at the FFI boundary: pairing one peer's Ed25519 signing
    /// key with another's X25519 identity no longer verifies.
    #[test]
    fn bundle_with_substituted_identity_key_is_rejected() {
        let (_bob, bob_bundle) = peer_with_prekeys(210);
        let (_carol, carol_bundle) = peer_with_prekeys(211);
        let alice = fresh_core(212);
        alice.save_identity(Identity::generate()).unwrap();

        // Bob's bundle carrying Carol's DH identity: structurally perfect, and
        // before v1 the signature would still have verified.
        let mut forged = bob_bundle.clone();
        forged[4..36].copy_from_slice(&carol_bundle[4..36]);

        let err = alice
            .establish_session_initiator(1, forged)
            .expect_err("a mismatched identity must not verify");
        assert!(
            matches!(err, CoreError::BadSignedPrekeySignature),
            "expected BadSignedPrekeySignature, got {err:?}"
        );
    }

    // ── One-time prekey state machine ────────────────────────────────────────

    /// The accepted path: the named prekey is consumed exactly once and a fresh
    /// one takes its place, so the record advances by one durable write.
    #[test]
    fn matching_one_time_prekey_is_consumed_and_replaced() {
        let (bob, bob_bundle) = peer_with_prekeys(220);
        let alice = fresh_core(221);
        alice.save_identity(Identity::generate()).unwrap();

        let published = current_opk_id(&bob).expect("establish_prekeys publishes one");
        assert_eq!(
            u64::from_be_bytes(bob_bundle[164..172].try_into().unwrap()),
            published,
            "the bundle must advertise the id actually held"
        );

        let handshake = alice.establish_session_initiator(1, bob_bundle).unwrap();
        bob.establish_session_responder(1, handshake).unwrap();

        let replacement = current_opk_id(&bob).expect("a replacement must be published");
        assert_ne!(replacement, published, "the consumed prekey must be replaced");

        // Round trip proves dh4 was actually included on both sides.
        let msg = b"through a one-time prekey".to_vec();
        let ct = alice.encrypt_message(1, msg.clone()).unwrap();
        assert_eq!(bob.decrypt_message(1, ct).unwrap(), msg);
    }

    /// Replay. The one property claimed: a handshake this device already accepted
    /// names an identifier that is no longer current, so it is refused — and the
    /// refusal happens before any state changes.
    #[test]
    fn replaying_an_accepted_handshake_is_rejected_and_changes_nothing() {
        let (bob, bob_bundle) = peer_with_prekeys(222);
        let alice = fresh_core(223);
        alice.save_identity(Identity::generate()).unwrap();

        let handshake = alice.establish_session_initiator(1, bob_bundle).unwrap();
        bob.establish_session_responder(1, handshake.clone()).unwrap();

        let before = read_record(&bob);
        let err = bob
            .establish_session_responder(2, handshake)
            .expect_err("a replayed handshake must be refused");
        assert!(
            matches!(err, CoreError::OneTimePrekeyUnavailable { .. }),
            "expected OneTimePrekeyUnavailable, got {err:?}"
        );
        assert_eq!(read_record(&bob), before, "a refused replay must not touch the record");

        assert!(
            matches!(
                bob.encrypt_message(2, b"x".to_vec()),
                Err(CoreError::NoSession { session_id: 2 })
            ),
            "a refused replay must leave no session"
        );
    }

    /// A wrong identifier must be refused *without* spending the prekey it failed
    /// to name — otherwise anyone could burn prekeys by guessing.
    #[test]
    fn wrong_one_time_prekey_id_does_not_consume_the_current_one() {
        let (bob, bob_bundle) = peer_with_prekeys(224);
        let alice = fresh_core(225);
        alice.save_identity(Identity::generate()).unwrap();

        let mut tampered = bob_bundle.clone();
        tampered[164..172].copy_from_slice(&0xDEAD_BEEF_u64.to_be_bytes());
        // Re-sign is impossible, but the id is outside the signature, so the
        // bundle still verifies — which is exactly why the responder checks it
        // against its own record.
        let handshake = alice.establish_session_initiator(1, tampered).unwrap();

        let before = read_record(&bob);
        let err = bob
            .establish_session_responder(1, handshake)
            .expect_err("an unknown id must be refused");
        assert!(
            matches!(err, CoreError::OneTimePrekeyUnavailable { opk_id } if opk_id == 0xDEAD_BEEF),
            "expected OneTimePrekeyUnavailable{{0xDEADBEEF}}, got {err:?}"
        );
        assert_eq!(read_record(&bob), before, "the held prekey must survive untouched");
    }

    /// Anti-downgrade. Stripping the one-time prekey from a bundle in flight
    /// leaves a signature that still verifies, so the responder — not the
    /// signature — is what must refuse the weaker handshake.
    #[test]
    fn stripping_the_one_time_prekey_is_refused_rather_than_downgraded() {
        let (bob, bob_bundle) = peer_with_prekeys(226);
        let alice = fresh_core(227);
        alice.save_identity(Identity::generate()).unwrap();

        let mut stripped = bob_bundle.clone();
        stripped[2] = 0x00;
        stripped[164..204].fill(0);

        // Alice accepts it: the signed object does not cover these bytes.
        let handshake = alice.establish_session_initiator(1, stripped).unwrap();
        assert_eq!(handshake[2] & FLAG_OTP, 0, "Alice built an SPK-only handshake");

        let before = read_record(&bob);
        let err = bob
            .establish_session_responder(1, handshake)
            .expect_err("Bob still publishes a one-time prekey, so this must be refused");
        assert!(
            matches!(err, CoreError::OneTimePrekeyRequired),
            "expected OneTimePrekeyRequired, got {err:?}"
        );
        assert_eq!(read_record(&bob), before);
    }

    /// A bundle from before a rotation names a signed prekey this device no
    /// longer holds, and is refused explicitly rather than deriving a key the
    /// peer cannot match.
    #[test]
    fn stale_signed_prekey_is_rejected() {
        let (bob, old_bundle) = peer_with_prekeys(228);
        let alice = fresh_core(229);
        alice.save_identity(Identity::generate()).unwrap();

        let handshake = alice.establish_session_initiator(1, old_bundle).unwrap();
        bob.establish_prekeys().unwrap(); // rotation

        let before = read_record(&bob);
        let err = bob
            .establish_session_responder(1, handshake)
            .expect_err("a stale signed prekey must be refused");
        assert!(
            matches!(err, CoreError::StaleSignedPrekey),
            "expected StaleSignedPrekey, got {err:?}"
        );
        assert_eq!(read_record(&bob), before);
    }

    /// The SPK-only branch. No normal writer produces a record without a one-time
    /// prekey — `establish_prekeys` and the consume path both publish one — so
    /// the record is constructed directly. Without this the branch would be
    /// carried but never executed.
    #[test]
    fn spk_only_branch_accepts_and_omits_dh4() {
        let (bob, bob_bundle) = peer_with_prekeys(230);
        let alice = fresh_core(231);
        alice.save_identity(Identity::generate()).unwrap();

        // Strip the one-time prekey from Bob's stored record.
        let mut record = unpack_prekeys(&read_record(&bob)).unwrap();
        record.opk = None;
        bob.store
            .lock()
            .unwrap()
            .put(PREKEYS_KEY, &pack_prekeys(&record))
            .unwrap();
        assert!(current_opk_id(&bob).is_none());

        // Alice must also hold an SPK-only bundle, or the two sides disagree
        // about dh4 — which is the mismatch the identifiers exist to surface.
        let mut spk_only = bob_bundle.clone();
        spk_only[2] = 0x00;
        spk_only[164..204].fill(0);

        let handshake = alice.establish_session_initiator(1, spk_only).unwrap();
        bob.establish_session_responder(1, handshake).unwrap();

        let msg = b"no one-time prekey here".to_vec();
        let ct = alice.encrypt_message(1, msg.clone()).unwrap();
        assert_eq!(
            bob.decrypt_message(1, ct).unwrap(),
            msg,
            "both sides must have omitted dh4 identically"
        );

        // And a handshake that names a one-time prekey Bob does not hold must be
        // refused as unavailable — never quietly accepted on the SPK-only path.
        // The bundle keeps Bob's real signed prekey (so spk_id matches and this
        // reaches the OPK check), but advertises a one-time prekey that exists
        // nowhere; the OPK fields sit outside the signature, so it still verifies.
        let mut phantom = bob_bundle.clone();
        phantom[2] = FLAG_OTP;
        phantom[164..172].copy_from_slice(&0x5EED_5EED_5EED_5EEDu64.to_be_bytes());
        phantom[172..204].copy_from_slice(&[0x42u8; 32]);
        // A second initiator: Alice already holds her one session with Bob,
        // and sessions are stored one per peer identity.
        let dave = fresh_core(232);
        dave.save_identity(Identity::generate()).unwrap();
        let named = dave.establish_session_initiator(2, phantom).unwrap();
        assert_eq!(named[2] & FLAG_OTP, FLAG_OTP, "Alice must have set used_otp");

        let before = read_record(&bob);
        let err = bob
            .establish_session_responder(3, named)
            .expect_err("no one-time prekey is held, so naming one must fail");
        assert!(
            matches!(err, CoreError::OneTimePrekeyUnavailable { opk_id } if opk_id == 0x5EED_5EED_5EED_5EED),
            "expected OneTimePrekeyUnavailable, got {err:?}"
        );
        assert_eq!(read_record(&bob), before, "the refusal must not touch the record");
        assert!(matches!(
            bob.encrypt_message(3, b"x".to_vec()),
            Err(CoreError::NoSession { session_id: 3 })
        ));
    }

    // ── Atomicity ────────────────────────────────────────────────────────────

    /// Two threads presenting the same valid handshake must not both consume the
    /// one-time prekey it names. The transition is read-validate-rotate-write
    /// under one continuous store guard, so the loser sees the replacement and is
    /// refused — leaving exactly one accepted session and one durable advance.
    #[test]
    fn concurrent_receipt_of_one_handshake_consumes_the_prekey_once() {
        use std::sync::mpsc;
        use std::thread;

        let (bob, bob_bundle) = peer_with_prekeys(240);
        let alice = fresh_core(241);
        alice.save_identity(Identity::generate()).unwrap();

        let published = current_opk_id(&bob).unwrap();
        let handshake = alice.establish_session_initiator(1, bob_bundle).unwrap();

        // Both threads block on the barrier and are released together, so they
        // enter establish_session_responder as close to simultaneously as the
        // scheduler allows. Without this the second thread would usually start
        // after the first had already finished and the test would only be
        // checking the sequential state machine.
        let gate = Arc::new(std::sync::Barrier::new(2));
        let (tx, rx) = mpsc::channel();
        let mut joins = Vec::new();
        for handle in [10u64, 11u64] {
            let core = Arc::clone(&bob);
            let hs = handshake.clone();
            let tx = tx.clone();
            let gate = Arc::clone(&gate);
            joins.push(thread::spawn(move || {
                gate.wait();
                tx.send(core.establish_session_responder(handle, hs)).unwrap();
            }));
        }
        drop(tx);
        for j in joins {
            j.join().unwrap();
        }

        let results: Vec<_> = rx.iter().collect();
        assert_eq!(results.len(), 2);
        assert_eq!(
            results.iter().filter(|r| r.is_ok()).count(),
            1,
            "exactly one receipt may consume the prekey: {results:?}"
        );
        assert!(
            results.iter().any(|r| matches!(
                r,
                Err(CoreError::OneTimePrekeyUnavailable { opk_id }) if *opk_id == published
            )),
            "the loser must be refused as unavailable, not silently accepted: {results:?}"
        );

        let after = current_opk_id(&bob).unwrap();
        assert_ne!(after, published, "the durable state must have advanced once");
    }

    /// Session insertion failing after the prekey was durably consumed must not
    /// put it back. A prekey handed to a handshake never returns to circulation,
    /// even when nothing was built from it (T1).
    #[test]
    fn a_consumed_prekey_is_not_restored_when_session_insertion_fails() {
        let (bob, first_bundle) = peer_with_prekeys(242);
        let alice = fresh_core(243);
        alice.save_identity(Identity::generate()).unwrap();

        // Occupy the handle with a real session first.
        let hs1 = alice.establish_session_initiator(1, first_bundle).unwrap();
        bob.establish_session_responder(7, hs1).unwrap();

        // A second, different initiator aims at the same handle.
        let second_bundle = bob.export_prekey_bundle().unwrap();
        let carol = fresh_core(244);
        carol.save_identity(Identity::generate()).unwrap();
        let hs2 = carol.establish_session_initiator(1, second_bundle).unwrap();

        let consumed = current_opk_id(&bob).unwrap();
        let err = bob
            .establish_session_responder(7, hs2)
            .expect_err("the handle is taken by a different peer");
        assert!(
            matches!(err, CoreError::SessionIdCollision { session_id: 7 }),
            "expected SessionIdCollision, got {err:?}"
        );

        let after = current_opk_id(&bob).unwrap();
        assert_ne!(
            after, consumed,
            "the prekey was already consumed and must stay consumed"
        );
    }

    mod durable;
    mod net_harness;
    mod network;
    mod network_crash;
    mod net_peer;
}
