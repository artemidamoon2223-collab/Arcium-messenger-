//! `ARCIUM_X3DH_FORMAT_V1` on the wire: the prekey bundle, the initiator
//! handshake, the low-order check and `HANDSHAKE_REFUSAL_V1`.

use super::*;

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

fn bytes_to_pubkey(b: &[u8]) -> Result<PublicKey, CoreError> {
    let arr: [u8; 32] = b.try_into().map_err(|_| CoreError::Handshake {
        msg: "expected a 32-byte public key".into(),
    })?;
    Ok(PublicKey::from(arr))
}

/// Serializes a `PREKEY_BUNDLE_V1`.
pub(crate) fn pack_prekey_bundle(
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

pub(crate) fn unpack_prekey_bundle(bytes: &[u8]) -> Result<PrekeyBundle, CoreError> {
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
pub(crate) struct InitiatorHandshakeV1 {
    pub(crate) identity_pk: PublicKey,
    pub(crate) ephemeral_pk: PublicKey,
    pub(crate) spk_id: [u8; SPK_ID_LEN],
    /// The one-time prekey the initiator says it used, if any.
    pub(crate) opk_id: Option<u64>,
}

pub(crate) fn pack_initiator_handshake(
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

pub(crate) fn unpack_initiator_handshake(bytes: &[u8]) -> Result<InitiatorHandshakeV1, CoreError> {
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
    pub(crate) fn fields(&self) -> [u8; REFUSAL_FIELDS_LEN] {
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
    pub(crate) fn open(bytes: &[u8], own_sk: &StaticSecret, refuser_dh_pk: &[u8; 32]) -> Option<Self> {
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
