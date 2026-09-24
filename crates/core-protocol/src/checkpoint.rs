//! `SESSION_CHECKPOINT_V1`: a [`Session`] together with the identity binding
//! needed to check, on reload, that the record belongs to the session the
//! caller is asking for.
//!
//! Written by the live message path through `crate::messaging`. The record
//! is plaintext containing secret keys. Its confidentiality, integrity and
//! authenticity come only from the authenticated encrypted store it is kept
//! in; the checks below are structural and do not show that a record is
//! genuine or current.
//!
//! Encoding and decoding are crate-private: outside this crate a session
//! record is reachable only through [`crate::durable::DurableSession`].
//!
//! # Layout (all integers big-endian)
//!
//! | offset | size | field                                          |
//! |-------:|-----:|------------------------------------------------|
//! |      0 |    7 | magic `ARCSESS`                                |
//! |      7 |    1 | version, `1`                                   |
//! |      8 |    1 | role: `0` initiator, `1` responder             |
//! |      9 |    8 | generation                                     |
//! |     17 |   32 | our X25519 identity public key                 |
//! |     49 |   32 | peer X25519 identity public key                |
//! |     81 |   64 | associated data                                |
//! |    145 |    4 | ratchet record length                          |
//! |    149 |    … | `RATCHET_STATE_V1` record (core-crypto)        |
//!
//! The associated data must be exactly what X3DH produces for the stored role
//! and identities: initiator key then responder key
//! (`core_crypto::x3dh`, `x3dh_initiate` / `x3dh_respond`). A record whose AD
//! disagrees with its own role and identities is rejected, not corrected.
//!
//! The generation counts committed checkpoints of one session. It orders
//! records written by this code; it does not detect or prevent an older record
//! being put back in place of a newer one.

use core_crypto::ratchet::{CheckpointError, DoubleRatchet, RATCHET_CHECKPOINT_MAX_LEN};
use zeroize::Zeroizing;

use crate::Session;

const MAGIC: &[u8; 7] = b"ARCSESS";

/// Current `SESSION_CHECKPOINT_V1` format version.
pub const SESSION_CHECKPOINT_VERSION: u8 = 1;

const AD_LEN: usize = 64;
const HEADER_LEN: usize = 7 + 1 + 1 + 8 + 32 + 32 + AD_LEN + 4;

/// Largest valid `SESSION_CHECKPOINT_V1` record, in bytes.
pub const SESSION_CHECKPOINT_MAX_LEN: usize = HEADER_LEN + RATCHET_CHECKPOINT_MAX_LEN;

/// Which side of X3DH this device was. It fixes the order of the identity keys
/// in the associated data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    Initiator,
    Responder,
}

impl SessionRole {
    fn to_byte(self) -> u8 {
        match self {
            SessionRole::Initiator => 0,
            SessionRole::Responder => 1,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(SessionRole::Initiator),
            1 => Some(SessionRole::Responder),
            _ => None,
        }
    }

    /// The associated data X3DH derives for this role.
    fn expected_ad(self, our: &[u8; 32], peer: &[u8; 32]) -> [u8; AD_LEN] {
        let (first, second) = match self {
            SessionRole::Initiator => (our, peer),
            SessionRole::Responder => (peer, our),
        };
        let mut ad = [0u8; AD_LEN];
        ad[..32].copy_from_slice(first);
        ad[32..].copy_from_slice(second);
        ad
    }
}

/// The identities a caller expects a stored session to be bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionBinding {
    pub our_identity_pk: [u8; 32],
    pub peer_identity_pk: [u8; 32],
}

/// A session rebuilt from a record, with the metadata stored beside it.
pub(crate) struct RestoredSession {
    pub session: Session,
    pub role: SessionRole,
    pub generation: u64,
}

/// Why a session checkpoint could not be written or read. No variant carries
/// key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionCheckpointError {
    Truncated {
        actual: usize,
    },
    Oversized {
        actual: usize,
    },
    BadMagic,
    UnsupportedVersion(u8),
    UnknownRole(u8),
    /// The record is for a different local identity than expected.
    OurIdentityMismatch,
    /// The record is for a different peer than expected.
    PeerIdentityMismatch,
    /// The AD does not match the role and identities it is stored with.
    AdMismatch,
    LengthMismatch {
        expected: usize,
        actual: usize,
    },
    Ratchet(CheckpointError),
}

impl std::fmt::Display for SessionCheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use SessionCheckpointError::*;
        match self {
            Truncated { actual } => {
                write!(
                    f,
                    "session checkpoint is {actual} bytes; at least {HEADER_LEN} required"
                )
            }
            Oversized { actual } => write!(
                f,
                "session checkpoint is {actual} bytes; limit is {SESSION_CHECKPOINT_MAX_LEN}"
            ),
            BadMagic => write!(f, "not a session checkpoint"),
            UnsupportedVersion(v) => write!(f, "unsupported session checkpoint version {v}"),
            UnknownRole(r) => write!(f, "unknown session role {r}"),
            OurIdentityMismatch => {
                write!(f, "session checkpoint belongs to another local identity")
            }
            PeerIdentityMismatch => write!(f, "session checkpoint belongs to another peer"),
            AdMismatch => {
                write!(
                    f,
                    "session associated data does not match its role and identities"
                )
            }
            LengthMismatch { expected, actual } => write!(
                f,
                "session checkpoint length {actual} does not match {expected} implied by its header"
            ),
            Ratchet(e) => write!(f, "invalid ratchet state: {e}"),
        }
    }
}

impl std::error::Error for SessionCheckpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SessionCheckpointError::Ratchet(e) => Some(e),
            _ => None,
        }
    }
}

/// The store key for the session with `peer_identity_pk`.
pub(crate) fn session_storage_key(peer_identity_pk: &[u8; 32]) -> String {
    let mut key = String::with_capacity(11 + 64);
    key.push_str("session:v1/");
    for b in peer_identity_pk {
        key.push_str(&format!("{b:02x}"));
    }
    key
}

/// Encodes `session` as a `SESSION_CHECKPOINT_V1` record.
///
/// Refuses a session whose AD is not the X3DH AD for `role`, `our_identity_pk`
/// and the session's own peer key, so an inconsistent session is never
/// written.
pub(crate) fn encode_session_checkpoint(
    session: &Session,
    role: SessionRole,
    our_identity_pk: &[u8; 32],
    generation: u64,
) -> Result<Zeroizing<Vec<u8>>, SessionCheckpointError> {
    encode_parts(
        &session.ratchet,
        &session.ad,
        &session.peer_identity_pk,
        role,
        our_identity_pk,
        generation,
    )
}

pub(crate) fn encode_parts(
    ratchet: &DoubleRatchet,
    ad: &[u8],
    peer_identity_pk: &[u8; 32],
    role: SessionRole,
    our_identity_pk: &[u8; 32],
    generation: u64,
) -> Result<Zeroizing<Vec<u8>>, SessionCheckpointError> {
    if ad != role.expected_ad(our_identity_pk, peer_identity_pk) {
        return Err(SessionCheckpointError::AdMismatch);
    }
    let inner = ratchet
        .to_checkpoint()
        .map_err(SessionCheckpointError::Ratchet)?;
    let mut out = Zeroizing::new(Vec::with_capacity(HEADER_LEN + inner.len()));
    out.extend_from_slice(MAGIC);
    out.push(SESSION_CHECKPOINT_VERSION);
    out.push(role.to_byte());
    out.extend_from_slice(&generation.to_be_bytes());
    out.extend_from_slice(our_identity_pk);
    out.extend_from_slice(peer_identity_pk);
    out.extend_from_slice(ad);
    // Bounded by RATCHET_CHECKPOINT_MAX_LEN, far below u32::MAX.
    out.extend_from_slice(&(inner.len() as u32).to_be_bytes());
    out.extend_from_slice(&inner);
    Ok(out)
}

/// Rebuilds a session from a `SESSION_CHECKPOINT_V1` record and checks that it
/// is bound to `expected`.
///
/// Rejects the whole record on any mismatch; nothing is repaired or replaced
/// with fresh state. Success does not show that the record is the newest one
/// that was written.
pub(crate) fn decode_session_checkpoint(
    record: &[u8],
    expected: &SessionBinding,
) -> Result<RestoredSession, SessionCheckpointError> {
    if record.len() > SESSION_CHECKPOINT_MAX_LEN {
        return Err(SessionCheckpointError::Oversized {
            actual: record.len(),
        });
    }
    if record.len() < HEADER_LEN {
        return Err(SessionCheckpointError::Truncated {
            actual: record.len(),
        });
    }
    if &record[0..7] != MAGIC {
        return Err(SessionCheckpointError::BadMagic);
    }
    if record[7] != SESSION_CHECKPOINT_VERSION {
        return Err(SessionCheckpointError::UnsupportedVersion(record[7]));
    }
    let role =
        SessionRole::from_byte(record[8]).ok_or(SessionCheckpointError::UnknownRole(record[8]))?;
    let generation = u64::from_be_bytes(record[9..17].try_into().expect("8 bytes"));
    let our: [u8; 32] = record[17..49].try_into().expect("32 bytes");
    let peer: [u8; 32] = record[49..81].try_into().expect("32 bytes");
    if our != expected.our_identity_pk {
        return Err(SessionCheckpointError::OurIdentityMismatch);
    }
    if peer != expected.peer_identity_pk {
        return Err(SessionCheckpointError::PeerIdentityMismatch);
    }
    let ad = &record[81..81 + AD_LEN];
    if ad != role.expected_ad(&our, &peer) {
        return Err(SessionCheckpointError::AdMismatch);
    }
    let inner_len = u32::from_be_bytes(record[145..149].try_into().expect("4 bytes")) as usize;
    let expected_len = HEADER_LEN + inner_len;
    if record.len() != expected_len {
        return Err(SessionCheckpointError::LengthMismatch {
            expected: expected_len,
            actual: record.len(),
        });
    }
    let ratchet = DoubleRatchet::from_checkpoint(&record[HEADER_LEN..])
        .map_err(SessionCheckpointError::Ratchet)?;
    Ok(RestoredSession {
        session: Session {
            ratchet,
            ad: ad.to_vec(),
            peer_identity_pk: peer,
        },
        role,
        generation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    pub(crate) fn identity() -> [u8; 32] {
        PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes()
    }

    fn initiator_session(our: &[u8; 32], peer: &[u8; 32]) -> Session {
        let spk = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        Session {
            ratchet: DoubleRatchet::init_alice([3u8; 32], spk),
            ad: SessionRole::Initiator.expected_ad(our, peer).to_vec(),
            peer_identity_pk: *peer,
        }
    }

    fn decode_err(record: &[u8], expected: &SessionBinding) -> SessionCheckpointError {
        match decode_session_checkpoint(record, expected) {
            Ok(_) => panic!("record was accepted"),
            Err(e) => e,
        }
    }

    #[test]
    fn round_trip_keeps_binding_role_generation_and_ratchet() {
        let (our, peer) = (identity(), identity());
        let s = initiator_session(&our, &peer);
        let rec = encode_session_checkpoint(&s, SessionRole::Initiator, &our, 42).unwrap();
        let binding = SessionBinding {
            our_identity_pk: our,
            peer_identity_pk: peer,
        };
        let r = decode_session_checkpoint(&rec, &binding).unwrap();
        assert_eq!(r.role, SessionRole::Initiator);
        assert_eq!(r.generation, 42);
        assert_eq!(r.session.ad, s.ad);
        assert_eq!(r.session.peer_identity_pk, peer);
        assert_eq!(
            *r.session.ratchet.to_checkpoint().unwrap(),
            *s.ratchet.to_checkpoint().unwrap()
        );
        let again = encode_session_checkpoint(&r.session, r.role, &our, 42).unwrap();
        assert_eq!(*again, *rec);
    }

    #[test]
    fn responder_ad_order_is_accepted_and_initiator_order_is_not() {
        let (our, peer) = (identity(), identity());
        let spk = StaticSecret::random_from_rng(OsRng);
        let s = Session {
            ratchet: DoubleRatchet::init_bob([4u8; 32], spk),
            ad: SessionRole::Responder.expected_ad(&our, &peer).to_vec(),
            peer_identity_pk: peer,
        };
        assert!(encode_session_checkpoint(&s, SessionRole::Responder, &our, 0).is_ok());
        assert_eq!(
            encode_session_checkpoint(&s, SessionRole::Initiator, &our, 0).unwrap_err(),
            SessionCheckpointError::AdMismatch
        );
    }

    #[test]
    fn encoding_refuses_an_ad_that_is_not_the_x3dh_ad() {
        let (our, peer) = (identity(), identity());
        let mut s = initiator_session(&our, &peer);
        s.ad = b"test-ad".to_vec();
        assert_eq!(
            encode_session_checkpoint(&s, SessionRole::Initiator, &our, 0).unwrap_err(),
            SessionCheckpointError::AdMismatch
        );
        let s = initiator_session(&our, &peer);
        assert_eq!(
            encode_session_checkpoint(&s, SessionRole::Initiator, &identity(), 0).unwrap_err(),
            SessionCheckpointError::AdMismatch,
            "AD built for another local identity"
        );
    }

    #[test]
    fn wrong_identities_and_tampered_binding_are_rejected() {
        let (our, peer) = (identity(), identity());
        let s = initiator_session(&our, &peer);
        let rec = encode_session_checkpoint(&s, SessionRole::Initiator, &our, 1).unwrap();
        let good = SessionBinding {
            our_identity_pk: our,
            peer_identity_pk: peer,
        };

        let other_us = SessionBinding {
            our_identity_pk: identity(),
            ..good
        };
        assert_eq!(
            decode_err(&rec, &other_us),
            SessionCheckpointError::OurIdentityMismatch
        );
        let other_peer = SessionBinding {
            peer_identity_pk: identity(),
            ..good
        };
        assert_eq!(
            decode_err(&rec, &other_peer),
            SessionCheckpointError::PeerIdentityMismatch
        );

        let mut flipped_role = rec.to_vec();
        flipped_role[8] = 1;
        assert_eq!(
            decode_err(&flipped_role, &good),
            SessionCheckpointError::AdMismatch
        );
        let mut bad_ad = rec.to_vec();
        bad_ad[81] ^= 1;
        assert_eq!(
            decode_err(&bad_ad, &good),
            SessionCheckpointError::AdMismatch
        );
    }

    #[test]
    fn malformed_envelopes_are_rejected() {
        let (our, peer) = (identity(), identity());
        let s = initiator_session(&our, &peer);
        let rec = encode_session_checkpoint(&s, SessionRole::Initiator, &our, 1).unwrap();
        let good = SessionBinding {
            our_identity_pk: our,
            peer_identity_pk: peer,
        };

        for len in 0..rec.len() {
            assert!(
                decode_session_checkpoint(&rec[..len], &good).is_err(),
                "prefix {len}"
            );
        }
        let mut longer = rec.to_vec();
        longer.push(0);
        assert!(matches!(
            decode_err(&longer, &good),
            SessionCheckpointError::LengthMismatch { .. }
        ));
        assert!(matches!(
            decode_err(&vec![0u8; SESSION_CHECKPOINT_MAX_LEN + 1], &good),
            SessionCheckpointError::Oversized { .. }
        ));

        let mut r = rec.to_vec();
        r[0] = b'X';
        assert_eq!(decode_err(&r, &good), SessionCheckpointError::BadMagic);
        let mut r = rec.to_vec();
        r[7] = 2;
        assert_eq!(
            decode_err(&r, &good),
            SessionCheckpointError::UnsupportedVersion(2)
        );
        let mut r = rec.to_vec();
        r[8] = 2;
        assert_eq!(
            decode_err(&r, &good),
            SessionCheckpointError::UnknownRole(2)
        );
        let mut r = rec.to_vec();
        r[HEADER_LEN] = 9; // inner ratchet version
        assert_eq!(
            decode_err(&r, &good),
            SessionCheckpointError::Ratchet(CheckpointError::UnsupportedVersion(9))
        );
    }

    #[test]
    fn storage_key_is_per_peer() {
        let k = session_storage_key(&[0xab; 32]);
        assert_eq!(k.len(), 11 + 64);
        assert!(k.starts_with("session:v1/abab"));
        assert_ne!(k, session_storage_key(&[0xac; 32]));
    }
}
