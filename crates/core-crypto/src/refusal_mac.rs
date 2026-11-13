//! The tag of a handshake refusal: a MAC that only the two parties can make
//! and check (docs/NET-MESSAGING.md, section 6).
//!
//! ```text
//! shared = X25519(own identity secret, other identity public key)
//! key    = HKDF-SHA256(salt = none, ikm = shared,
//!                      info = "arcium/handshake-refusal-mac/v1"
//!                             || refuser_pk || initiator_pk)       32 bytes
//! tag    = HMAC-SHA256(key, fields)                                32 bytes
//! ```
//!
//! Either party computes the same `shared`, so the refuser makes the tag and
//! the initiator checks it with its own secret. Nobody else can do either.
//! And because the initiator could have made the same bytes itself, a valid
//! tag shown to a third party proves nothing about the refuser: unlike a
//! signature, a refusal is not evidence that the refuser knows the initiator.
//!
//! `info` names who refuses whom, so the key for "A refuses B" differs from
//! the key for "B refuses A": a tag cannot be reused with the roles swapped.
//!
//! The identity key also takes part in X3DH, which never computes an
//! identity-to-identity DH. Its HKDF has the same extract salt (no salt here
//! is 32 zero bytes, as there), but another input (0xFF x 32 followed by
//! three or four DH outputs, at least one of which an outsider cannot
//! compute) and another info (`X3DH/v1`), so the two derivations share no
//! key.
//!
//! **Key-compromise impersonation.** Whoever holds the initiator's identity
//! secret can make a refusal the initiator accepts as the refuser's: a MAC
//! cannot tell the two parties apart. With it, and the ability to read the
//! refuser's mailbox and write the initiator's, an attacker can make the
//! initiator give up a pending first contact (its texts become NotDelivered)
//! and start again. Holding that secret already lets one impersonate the
//! initiator to everyone, so this adds little; it is the price of a refusal
//! that proves nothing to third parties. Not reviewed by a cryptographer:
//! REVISIT AT SECURITY AUDIT.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// HKDF `info` prefix of the refusal key.
pub const REFUSAL_MAC_INFO: &[u8] = b"arcium/handshake-refusal-mac/v1";

/// Length of a refusal tag.
pub const REFUSAL_TAG_LEN: usize = 32;

/// The MAC key of refusals by `refuser_pk` of handshakes from
/// `initiator_pk`, computed by either party: `own_sk` is its identity
/// secret and `other_pk` the other party's identity public key. `None` if
/// the DH output is all zeros (a low-order public key), which would give a
/// key anyone can compute.
fn refusal_key(
    own_sk: &StaticSecret,
    other_pk: &[u8; 32],
    refuser_pk: &[u8; 32],
    initiator_pk: &[u8; 32],
) -> Option<Hmac<Sha256>> {
    let shared = own_sk.diffie_hellman(&PublicKey::from(*other_pk));
    if !shared.was_contributory() {
        return None;
    }
    let mut info = Vec::with_capacity(REFUSAL_MAC_INFO.len() + 64);
    info.extend_from_slice(REFUSAL_MAC_INFO);
    info.extend_from_slice(refuser_pk);
    info.extend_from_slice(initiator_pk);
    // The HKDF pseudorandom key is secret; `Hkdf::new` drops it unwiped, so it
    // is taken from `extract` and wiped here (see `hash_contract`).
    let (mut prk, hk) = Hkdf::<Sha256>::extract(None, shared.as_bytes());
    prk.as_mut_slice().zeroize();
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut key[..]).expect("hkdf expand");
    Some(<Hmac<Sha256> as KeyInit>::new_from_slice(&key[..]).expect("hmac"))
}

/// The tag over `fields` of a refusal by `refuser_pk` of a handshake from
/// `initiator_pk`. `None` for a low-order `other_pk`.
pub fn refusal_tag(
    own_sk: &StaticSecret,
    other_pk: &[u8; 32],
    refuser_pk: &[u8; 32],
    initiator_pk: &[u8; 32],
    fields: &[u8],
) -> Option<[u8; REFUSAL_TAG_LEN]> {
    let mut mac = refusal_key(own_sk, other_pk, refuser_pk, initiator_pk)?;
    mac.update(fields);
    // The tag is public: it goes on the wire. It is only borrowed from the
    // `CtOutput`, which wipes itself (`into_bytes` would copy it).
    let tag = mac.finalize();
    let mut out = [0u8; REFUSAL_TAG_LEN];
    out.copy_from_slice(tag.as_bytes());
    Some(out)
}

/// Whether `tag` is the tag over `fields` of a refusal by `refuser_pk` of a
/// handshake from `initiator_pk`. Compared in constant time. False for a
/// low-order `other_pk` and for a tag of the wrong length.
pub fn verify_refusal_tag(
    own_sk: &StaticSecret,
    other_pk: &[u8; 32],
    refuser_pk: &[u8; 32],
    initiator_pk: &[u8; 32],
    fields: &[u8],
    tag: &[u8],
) -> bool {
    let Some(mut mac) = refusal_key(own_sk, other_pk, refuser_pk, initiator_pk) else {
        return false;
    };
    mac.update(fields);
    mac.verify_slice(tag).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn party(byte: u8) -> (StaticSecret, [u8; 32]) {
        let sk = StaticSecret::from([byte; 32]);
        let pk = PublicKey::from(&sk).to_bytes();
        (sk, pk)
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Byte-for-byte pin. The value was computed independently with Python's
    /// `cryptography` (X25519, HKDF-SHA256, HMAC-SHA256) from the same inputs.
    #[test]
    fn golden() {
        let (bob_sk, bob_pk) = party(0x11);
        let (_, carol_pk) = party(0x22);
        let fields: Vec<u8> = (0u8..97).collect();
        let tag = refusal_tag(&bob_sk, &carol_pk, &bob_pk, &carol_pk, &fields).unwrap();
        assert_eq!(hex(&tag), GOLDEN_TAG);
    }

    const GOLDEN_TAG: &str = "52369559e09bb11e716fa36ed59ca4d34e3bbd28f9841aa51277993d2a72cf36";

    /// Both parties compute the same tag: the refuser makes it, the
    /// initiator checks it with its own secret.
    #[test]
    fn the_initiator_checks_what_the_refuser_made() {
        let (bob_sk, bob_pk) = party(0x11);
        let (carol_sk, carol_pk) = party(0x22);
        let fields = [7u8; 97];
        let tag = refusal_tag(&bob_sk, &carol_pk, &bob_pk, &carol_pk, &fields).unwrap();
        assert!(verify_refusal_tag(&carol_sk, &bob_pk, &bob_pk, &carol_pk, &fields, &tag));
        // Deniability: the initiator alone makes the very same tag.
        assert_eq!(refusal_tag(&carol_sk, &bob_pk, &bob_pk, &carol_pk, &fields), Some(tag));
    }

    #[test]
    fn a_tag_is_bound_to_the_two_parties_their_roles_and_the_fields() {
        let (bob_sk, bob_pk) = party(0x11);
        let (carol_sk, carol_pk) = party(0x22);
        let (dave_sk, dave_pk) = party(0x33);
        let fields = [7u8; 97];
        let tag = refusal_tag(&bob_sk, &carol_pk, &bob_pk, &carol_pk, &fields).unwrap();
        // Roles swapped: "Carol refuses Bob" has another key.
        assert!(!verify_refusal_tag(&carol_sk, &bob_pk, &carol_pk, &bob_pk, &fields, &tag));
        // A third party, with its own secret, cannot check it.
        assert!(!verify_refusal_tag(&dave_sk, &bob_pk, &bob_pk, &carol_pk, &fields, &tag));
        // Nor make one Carol accepts as Bob's.
        let fake = refusal_tag(&dave_sk, &carol_pk, &bob_pk, &carol_pk, &fields).unwrap();
        assert!(!verify_refusal_tag(&carol_sk, &bob_pk, &bob_pk, &carol_pk, &fields, &fake));
        // Another refuser or initiator named in the key.
        assert!(!verify_refusal_tag(&carol_sk, &bob_pk, &dave_pk, &carol_pk, &fields, &tag));
        assert!(!verify_refusal_tag(&carol_sk, &bob_pk, &bob_pk, &dave_pk, &fields, &tag));
        // Any changed field byte, a changed tag byte, a short or long tag.
        for i in 0..fields.len() {
            let mut f = fields;
            f[i] ^= 1;
            assert!(!verify_refusal_tag(&carol_sk, &bob_pk, &bob_pk, &carol_pk, &f, &tag), "field byte {i}");
        }
        for i in 0..tag.len() {
            let mut t = tag;
            t[i] ^= 0x80;
            assert!(!verify_refusal_tag(&carol_sk, &bob_pk, &bob_pk, &carol_pk, &fields, &t), "tag byte {i}");
        }
        assert!(!verify_refusal_tag(&carol_sk, &bob_pk, &bob_pk, &carol_pk, &fields, &tag[..31]));
        assert!(!verify_refusal_tag(&carol_sk, &bob_pk, &bob_pk, &carol_pk, &fields, &[&tag[..], &[0]].concat()));
    }

    /// A low-order public key gives an all-zero DH output, so a key anyone
    /// can compute: no tag is made and none is accepted.
    #[test]
    fn a_low_order_key_gives_no_tag() {
        let (bob_sk, bob_pk) = party(0x11);
        let fields = [7u8; 97];
        let mut one = [0u8; 32];
        one[0] = 1;
        for low in [[0u8; 32], one] {
            assert_eq!(refusal_tag(&bob_sk, &low, &bob_pk, &low, &fields), None);
            assert!(!verify_refusal_tag(&bob_sk, &low, &low, &bob_pk, &fields, &[0u8; 32]));
        }
    }
}
