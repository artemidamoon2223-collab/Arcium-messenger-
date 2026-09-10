//! Signed-prekey identifiers for `ARCIUM_X3DH_FORMAT_V1`.
//!
//! An initiator echoes the identifier of the signed prekey it actually used back
//! to the responder, so the responder can tell "you are holding a bundle I have
//! since rotated away from" apart from "these bytes are forged". Without it a
//! stale bundle and a tampered one both end the same way: two sides derive
//! different root keys, both report success, and the failure only surfaces later
//! as an authentication error on the first message, with nothing to distinguish
//! the two causes.
//!
//! # This is NOT `local_session_handle`
//!
//! [`crate::session_handle::local_session_handle`] derives a purely local map key
//! and is **little-endian** by an in-crate convention that predates this module.
//! This one goes on the wire, where `ARCIUM_X3DH_FORMAT_V1` fixes every integer as
//! big-endian. The two must not be modelled on each other: copying the
//! little-endian conversion here would produce an identifier that this device
//! compares happily against itself and never matches on a peer, and no test that
//! only round-trips through one implementation would notice.
//!
//! The safe form is the one below — the first eight digest bytes, kept as bytes.
//! `Trunc8` is then literal, and the wire encoding cannot disagree with the
//! derivation because no integer conversion happens at all.
//!
//! # What this value is not
//!
//! - **Not a secret.** It is published inside every prekey bundle and derived
//!   from a public key.
//! - **Not an authentication boundary.** It selects which signed prekey the
//!   responder should check against; the binding that actually matters is that
//!   `dh1`/`dh3` only agree when both sides used the same signed prekey. A
//!   matching identifier over a substituted key still fails there.
//! - **Not collision-free.** Eight bytes leave a birthday bound near 2^32 signed
//!   prekeys, and a deliberate search for a colliding identifier costs about 2^64
//!   hashes. Neither matters for what this does: a collision would let a stale
//!   bundle be mistaken for a current one, which downgrades an explicit
//!   `StaleSignedPrekey` back into the silent root-key mismatch this identifier
//!   exists to replace — it grants nothing.

use sha2::{Digest, Sha256};

/// Domain separator, exactly 21 bytes. Bump the version suffix if the derivation
/// changes; every published bundle carrying an identifier derived with the old
/// string stops matching.
const DOMAIN: &[u8] = b"arcium/x3dh-spk-id/v1";

/// Width of a signed-prekey identifier, in bytes.
pub const SPK_ID_LEN: usize = 8;

/// Derives the identifier of the signed prekey whose X25519 public key is
/// `signed_prekey_pk`: `SHA-256(DOMAIN || signed_prekey_pk)[0..8]`.
///
/// The result is the first eight digest bytes in digest order, which is exactly
/// what goes on the wire. Callers that need a `u64` must convert with
/// [`u64::from_be_bytes`] — never `from_le_bytes`, which would silently disagree
/// with every other implementation of this format.
pub fn spk_id(signed_prekey_pk: &[u8; 32]) -> [u8; SPK_ID_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(signed_prekey_pk);
    let digest = hasher.finalize();
    digest[0..SPK_ID_LEN]
        .try_into()
        .expect("sha256 is 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// The domain string is part of the wire contract: a different length means a
    /// different derivation, so it is pinned rather than left to the literal.
    #[test]
    fn domain_is_exactly_21_bytes() {
        assert_eq!(DOMAIN.len(), 21, "frozen spec fixes the domain at 21 bytes");
        assert_eq!(DOMAIN, b"arcium/x3dh-spk-id/v1");
    }

    #[test]
    fn spk_id_is_eight_bytes_and_deterministic() {
        let pk = key(0x11);
        assert_eq!(spk_id(&pk).len(), SPK_ID_LEN);
        assert_eq!(spk_id(&pk), spk_id(&pk));
    }

    /// Known vector. Recomputed here from the primitive rather than pasted, so the
    /// test pins the *construction* — domain, order, truncation point — instead of
    /// re-asserting whatever the implementation happens to produce.
    #[test]
    fn spk_id_matches_the_frozen_construction() {
        let pk = key(0x2a);

        let mut expected_hasher = Sha256::new();
        expected_hasher.update(b"arcium/x3dh-spk-id/v1");
        expected_hasher.update(pk);
        let expected_digest = expected_hasher.finalize();

        assert_eq!(spk_id(&pk), expected_digest[0..8]);
    }

    /// A different signed prekey must produce a different identifier, or rotation
    /// becomes undetectable — which is the whole point of the field.
    #[test]
    fn a_different_signed_prekey_changes_the_id() {
        assert_ne!(spk_id(&key(1)), spk_id(&key(2)));

        // A one-byte difference is still a different key.
        let mut near = key(1);
        near[31] = 2;
        assert_ne!(spk_id(&key(1)), spk_id(&near));
    }

    /// Domain separation: the identifier must not equal the undomained truncation,
    /// or a hash computed for some other purpose could be mistaken for one of these.
    #[test]
    fn domain_separation_changes_the_result() {
        let pk = key(7);
        let undomained: [u8; 8] = Sha256::digest(pk)[0..8].try_into().unwrap();
        assert_ne!(spk_id(&pk), undomained);
    }

    /// The endianness trap this module exists to avoid.
    ///
    /// `session_handle` truncates the same way and then reads the bytes as a
    /// **little-endian** `u64`. If that conversion were ever copied here, the wire
    /// bytes would come out reversed. This pins both halves: the identifier equals
    /// the digest prefix in digest order, and a big-endian round trip preserves it
    /// while a little-endian one does not.
    #[test]
    fn wire_bytes_are_digest_order_and_survive_a_big_endian_round_trip() {
        let pk = key(0x5a);
        let id = spk_id(&pk);

        let digest = {
            let mut h = Sha256::new();
            h.update(DOMAIN);
            h.update(pk);
            h.finalize()
        };
        assert_eq!(id, digest[0..8], "id must be the digest prefix, unreversed");

        assert_eq!(u64::from_be_bytes(id).to_be_bytes(), id);

        // The little-endian reading differs whenever the prefix is not a
        // palindrome, which is what makes copying `session_handle` a real hazard.
        assert_ne!(
            u64::from_le_bytes(id),
            u64::from_be_bytes(id),
            "test vector must not be byte-order symmetric, or it proves nothing"
        );
    }
}
