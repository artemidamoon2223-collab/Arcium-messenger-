//! Local messaging session handles.
//!
//! A device needs some `u64` to key its own `SessionManager` entries by, because
//! that is the type `core-protocol` uses for `ContactId`. This module derives
//! that number from the peer's identity public key.
//!
//! # This is NOT `contact_hash`
//!
//! [`crate::contact_hash::hash_contact`] hashes a **phone number** and exists to
//! feed the Arcium PSI circuit. Its width and hash function are pinned by a
//! cross-language parity gate with the TypeScript client and by `CIRCUIT_HASH`.
//! The two values must never be used interchangeably:
//!
//! - reusing the PSI hash for messaging would tie local ratchet routing to the
//!   deployed circuit version, so any PSI-side change would become a messaging
//!   migration;
//! - it would also put a phone-derived number — reversible by enumeration, as
//!   `contact_hash` documents — in the local session table.
//!
//! The domain separator below guarantees the two derivations cannot collide by
//! construction even if they were ever fed the same bytes.

use sha2::{Digest, Sha256};

/// Domain separator. Bump the version suffix if the derivation ever changes;
/// every stored or in-flight handle derived with the old string becomes invalid.
const DOMAIN: &[u8] = b"arcium/local-session-handle/v1";

/// Derives this device's local lookup handle for the session with the peer whose
/// X25519 identity public key is `peer_identity_pk`.
///
/// `SHA-256(DOMAIN || peer_identity_pk)[0..8]` as a little-endian `u64`, matching
/// the endianness convention already used elsewhere in this crate.
///
/// # What this value is not
///
/// - **Not transmitted.** It appears in no prekey bundle, handshake, message
///   header, or associated data. PR #75 established by test that the two peers
///   may pick different handles for the same cryptographic session, so this
///   never needs to agree with what the peer chose.
/// - **Not a security boundary.** It authenticates nothing and grants nothing.
///   The 32-byte public key remains the identity anchor; this is only a map key.
/// - **Not collision-free.** Truncating to 64 bits leaves a birthday bound near
///   2^32 distinct peers. `SessionManager::new_session` is an UPSERT with no
///   guard, so a collision would silently rebind one peer's ratchet to another's.
///   Callers **must** keep the full public key alongside the handle and reject a
///   handle already bound to a different key rather than overwrite it.
pub fn local_session_handle(peer_identity_pk: &[u8; 32]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(peer_identity_pk);
    let digest = hasher.finalize();
    let bytes: [u8; 8] = digest[0..8].try_into().expect("sha256 is 32 bytes");
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn handle_is_deterministic() {
        assert_eq!(local_session_handle(&key(7)), local_session_handle(&key(7)));
    }

    #[test]
    fn different_keys_give_different_handles() {
        assert_ne!(local_session_handle(&key(1)), local_session_handle(&key(2)));
    }

    #[test]
    fn single_bit_flip_changes_the_handle() {
        let mut flipped = key(0);
        flipped[31] = 1;
        assert_ne!(local_session_handle(&key(0)), local_session_handle(&flipped));
    }

    /// The domain separator must actually be mixed in: a bare SHA-256 of the key
    /// must not produce the same handle. This is what keeps the messaging
    /// derivation from ever coinciding with an undomained hash of the same bytes.
    #[test]
    fn domain_separator_is_applied() {
        let pk = key(9);
        let undomained: [u8; 8] = Sha256::digest(pk)[0..8].try_into().unwrap();
        assert_ne!(local_session_handle(&pk), u64::from_le_bytes(undomained));
    }

    /// Guards the documented wire format of the derivation so an accidental
    /// change to the hash, the truncation width, or the endianness fails loudly
    /// instead of silently re-keying every session.
    #[test]
    fn known_answer_pins_the_derivation() {
        let expected = {
            let mut h = Sha256::new();
            h.update(b"arcium/local-session-handle/v1");
            h.update([0xABu8; 32]);
            let d = h.finalize();
            u64::from_le_bytes(d[0..8].try_into().unwrap())
        };
        assert_eq!(local_session_handle(&key(0xAB)), expected);
    }
}
