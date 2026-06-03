//! Contact hashing for PSI (Private Set Intersection).
//! MUST match the TypeScript client exactly (tests/src/utils.ts):
//!   u64::from_le_bytes(sha256(phone)[0..8])

use sha2::{Digest, Sha256};

/// Hash a phone number to a u64 for PSI matching.
///
/// # Algorithm
/// SHA-256(utf8(phone))[0..8] interpreted as a little-endian u64.
/// Output width: **64 bits** (keep 8 bytes = 64 bits, discard 24 bytes = 192 bits).
/// Cross-language parity gate: must equal TS `hashPhoneWithTruncation`.
///
/// # Collision bound
/// Birthday bound at W=64: ~50% collision probability at ~2^32 ≈ 4.3 billion entries.
/// At 100M users: ~0.03% chance of any collision. Acceptable at current scale.
///
/// # Privacy model
/// Phone numbers have low entropy (~2^30–2^33), so SHA-256 of any width can be
/// reversed by exhaustive enumeration regardless of truncation.
/// Privacy relies entirely on MPC confidentiality, not hash secrecy:
/// the u64 is RescueCipher-encrypted before leaving the device, submitted as
/// ciphertext on-chain, and compared inside the Arcium MPC circuit as secret
/// shares (Cerberus protocol) — no single party observes a plaintext hash.
///
/// # Current status: privacy is conditional on M-3
/// `RescueCipher` in `rescue.rs` is currently a **stub** backed by ChaCha20Poly1305.
/// The stub is standard AEAD (a chain observer cannot recover the u64), but the
/// Arcium MPC circuit expects genuine Rescue arithmetic-friendly encryption.
/// The circuit will not operate correctly until the real Rescue cipher is wired (M-3).
/// M-3 is home-only work (requires arcium-client which pulls the full Solana/Anchor
/// stack, not suitable for Android .so until the circuit is deployed on devnet).
///
/// # Constraints — do NOT change truncation width or hash function without:
///   1. Updating `hashPhoneWithTruncation` in TS (breaks Rust==TS parity gate), AND
///   2. Recomputing CIRCUIT_HASH (SHA-256 of psi_intersect.arcis.ir changes), AND
///   3. Redeploying the Arcium circuit on devnet (requires toolchain + open network).
pub fn hash_contact(phone: &str) -> u64 {
    let digest = Sha256::digest(phone.as_bytes());
    let bytes: [u8; 8] = digest[0..8].try_into().expect("sha256 is 32 bytes");
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(hash_contact("+1234567890"), hash_contact("+1234567890"));
    }

    #[test]
    fn different_inputs_differ() {
        assert_ne!(hash_contact("+1234567890"), hash_contact("+9876543210"));
    }

    #[test]
    fn matches_canonical_vector() {
        // Canonical cross-language test vector — must match TS hashPhoneWithTruncation('+1234567890').
        // sha256("+1234567890")[0..8] as little-endian u64 = 5364562789390625858
        assert_eq!(hash_contact("+1234567890"), 5364562789390625858u64);
    }
}
