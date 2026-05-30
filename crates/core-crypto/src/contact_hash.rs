//! Contact hashing for PSI (Private Set Intersection).
//! MUST match the TypeScript client exactly (tests/src/utils.ts):
//!   u64::from_le_bytes(sha256(phone)[0..8])

use sha2::{Digest, Sha256};

/// Hash a phone number to a u64 for PSI matching.
/// Canonical standard: SHA256, then first 8 bytes as little-endian u64.
/// This MUST produce the identical value to the TS `hashPhoneWithTruncation`.
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
