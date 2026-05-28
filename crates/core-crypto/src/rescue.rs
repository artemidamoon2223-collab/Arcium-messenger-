// STUB IMPLEMENTATION - replace internal cipher with real Rescue cipher
// from arcium-client crate when integrating with v1.0 arcium-psi.
// API matches the expected production interface.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};

#[derive(Debug)]
pub struct RescueError;

impl std::fmt::Display for RescueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rescue decryption failed")
    }
}

impl std::error::Error for RescueError {}

pub struct RescueCipher {
    key: [u8; 32],
}

impl RescueCipher {
    pub fn from_shared_secret(secret: &[u8; 32]) -> Self {
        Self { key: *secret }
    }

    pub fn encrypt(&self, data: &[u8], nonce: &[u8; 16]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        // ChaCha20Poly1305 uses 12-byte nonce; take first 12 bytes of the 16-byte input.
        let nonce12: &[u8; 12] = nonce[..12].try_into().unwrap();
        cipher.encrypt(nonce12.into(), data).expect("encrypt is infallible for valid key")
    }

    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 16]) -> Result<Vec<u8>, RescueError> {
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let nonce12: &[u8; 12] = nonce[..12].try_into().unwrap();
        cipher.decrypt(nonce12.into(), ciphertext).map_err(|_| RescueError)
    }
}

/// Encrypt a SHA-256 contact hash for PSI submission.
pub fn psi_pack_contact(phone_hash: &[u8; 32], cipher: &RescueCipher, nonce: &[u8; 16]) -> Vec<u8> {
    cipher.encrypt(phone_hash, nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] { [42u8; 32] }
    fn test_nonce() -> [u8; 16] { [1u8; 16] }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let cipher = RescueCipher::from_shared_secret(&test_key());
        let data = b"contact phone hash placeholder";
        let ct = cipher.encrypt(data, &test_nonce());
        let pt = cipher.decrypt(&ct, &test_nonce()).unwrap();
        assert_eq!(pt, data);
    }

    #[test]
    fn different_nonces_produce_different_ciphertexts() {
        let cipher = RescueCipher::from_shared_secret(&test_key());
        let data = b"same contact data";
        let ct1 = cipher.encrypt(data, &[1u8; 16]);
        let ct2 = cipher.encrypt(data, &[2u8; 16]);
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let cipher = RescueCipher::from_shared_secret(&test_key());
        let ct = cipher.encrypt(b"secret contact", &test_nonce());
        let wrong = RescueCipher::from_shared_secret(&[0u8; 32]);
        assert!(wrong.decrypt(&ct, &test_nonce()).is_err());
    }

    #[test]
    fn psi_pack_produces_consistent_output() {
        let cipher = RescueCipher::from_shared_secret(&test_key());
        let hash = [7u8; 32];
        let nonce = test_nonce();
        // Same inputs → same ciphertext (deterministic nonce in this stub)
        assert_eq!(
            psi_pack_contact(&hash, &cipher, &nonce),
            psi_pack_contact(&hash, &cipher, &nonce),
        );
    }
}
