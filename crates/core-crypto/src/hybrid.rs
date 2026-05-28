// Post-quantum hybrid KEM: X25519 + ML-KEM-768 (FIPS 203).
// Shared secret = HKDF-SHA256(x25519_ss || ml_kem_ss) → 64 bytes.
// Intended for v1.1; ML-KEM is quantum-resistant, X25519 provides
// classical security.

use hkdf::Hkdf;
use ml_kem::{
    Ciphertext, Decapsulate, DecapsulationKey768, Encapsulate, EncapsulationKey768, Key,
    KeyExport, MlKem768, Seed,
};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug)]
pub struct HybridError;

impl std::fmt::Display for HybridError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "hybrid KEM error")
    }
}

impl std::error::Error for HybridError {}

/// Public key: X25519 public + ML-KEM-768 encapsulation key (1184 bytes).
pub struct HybridPublicKey {
    pub x25519: [u8; 32],
    pub ml_kem: Vec<u8>,
}

/// Secret key: X25519 secret + 64-byte ML-KEM-768 seed (derives DecapsulationKey).
pub struct HybridSecretKey {
    pub x25519: [u8; 32],
    pub ml_kem: Vec<u8>,
}

const X25519_LEN: usize = 32;

pub fn hybrid_keygen() -> (HybridPublicKey, HybridSecretKey) {
    // X25519 key pair
    let x25519_sk = StaticSecret::random_from_rng(OsRng);
    let x25519_pk = PublicKey::from(&x25519_sk);

    // ML-KEM: generate random 64-byte seed via rand_core 0.6 OsRng
    let mut seed_bytes = [0u8; 64];
    OsRng.fill_bytes(&mut seed_bytes);
    let seed: Seed = seed_bytes.as_ref().try_into().expect("64 bytes");
    let dk = DecapsulationKey768::from_seed(seed);
    let ek = dk.encapsulation_key();

    (
        HybridPublicKey {
            x25519: x25519_pk.to_bytes(),
            ml_kem: ek.to_bytes().as_slice().to_vec(),
        },
        HybridSecretKey {
            x25519: x25519_sk.to_bytes(),
            ml_kem: seed_bytes.to_vec(),
        },
    )
}

/// Returns `(ciphertext, shared_secret_64_bytes)`.
/// ciphertext layout: `[x25519_eph_pk (32)] || [ml_kem_ct (1088)]`
pub fn hybrid_encaps(pk: &HybridPublicKey) -> (Vec<u8>, [u8; 64]) {
    // X25519 ephemeral encapsulation
    let eph_sk = StaticSecret::random_from_rng(OsRng);
    let eph_pk = PublicKey::from(&eph_sk);
    let x25519_ss = eph_sk.diffie_hellman(&PublicKey::from(pk.x25519));

    // ML-KEM encapsulation (uses getrandom feature internally)
    let ek_key: Key<EncapsulationKey768> = pk
        .ml_kem
        .as_slice()
        .try_into()
        .expect("valid encapsulation key bytes");
    let ek = EncapsulationKey768::new(&ek_key).expect("valid key");
    let (ml_ct, ml_ss) = ek.encapsulate();

    // Combine: HKDF-SHA256(x25519_ss || ml_kem_ss) → 64 bytes
    let shared = combine_secrets(x25519_ss.as_bytes(), ml_ss.as_slice());

    let mut ct = Vec::with_capacity(X25519_LEN + ml_ct.len());
    ct.extend_from_slice(&eph_pk.to_bytes());
    ct.extend_from_slice(ml_ct.as_slice());

    (ct, shared)
}

pub fn hybrid_decaps(sk: &HybridSecretKey, ct: &[u8]) -> Result<[u8; 64], HybridError> {
    if ct.len() < X25519_LEN {
        return Err(HybridError);
    }

    // X25519 decapsulation
    let eph_pk_bytes: [u8; 32] = ct[..X25519_LEN].try_into().map_err(|_| HybridError)?;
    let x25519_ss = StaticSecret::from(sk.x25519).diffie_hellman(&PublicKey::from(eph_pk_bytes));

    // ML-KEM decapsulation
    let seed_bytes: [u8; 64] = sk.ml_kem.as_slice().try_into().map_err(|_| HybridError)?;
    let seed: Seed = seed_bytes.as_ref().try_into().map_err(|_| HybridError)?;
    let dk = DecapsulationKey768::from_seed(seed);
    let ml_ct: Ciphertext<MlKem768> = ct[X25519_LEN..]
        .try_into()
        .map_err(|_| HybridError)?;
    let ml_ss = dk.decapsulate(&ml_ct);

    Ok(combine_secrets(x25519_ss.as_bytes(), ml_ss.as_slice()))
}

fn combine_secrets(x25519_ss: &[u8], ml_kem_ss: &[u8]) -> [u8; 64] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(x25519_ss);
    ikm[32..].copy_from_slice(ml_kem_ss);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut out = [0u8; 64];
    hk.expand(b"HybridKEM/v1", &mut out).expect("hkdf expand");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_produces_valid_keys() {
        let (pk, sk) = hybrid_keygen();
        assert_eq!(pk.x25519.len(), 32);
        assert_eq!(sk.x25519.len(), 32);
        assert!(!pk.ml_kem.is_empty(), "ML-KEM EK must not be empty");
        assert_eq!(sk.ml_kem.len(), 64, "ML-KEM SK seed is 64 bytes");
    }

    #[test]
    fn encaps_decaps_produce_same_secret() {
        let (pk, sk) = hybrid_keygen();
        let (ct, shared_send) = hybrid_encaps(&pk);
        let shared_recv = hybrid_decaps(&sk, &ct).unwrap();
        assert_eq!(shared_send, shared_recv);
    }

    #[test]
    fn different_keys_produce_different_secrets() {
        let (pk1, _) = hybrid_keygen();
        let (pk2, sk2) = hybrid_keygen();
        let (ct, _) = hybrid_encaps(&pk1); // encapsulate to pk1
        // Decapsulate with sk2 (wrong key) → different or error
        let wrong = hybrid_decaps(&sk2, &ct).unwrap(); // won't error but output differs
        let (_, correct) = hybrid_encaps(&pk2);
        // wrong decaps of pk1 ct with sk2 produces different result than correct encaps to pk2
        assert_ne!(wrong, correct);
    }

    #[test]
    fn wrong_secret_key_fails_decaps() {
        let (pk, _) = hybrid_keygen();
        let (_, sk2) = hybrid_keygen();
        let (ct, shared_correct) = hybrid_encaps(&pk);
        // Decaps with wrong sk — won't return error (ML-KEM uses implicit rejection)
        // but the shared secret must be different from the correct one
        let shared_wrong = hybrid_decaps(&sk2, &ct).unwrap();
        assert_ne!(shared_correct, shared_wrong, "wrong key must yield different shared secret");
    }
}
