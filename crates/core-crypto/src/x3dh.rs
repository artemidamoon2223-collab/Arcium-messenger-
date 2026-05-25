//! X3DH initial key agreement.
//!
//! Each user has:
//!   - An X25519 identity keypair (`identity_sk` / `identity_pk`) used for DH.
//!   - An Ed25519 signing keypair used to sign published prekeys.
//!
//! Bob publishes a `PrekeyBundle` (identity_pk, signed_prekey, optional one-time prekey).
//! Alice fetches it, calls `x3dh_initiate`, gets a root key, then bootstraps the
//! Double Ratchet using `DoubleRatchet::init_alice(root_key, bob_signed_prekey_pk)`.
//!
//! Bob, upon receiving Alice's first message containing her ephemeral public key,
//! calls `x3dh_respond` and bootstraps with `DoubleRatchet::init_bob(root_key, bob_signed_prekey_sk)`.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Error)]
pub enum X3dhError {
    #[error("signed prekey signature verification failed")]
    BadSignature,
}

/// What Bob publishes to a directory (or in our case, shares out of band via QR / .onion address).
pub struct PrekeyBundle {
    pub identity_pk: PublicKey,
    pub signing_pk: VerifyingKey,
    pub signed_prekey_pk: PublicKey,
    pub signed_prekey_signature: Signature,
    pub one_time_prekey_pk: Option<PublicKey>,
}

pub struct AliceSession {
    pub root_key: [u8; 32],
    pub ephemeral_pk: PublicKey,
    /// Public key Bob will use as the initial `their_initial_dh` for his ratchet.
    pub their_signed_prekey_pk: PublicKey,
    /// Associated data = identity_pk(Alice) || identity_pk(Bob). Use this as AAD on every message.
    pub ad: Vec<u8>,
}

pub fn x3dh_initiate(
    our_identity_sk: &StaticSecret,
    our_identity_pk: PublicKey,
    bob: &PrekeyBundle,
) -> Result<AliceSession, X3dhError> {
    bob.signing_pk
        .verify(bob.signed_prekey_pk.as_bytes(), &bob.signed_prekey_signature)
        .map_err(|_| X3dhError::BadSignature)?;

    let ephemeral_sk = StaticSecret::random_from_rng(OsRng);
    let ephemeral_pk = PublicKey::from(&ephemeral_sk);

    let dh1 = our_identity_sk.diffie_hellman(&bob.signed_prekey_pk);
    let dh2 = ephemeral_sk.diffie_hellman(&bob.identity_pk);
    let dh3 = ephemeral_sk.diffie_hellman(&bob.signed_prekey_pk);
    let dh4 = bob
        .one_time_prekey_pk
        .as_ref()
        .map(|opk| ephemeral_sk.diffie_hellman(opk));

    let root_key = derive_root(dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes(), dh4.as_ref().map(|d| d.as_bytes()));

    let mut ad = Vec::with_capacity(64);
    ad.extend_from_slice(our_identity_pk.as_bytes());
    ad.extend_from_slice(bob.identity_pk.as_bytes());

    Ok(AliceSession {
        root_key,
        ephemeral_pk,
        their_signed_prekey_pk: bob.signed_prekey_pk,
        ad,
    })
}

pub struct BobSession {
    pub root_key: [u8; 32],
    pub their_ephemeral_pk: PublicKey,
    pub ad: Vec<u8>,
}

pub fn x3dh_respond(
    our_identity_sk: &StaticSecret,
    our_identity_pk: PublicKey,
    our_signed_prekey_sk: &StaticSecret,
    our_one_time_prekey_sk: Option<&StaticSecret>,
    their_identity_pk: PublicKey,
    their_ephemeral_pk: PublicKey,
) -> BobSession {
    let dh1 = our_signed_prekey_sk.diffie_hellman(&their_identity_pk);
    let dh2 = our_identity_sk.diffie_hellman(&their_ephemeral_pk);
    let dh3 = our_signed_prekey_sk.diffie_hellman(&their_ephemeral_pk);
    let dh4 = our_one_time_prekey_sk.map(|opk| opk.diffie_hellman(&their_ephemeral_pk));

    let root_key = derive_root(dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes(), dh4.as_ref().map(|d| d.as_bytes()));

    let mut ad = Vec::with_capacity(64);
    ad.extend_from_slice(their_identity_pk.as_bytes());
    ad.extend_from_slice(our_identity_pk.as_bytes());

    BobSession {
        root_key,
        their_ephemeral_pk,
        ad,
    }
}

fn derive_root(dh1: &[u8], dh2: &[u8], dh3: &[u8], dh4: Option<&[u8]>) -> [u8; 32] {
    // X3DH spec: prepend 32 bytes of 0xFF for X25519, then concatenate DH outputs.
    let mut ikm = Vec::with_capacity(32 * 5);
    ikm.extend_from_slice(&[0xFFu8; 32]);
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    if let Some(d) = dh4 {
        ikm.extend_from_slice(d);
    }
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &ikm);
    let mut rk = [0u8; 32];
    hk.expand(b"X3DH/v1", &mut rk).expect("hkdf expand");
    rk
}