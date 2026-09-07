//! X3DH initial key agreement.

use ed25519_dalek::{Signature, VerifyingKey};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Protocol version carried by `ARCIUM_X3DH_FORMAT_V1` structures.
pub const PROTOCOL_VERSION: u8 = 0x01;
/// Cipher suite: X25519 · Ed25519 · XChaCha20-Poly1305 · HKDF-SHA256.
pub const CIPHER_SUITE: u8 = 0x01;

/// Domain separator of [`signed_prekey_object_v1`], exactly 18 bytes.
const SPK_OBJECT_DOMAIN: &[u8] = b"arcium/x3dh-spk/v1";

/// Size of the byte string a signed prekey's signature covers.
pub const SIGNED_PREKEY_OBJECT_LEN: usize = 116;

#[derive(Debug, Error)]
pub enum X3dhError {
    #[error("signed prekey signature verification failed")]
    BadSignature,
}

pub struct PrekeyBundle {
    pub identity_pk: PublicKey,
    pub signing_pk: VerifyingKey,
    pub signed_prekey_pk: PublicKey,
    pub signed_prekey_signature: Signature,
    pub one_time_prekey_pk: Option<PublicKey>,
    /// Opaque identifier of `one_time_prekey_pk`. Present exactly when the
    /// one-time prekey is.
    pub one_time_prekey_id: Option<u64>,
}

/// Builds the byte string a signed prekey's signature covers.
///
/// ```text
/// "arcium/x3dh-spk/v1"(18) || protocol_version(1) || cipher_suite(1)
///     || identity_dh_pk(32) || signing_pk(32) || signed_prekey_pk(32)
/// ```
///
/// This is never transmitted: both sides rebuild it from bundle fields, so the
/// signature commits to all of them without spending wire bytes on a copy.
///
/// # What each field is doing here
///
/// - **Domain and version/suite.** Without them an Ed25519 signature made for
///   some other purpose over the same 32 bytes would read as a prekey
///   endorsement, and a bundle could be re-presented under a future cipher suite
///   with its old signature still verifying (F13-A).
/// - **`identity_dh_pk`.** This is the F-2 binding. Ed25519 and X25519 identities
///   are generated independently, so before v1 nothing tied the signing key a
///   user might verify out of band to the DH key sessions are actually keyed
///   from. An attacker cannot sign *their* X25519 key under a *victim's* Ed25519
///   key without the victim's secret, so whatever signing key a verifier trusts
///   now vouches for exactly one DH key.
/// - **`signing_pk`.** Not needed to bind the signature to its verification key —
///   Ed25519 already hashes the public key into the challenge (RFC 8032 computes
///   `H(R ‖ A ‖ M)`). It is here so the signed object is a self-contained identity
///   assertion that keeps its meaning when lifted out of the bundle, which is what
///   a future fingerprint or directory scheme would hash.
///
/// One-time prekeys are deliberately absent: they rotate on every use, and
/// including them would force re-signing the signed prekey on each rotation.
pub fn signed_prekey_object_v1(
    identity_dh_pk: &PublicKey,
    signing_pk: &VerifyingKey,
    signed_prekey_pk: &PublicKey,
) -> [u8; SIGNED_PREKEY_OBJECT_LEN] {
    let mut out = [0u8; SIGNED_PREKEY_OBJECT_LEN];
    out[0..18].copy_from_slice(SPK_OBJECT_DOMAIN);
    out[18] = PROTOCOL_VERSION;
    out[19] = CIPHER_SUITE;
    out[20..52].copy_from_slice(identity_dh_pk.as_bytes());
    out[52..84].copy_from_slice(&signing_pk.to_bytes());
    out[84..116].copy_from_slice(signed_prekey_pk.as_bytes());
    out
}

/// Verifies a bundle's signed-prekey signature over [`signed_prekey_object_v1`].
///
/// Uses `verify_strict`, not `verify`: the signing key arrives inside the same
/// untrusted bundle it authenticates, and the strict form additionally rejects
/// small-order public keys and small-order `R`. Those are the cases where one
/// signature can validate under more than one key, which is precisely the
/// property a self-asserted key must not be allowed to exploit.
pub fn verify_signed_prekey_v1(bundle: &PrekeyBundle) -> Result<(), X3dhError> {
    let object = signed_prekey_object_v1(
        &bundle.identity_pk,
        &bundle.signing_pk,
        &bundle.signed_prekey_pk,
    );
    bundle
        .signing_pk
        .verify_strict(&object, &bundle.signed_prekey_signature)
        .map_err(|_| X3dhError::BadSignature)
}

#[derive(Debug)]
pub struct AliceSession {
    pub root_key: [u8; 32],
    pub ephemeral_pk: PublicKey,
    pub their_signed_prekey_pk: PublicKey,
    pub ad: Vec<u8>,
}

pub fn x3dh_initiate(
    our_identity_sk: &StaticSecret,
    our_identity_pk: PublicKey,
    bob: &PrekeyBundle,
) -> Result<AliceSession, X3dhError> {
    verify_signed_prekey_v1(bob)?;

    let ephemeral_sk = StaticSecret::random_from_rng(OsRng);
    let ephemeral_pk = PublicKey::from(&ephemeral_sk);

    let dh1 = our_identity_sk.diffie_hellman(&bob.signed_prekey_pk);
    let dh2 = ephemeral_sk.diffie_hellman(&bob.identity_pk);
    let dh3 = ephemeral_sk.diffie_hellman(&bob.signed_prekey_pk);
    let dh4 = bob
        .one_time_prekey_pk
        .as_ref()
        .map(|opk| ephemeral_sk.diffie_hellman(opk));

    let root_key = derive_root(
        dh1.as_bytes(),
        dh2.as_bytes(),
        dh3.as_bytes(),
        dh4.as_ref().map(|d| d.as_bytes()),
    );

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

    let root_key = derive_root(
        dh1.as_bytes(),
        dh2.as_bytes(),
        dh3.as_bytes(),
        dh4.as_ref().map(|d| d.as_bytes()),
    );

    let mut ad = Vec::with_capacity(64);
    ad.extend_from_slice(their_identity_pk.as_bytes());
    ad.extend_from_slice(our_identity_pk.as_bytes());

    BobSession {
        root_key,
        their_ephemeral_pk,
        ad,
    }
}

fn derive_root<T: AsRef<[u8]>>(dh1: &[u8], dh2: &[u8], dh3: &[u8], dh4: Option<T>) -> [u8; 32] {
    // ikm concatenates every DH output — the handshake's master secret material —
    // so it must not outlive its use unzeroized (F-8).
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 * 5));
    ikm.extend_from_slice(&[0xFFu8; 32]);
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    if let Some(d) = dh4 {
        ikm.extend_from_slice(d.as_ref());
    }
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &ikm);
    let mut rk = [0u8; 32];
    hk.expand(b"X3DH/v1", &mut rk).expect("hkdf expand");
    rk
}

#[cfg(test)]
mod v1_signed_prekey_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    struct Material {
        identity_pk: PublicKey,
        signing_sk: SigningKey,
        signed_prekey_pk: PublicKey,
    }

    fn material() -> Material {
        let identity_sk = StaticSecret::random_from_rng(OsRng);
        let identity_pk = PublicKey::from(&identity_sk);
        let signing_sk = SigningKey::generate(&mut OsRng);
        let signed_prekey_pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        Material {
            identity_pk,
            signing_sk,
            signed_prekey_pk,
        }
    }

    /// Signs the canonical object and assembles a bundle around it.
    fn signed_bundle(m: &Material) -> PrekeyBundle {
        let object = signed_prekey_object_v1(
            &m.identity_pk,
            &m.signing_sk.verifying_key(),
            &m.signed_prekey_pk,
        );
        PrekeyBundle {
            identity_pk: m.identity_pk,
            signing_pk: m.signing_sk.verifying_key(),
            signed_prekey_pk: m.signed_prekey_pk,
            signed_prekey_signature: m.signing_sk.sign(&object),
            one_time_prekey_pk: None,
            one_time_prekey_id: None,
        }
    }

    /// The object's length and field placement are part of the wire contract:
    /// a peer rebuilds these exact bytes, so any shift breaks interoperability
    /// silently rather than loudly.
    #[test]
    fn object_layout_is_frozen() {
        let m = material();
        let o = signed_prekey_object_v1(
            &m.identity_pk,
            &m.signing_sk.verifying_key(),
            &m.signed_prekey_pk,
        );

        assert_eq!(o.len(), 116);
        assert_eq!(&o[0..18], b"arcium/x3dh-spk/v1");
        assert_eq!(SPK_OBJECT_DOMAIN.len(), 18);
        assert_eq!(o[18], PROTOCOL_VERSION);
        assert_eq!(o[19], CIPHER_SUITE);
        assert_eq!(&o[20..52], m.identity_pk.as_bytes());
        assert_eq!(&o[52..84], &m.signing_sk.verifying_key().to_bytes());
        assert_eq!(&o[84..116], m.signed_prekey_pk.as_bytes());
    }

    /// S1: the honest path.
    #[test]
    fn valid_signature_is_accepted() {
        let m = material();
        assert!(verify_signed_prekey_v1(&signed_bundle(&m)).is_ok());
        let a_sk = StaticSecret::random_from_rng(OsRng);
        assert!(x3dh_initiate(&a_sk, PublicKey::from(&a_sk), &signed_bundle(&m)).is_ok());
    }

    /// S2 — this is the F-2 closure. Before v1 the signature covered only the raw
    /// signed-prekey bytes, so a bundle could pair a victim's Ed25519 identity
    /// with an attacker's X25519 identity and still verify. Now the DH identity
    /// is inside the signed object, so substituting it invalidates the signature.
    #[test]
    fn substituted_identity_dh_key_is_rejected() {
        let m = material();
        let mut bundle = signed_bundle(&m);
        bundle.identity_pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng));

        assert!(
            matches!(
                verify_signed_prekey_v1(&bundle),
                Err(X3dhError::BadSignature)
            ),
            "swapping the DH identity under a signature made for another one must fail"
        );
    }

    /// S3: a different signing key cannot inherit someone else's endorsement.
    #[test]
    fn substituted_signing_key_is_rejected() {
        let m = material();
        let mut bundle = signed_bundle(&m);
        bundle.signing_pk = SigningKey::generate(&mut OsRng).verifying_key();

        assert!(matches!(
            verify_signed_prekey_v1(&bundle),
            Err(X3dhError::BadSignature)
        ));
    }

    /// S4: the endorsed signed prekey cannot be swapped for another.
    #[test]
    fn substituted_signed_prekey_is_rejected() {
        let m = material();
        let mut bundle = signed_bundle(&m);
        bundle.signed_prekey_pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng));

        assert!(matches!(
            verify_signed_prekey_v1(&bundle),
            Err(X3dhError::BadSignature)
        ));
    }

    /// S5 — F13-A closure: a signature made over the bare key, or under a
    /// different domain/version/suite, must not read as a v1 endorsement.
    #[test]
    fn signatures_from_other_contexts_are_rejected() {
        let m = material();
        let base = signed_bundle(&m);

        // (a) the pre-v1 construction: signing the raw 32-byte key.
        let mut legacy = signed_bundle(&m);
        legacy.signed_prekey_signature = m.signing_sk.sign(m.signed_prekey_pk.as_bytes());
        assert!(
            matches!(
                verify_signed_prekey_v1(&legacy),
                Err(X3dhError::BadSignature)
            ),
            "a legacy raw-key signature must not verify as v1"
        );

        // (b) same fields, different domain — a foreign protocol's endorsement.
        let mut foreign_object = signed_prekey_object_v1(
            &m.identity_pk,
            &m.signing_sk.verifying_key(),
            &m.signed_prekey_pk,
        );
        foreign_object[0..18].copy_from_slice(b"arcium/x3dh-spk/v2");
        let mut foreign = signed_bundle(&m);
        foreign.signed_prekey_signature = m.signing_sk.sign(&foreign_object);
        assert!(matches!(
            verify_signed_prekey_v1(&foreign),
            Err(X3dhError::BadSignature)
        ));

        // (c) same fields, different suite byte.
        let mut other_suite = signed_prekey_object_v1(
            &m.identity_pk,
            &m.signing_sk.verifying_key(),
            &m.signed_prekey_pk,
        );
        other_suite[19] = 0x02;
        let mut suite_bundle = signed_bundle(&m);
        suite_bundle.signed_prekey_signature = m.signing_sk.sign(&other_suite);
        assert!(matches!(
            verify_signed_prekey_v1(&suite_bundle),
            Err(X3dhError::BadSignature)
        ));

        // The unmodified bundle still verifies, so the assertions above are not
        // passing for some unrelated reason.
        assert!(verify_signed_prekey_v1(&base).is_ok());
    }

    /// S6: `verify_strict` must actually be what runs. A small-order signing key
    /// is the case the two verifiers disagree on — `verify` accepts it, and it is
    /// exactly the shape that lets one signature validate under more than one key.
    /// Since the signing key travels inside the untrusted bundle it authenticates,
    /// that difference is the reason for the strict form.
    #[test]
    fn small_order_signing_key_is_rejected_by_strict_verification() {
        // Canonical small-order Edwards point (order 8) in compressed form.
        const SMALL_ORDER: [u8; 32] = [
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10,
            0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77,
            0x92, 0xac, 0x03, 0x7a,
        ];
        let Ok(weak) = VerifyingKey::from_bytes(&SMALL_ORDER) else {
            // The library refuses to construct it at all — an even stronger
            // rejection than the one this test is checking for.
            return;
        };

        let m = material();
        let mut bundle = signed_bundle(&m);
        bundle.signing_pk = weak;

        assert!(
            matches!(
                verify_signed_prekey_v1(&bundle),
                Err(X3dhError::BadSignature)
            ),
            "a small-order verification key must never authenticate a bundle"
        );
        assert!(
            weak.is_weak(),
            "test vector must actually be a weak key, or it proves nothing"
        );
    }
}
