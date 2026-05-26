//! `core-crypto` — X3DH + Double Ratchet for the Arcium Messenger.
//!
//! Pure crypto, no I/O. Bundled into a higher-level `core-protocol` crate later.

pub mod ratchet;
pub mod x3dh;

pub use ratchet::{DoubleRatchet, Header, RatchetError, HEADER_SIZE, MAX_SKIP};
pub use x3dh::{x3dh_initiate, x3dh_respond, AliceSession, BobSession, PrekeyBundle, X3dhError};

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::{OsRng, RngCore};
    use x25519_dalek::{PublicKey, StaticSecret};

    fn random_root() -> [u8; 32] {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        k
    }

    /// Convenience: set up Alice and Bob already past X3DH, sharing the same root key.
    fn pair() -> (DoubleRatchet, DoubleRatchet) {
        let sk = random_root();
        let bob_sk = StaticSecret::random_from_rng(OsRng);
        let bob_pk = PublicKey::from(&bob_sk);
        let alice = DoubleRatchet::init_alice(sk, bob_pk);
        let bob = DoubleRatchet::init_bob(sk, bob_sk);
        (alice, bob)
    }

    #[test]
    fn basic_alice_to_bob() {
        let (mut alice, mut bob) = pair();
        let (h, ct) = alice.encrypt(b"hello bob", b"AD").unwrap();
        assert_eq!(bob.decrypt(&h, &ct, b"AD").unwrap(), b"hello bob");
    }

    #[test]
    fn many_in_same_direction_uses_symmetric_chain() {
        let (mut alice, mut bob) = pair();
        for i in 0..50u32 {
            let msg = format!("msg #{}", i);
            let (h, ct) = alice.encrypt(msg.as_bytes(), b"").unwrap();
            assert_eq!(h.n, i, "counter must advance on each send");
            assert_eq!(bob.decrypt(&h, &ct, b"").unwrap(), msg.as_bytes());
        }
    }

    #[test]
    fn bidirectional_with_dh_ratchet() {
        let (mut alice, mut bob) = pair();
        // A → B
        let (h, ct) = alice.encrypt(b"a1", b"").unwrap();
        bob.decrypt(&h, &ct, b"").unwrap();
        // B → A  (first send from Bob — his sending chain is set up by his receive DH ratchet)
        let (h, ct) = bob.encrypt(b"b1", b"").unwrap();
        alice.decrypt(&h, &ct, b"").unwrap();
        // A → B  (Alice's DH ratchet step triggered)
        let (h, ct) = alice.encrypt(b"a2", b"").unwrap();
        bob.decrypt(&h, &ct, b"").unwrap();
        // B → A
        let (h, ct) = bob.encrypt(b"b2", b"").unwrap();
        assert_eq!(alice.decrypt(&h, &ct, b"").unwrap(), b"b2");
    }

    #[test]
    fn out_of_order_within_chain() {
        let (mut alice, mut bob) = pair();
        let m1 = alice.encrypt(b"one", b"").unwrap();
        let m2 = alice.encrypt(b"two", b"").unwrap();
        let m3 = alice.encrypt(b"three", b"").unwrap();
        // arrive: 2, 1, 3
        assert_eq!(bob.decrypt(&m2.0, &m2.1, b"").unwrap(), b"two");
        assert_eq!(bob.decrypt(&m1.0, &m1.1, b"").unwrap(), b"one");
        assert_eq!(bob.decrypt(&m3.0, &m3.1, b"").unwrap(), b"three");
    }

    #[test]
    fn late_message_from_previous_chain_still_decrypts() {
        let (mut alice, mut bob) = pair();
        // Alice sends two in old chain
        let a1 = alice.encrypt(b"a1", b"").unwrap();
        let a2 = alice.encrypt(b"a2", b"").unwrap();
        // Only a1 reaches Bob
        bob.decrypt(&a1.0, &a1.1, b"").unwrap();
        // Bob replies — this triggers Alice's DH ratchet on her next receive
        let b1 = bob.encrypt(b"b1", b"").unwrap();
        alice.decrypt(&b1.0, &b1.1, b"").unwrap();
        // Alice now sends in a new chain
        let a3 = alice.encrypt(b"a3", b"").unwrap();
        // Bob receives a3 first, then the late a2 from the old chain
        assert_eq!(bob.decrypt(&a3.0, &a3.1, b"").unwrap(), b"a3");
        assert_eq!(bob.decrypt(&a2.0, &a2.1, b"").unwrap(), b"a2");
    }

    #[test]
    fn tampered_header_is_rejected() {
        let (mut alice, mut bob) = pair();
        let (mut h, ct) = alice.encrypt(b"secret", b"").unwrap();
        h.n = 99; // tamper
        assert!(bob.decrypt(&h, &ct, b"").is_err());
    }

    #[test]
    fn x3dh_then_ratchet_end_to_end() {
        // Alice setup
        let alice_id = StaticSecret::random_from_rng(OsRng);
        let alice_id_pk = PublicKey::from(&alice_id);

        // Bob setup with full prekey bundle
        let bob_id = StaticSecret::random_from_rng(OsRng);
        let bob_id_pk = PublicKey::from(&bob_id);
        let bob_signing = SigningKey::generate(&mut OsRng);
        let bob_spk = StaticSecret::random_from_rng(OsRng);
        let bob_spk_pk = PublicKey::from(&bob_spk);
        let bob_spk_sig = bob_signing.sign(bob_spk_pk.as_bytes());
        let bob_opk = StaticSecret::random_from_rng(OsRng);
        let bob_opk_pk = PublicKey::from(&bob_opk);

        let bundle = PrekeyBundle {
            identity_pk: bob_id_pk,
            signing_pk: bob_signing.verifying_key(),
            signed_prekey_pk: bob_spk_pk,
            signed_prekey_signature: bob_spk_sig,
            one_time_prekey_pk: Some(bob_opk_pk),
        };

        let alice_sess = x3dh_initiate(&alice_id, alice_id_pk, &bundle).unwrap();
        let bob_sess = x3dh_respond(
            &bob_id,
            bob_id_pk,
            &bob_spk,
            Some(&bob_opk),
            alice_id_pk,
            alice_sess.ephemeral_pk,
        );

        assert_eq!(alice_sess.root_key, bob_sess.root_key, "X3DH must agree");
        assert_eq!(alice_sess.ad, bob_sess.ad, "AD must match");

        // Bootstrap ratchets and exchange a few messages both ways
        let mut alice = DoubleRatchet::init_alice(alice_sess.root_key, alice_sess.their_signed_prekey_pk);
        let mut bob = DoubleRatchet::init_bob(bob_sess.root_key, bob_spk);
        let ad = &alice_sess.ad;

        let (h, ct) = alice.encrypt(b"hello via x3dh", ad).unwrap();
        assert_eq!(bob.decrypt(&h, &ct, ad).unwrap(), b"hello via x3dh");

        let (h, ct) = bob.encrypt(b"reply", ad).unwrap();
        assert_eq!(alice.decrypt(&h, &ct, ad).unwrap(), b"reply");

        let (h, ct) = alice.encrypt(b"and again", ad).unwrap();
        assert_eq!(bob.decrypt(&h, &ct, ad).unwrap(), b"and again");
    }

    #[test]
    fn rejects_bad_signed_prekey_signature() {
        let alice_id = StaticSecret::random_from_rng(OsRng);
        let alice_id_pk = PublicKey::from(&alice_id);
        let bob_id_pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let bob_signing = SigningKey::generate(&mut OsRng);
        let attacker_signing = SigningKey::generate(&mut OsRng);
        let bob_spk_pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        // Signed by attacker, not Bob
        let bad_sig = attacker_signing.sign(bob_spk_pk.as_bytes());

        let bundle = PrekeyBundle {
            identity_pk: bob_id_pk,
            signing_pk: bob_signing.verifying_key(),
            signed_prekey_pk: bob_spk_pk,
            signed_prekey_signature: bad_sig,
            one_time_prekey_pk: None,
        };
        assert!(x3dh_initiate(&alice_id, alice_id_pk, &bundle).is_err());
    }
}//! `core-crypto` — X3DH + Double Ratchet for the Arcium Messenger.
//!
//! Pure crypto, no I/O. Bundled into a higher-level `core-protocol` crate later.

pub mod ratchet;
pub mod x3dh;

pub use ratchet::{DoubleRatchet, Header, RatchetError, HEADER_SIZE, MAX_SKIP};
pub use x3dh::{x3dh_initiate, x3dh_respond, AliceSession, BobSession, PrekeyBundle, X3dhError};

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::{OsRng, RngCore};
    use x25519_dalek::{PublicKey, StaticSecret};

    fn random_root() -> [u8; 32] {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        k
    }

    /// Convenience: set up Alice and Bob already past X3DH, sharing the same root key.
    fn pair() -> (DoubleRatchet, DoubleRatchet) {
        let sk = random_root();
        let bob_sk = StaticSecret::random_from_rng(OsRng);
        let bob_pk = PublicKey::from(&bob_sk);
        let alice = DoubleRatchet::init_alice(sk, bob_pk);
        let bob = DoubleRatchet::init_bob(sk, bob_sk);
        (alice, bob)
    }

    #[test]
    fn basic_alice_to_bob() {
        let (mut alice, mut bob) = pair();
        let (h, ct) = alice.encrypt(b"hello bob", b"AD").unwrap();
        assert_eq!(bob.decrypt(&h, &ct, b"AD").unwrap(), b"hello bob");
    }

    #[test]
    fn many_in_same_direction_uses_symmetric_chain() {
        let (mut alice, mut bob) = pair();
        for i in 0..50u32 {
            let msg = format!("msg #{}", i);
            let (h, ct) = alice.encrypt(msg.as_bytes(), b"").unwrap();
            assert_eq!(h.n, i, "counter must advance on each send");
            assert_eq!(bob.decrypt(&h, &ct, b"").unwrap(), msg.as_bytes());
        }
    }

    #[test]
    fn bidirectional_with_dh_ratchet() {
        let (mut alice, mut bob) = pair();
        // A → B
        let (h, ct) = alice.encrypt(b"a1", b"").unwrap();
        bob.decrypt(&h, &ct, b"").unwrap();
        // B → A  (first send from Bob — his sending chain is set up by his receive DH ratchet)
        let (h, ct) = bob.encrypt(b"b1", b"").unwrap();
        alice.decrypt(&h, &ct, b"").unwrap();
        // A → B  (Alice's DH ratchet step triggered)
        let (h, ct) = alice.encrypt(b"a2", b"").unwrap();
        bob.decrypt(&h, &ct, b"").unwrap();
        // B → A
        let (h, ct) = bob.encrypt(b"b2", b"").unwrap();
        assert_eq!(alice.decrypt(&h, &ct, b"").unwrap(), b"b2");
    }

    #[test]
    fn out_of_order_within_chain() {
        let (mut alice, mut bob) = pair();
        let m1 = alice.encrypt(b"one", b"").unwrap();
        let m2 = alice.encrypt(b"two", b"").unwrap();
        let m3 = alice.encrypt(b"three", b"").unwrap();
        // arrive: 2, 1, 3
        assert_eq!(bob.decrypt(&m2.0, &m2.1, b"").unwrap(), b"two");
        assert_eq!(bob.decrypt(&m1.0, &m1.1, b"").unwrap(), b"one");
        assert_eq!(bob.decrypt(&m3.0, &m3.1, b"").unwrap(), b"three");
    }

    #[test]
    fn late_message_from_previous_chain_still_decrypts() {
        let (mut alice, mut bob) = pair();
        // Alice sends two in old chain
        let a1 = alice.encrypt(b"a1", b"").unwrap();
        let a2 = alice.encrypt(b"a2", b"").unwrap();
        // Only a1 reaches Bob
        bob.decrypt(&a1.0, &a1.1, b"").unwrap();
        // Bob replies — this triggers Alice's DH ratchet on her next receive
        let b1 = bob.encrypt(b"b1", b"").unwrap();
        alice.decrypt(&b1.0, &b1.1, b"").unwrap();
        // Alice now sends in a new chain
        let a3 = alice.encrypt(b"a3", b"").unwrap();
        // Bob receives a3 first, then the late a2 from the old chain
        assert_eq!(bob.decrypt(&a3.0, &a3.1, b"").unwrap(), b"a3");
        assert_eq!(bob.decrypt(&a2.0, &a2.1, b"").unwrap(), b"a2");
    }

    #[test]
    fn tampered_header_is_rejected() {
        let (mut alice, mut bob) = pair();
        let (mut h, ct) = alice.encrypt(b"secret", b"").unwrap();
        h.n = 99; // tamper
        assert!(bob.decrypt(&h, &ct, b"").is_err());
    }

    #[test]
    fn x3dh_then_ratchet_end_to_end() {
        // Alice setup
        let alice_id = StaticSecret::random_from_rng(OsRng);
        let alice_id_pk = PublicKey::from(&alice_id);

        // Bob setup with full prekey bundle
        let bob_id = StaticSecret::random_from_rng(OsRng);
        let bob_id_pk = PublicKey::from(&bob_id);
        let bob_signing = SigningKey::generate(&mut OsRng);
        let bob_spk = StaticSecret::random_from_rng(OsRng);
        let bob_spk_pk = PublicKey::from(&bob_spk);
        let bob_spk_sig = bob_signing.sign(bob_spk_pk.as_bytes());
        let bob_opk = StaticSecret::random_from_rng(OsRng);
        let bob_opk_pk = PublicKey::from(&bob_opk);

        let bundle = PrekeyBundle {
            identity_pk: bob_id_pk,
            signing_pk: bob_signing.verifying_key(),
            signed_prekey_pk: bob_spk_pk,
            signed_prekey_signature: bob_spk_sig,
            one_time_prekey_pk: Some(bob_opk_pk),
        };

        let alice_sess = x3dh_initiate(&alice_id, alice_id_pk, &bundle).unwrap();
        let bob_sess = x3dh_respond(
            &bob_id,
            bob_id_pk,
            &bob_spk,
            Some(&bob_opk),
            alice_id_pk,
            alice_sess.ephemeral_pk,
        );

        assert_eq!(alice_sess.root_key, bob_sess.root_key, "X3DH must agree");
        assert_eq!(alice_sess.ad, bob_sess.ad, "AD must match");

        // Bootstrap ratchets and exchange a few messages both ways
        let mut alice = DoubleRatchet::init_alice(alice_sess.root_key, alice_sess.their_signed_prekey_pk);
        let mut bob = DoubleRatchet::init_bob(bob_sess.root_key, bob_spk);
        let ad = &alice_sess.ad;

        let (h, ct) = alice.encrypt(b"hello via x3dh", ad).unwrap();
        assert_eq!(bob.decrypt(&h, &ct, ad).unwrap(), b"hello via x3dh");

        let (h, ct) = bob.encrypt(b"reply", ad).unwrap();
        assert_eq!(alice.decrypt(&h, &ct, ad).unwrap(), b"reply");

        let (h, ct) = alice.encrypt(b"and again", ad).unwrap();
        assert_eq!(bob.decrypt(&h, &ct, ad).unwrap(), b"and again");
    }

    #[test]
    fn rejects_bad_signed_prekey_signature() {
        let alice_id = StaticSecret::random_from_rng(OsRng);
        let alice_id_pk = PublicKey::from(&alice_id);
        let bob_id_pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let bob_signing = SigningKey::generate(&mut OsRng);
        let attacker_signing = SigningKey::generate(&mut OsRng);
        let bob_spk_pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        // Signed by attacker, not Bob
        let bad_sig = attacker_signing.sign(bob_spk_pk.as_bytes());

        let bundle = PrekeyBundle {
            identity_pk: bob_id_pk,
            signing_pk: bob_signing.verifying_key(),
            signed_prekey_pk: bob_spk_pk,
            signed_prekey_signature: bad_sig,
            one_time_prekey_pk: None,
        };
        assert!(x3dh_initiate(&alice_id, alice_id_pk, &bundle).is_err());
    }
}