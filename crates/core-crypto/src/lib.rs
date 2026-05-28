//! Core cryptographic primitives for Arcium.

pub mod ratchet;
pub mod rescue;
pub mod x3dh;

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, Signer, SigningKey};
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::ratchet::DoubleRatchet;
    use crate::x3dh::{x3dh_initiate, x3dh_respond, PrekeyBundle, X3dhError};

    // ─── Helpers ────────────────────────────────────────────────────────────────

    /// Build a full set of Bob's key material ready for an X3DH handshake.
    fn make_bob() -> (
        StaticSecret, // identity_sk
        PublicKey,    // identity_pk
        SigningKey,   // signing_sk (Ed25519)
        StaticSecret, // signed_prekey_sk
        PublicKey,    // signed_prekey_pk
        Signature,    // signed_prekey_sig
        StaticSecret, // one_time_prekey_sk
        PublicKey,    // one_time_prekey_pk
    ) {
        let identity_sk = StaticSecret::random_from_rng(OsRng);
        let identity_pk = PublicKey::from(&identity_sk);

        let signing_sk = SigningKey::generate(&mut OsRng);

        let signed_prekey_sk = StaticSecret::random_from_rng(OsRng);
        let signed_prekey_pk = PublicKey::from(&signed_prekey_sk);
        let sig = signing_sk.sign(signed_prekey_pk.as_bytes());

        let otpk_sk = StaticSecret::random_from_rng(OsRng);
        let otpk_pk = PublicKey::from(&otpk_sk);

        (
            identity_sk,
            identity_pk,
            signing_sk,
            signed_prekey_sk,
            signed_prekey_pk,
            sig,
            otpk_sk,
            otpk_pk,
        )
    }

    // ─── X3DH tests (5) ─────────────────────────────────────────────────────────

    /// Alice and Bob should derive the same root key (without OTPk).
    #[test]
    fn basic_alice_to_bob() {
        let (b_id_sk, b_id_pk, b_sign_sk, b_spk_sk, b_spk_pk, b_spk_sig, _, _) = make_bob();

        let a_id_sk = StaticSecret::random_from_rng(OsRng);
        let a_id_pk = PublicKey::from(&a_id_sk);

        let bundle = PrekeyBundle {
            identity_pk: b_id_pk,
            signing_pk: b_sign_sk.verifying_key(),
            signed_prekey_pk: b_spk_pk,
            signed_prekey_signature: b_spk_sig,
            one_time_prekey_pk: None,
        };

        let alice = x3dh_initiate(&a_id_sk, a_id_pk, &bundle).expect("initiate");
        let bob = x3dh_respond(
            &b_id_sk,
            b_id_pk,
            &b_spk_sk,
            None,
            a_id_pk,
            alice.ephemeral_pk,
        );

        assert_eq!(alice.root_key, bob.root_key, "root keys must match");
    }

    /// Alice sends without OTPk; Bob responds and keys still match bidirectionally.
    #[test]
    fn bidirectional_no_otpk() {
        let (b_id_sk, b_id_pk, b_sign_sk, b_spk_sk, b_spk_pk, b_spk_sig, _, _) = make_bob();
        let a_id_sk = StaticSecret::random_from_rng(OsRng);
        let a_id_pk = PublicKey::from(&a_id_sk);

        let bundle = PrekeyBundle {
            identity_pk: b_id_pk,
            signing_pk: b_sign_sk.verifying_key(),
            signed_prekey_pk: b_spk_pk,
            signed_prekey_signature: b_spk_sig,
            one_time_prekey_pk: None,
        };
        let alice = x3dh_initiate(&a_id_sk, a_id_pk, &bundle).unwrap();
        let bob = x3dh_respond(&b_id_sk, b_id_pk, &b_spk_sk, None, a_id_pk, alice.ephemeral_pk);

        assert_eq!(alice.root_key, bob.root_key);
        // AD: alice prepends hers, bob prepends theirs — the bytes must be identical.
        assert_eq!(alice.ad, bob.ad);
    }

    /// Including a one-time prekey should still produce matching root keys.
    #[test]
    fn with_one_time_prekey() {
        let (b_id_sk, b_id_pk, b_sign_sk, b_spk_sk, b_spk_pk, b_spk_sig, otpk_sk, otpk_pk) =
            make_bob();
        let a_id_sk = StaticSecret::random_from_rng(OsRng);
        let a_id_pk = PublicKey::from(&a_id_sk);

        let bundle = PrekeyBundle {
            identity_pk: b_id_pk,
            signing_pk: b_sign_sk.verifying_key(),
            signed_prekey_pk: b_spk_pk,
            signed_prekey_signature: b_spk_sig,
            one_time_prekey_pk: Some(otpk_pk),
        };
        let alice = x3dh_initiate(&a_id_sk, a_id_pk, &bundle).unwrap();
        let bob = x3dh_respond(
            &b_id_sk,
            b_id_pk,
            &b_spk_sk,
            Some(&otpk_sk),
            a_id_pk,
            alice.ephemeral_pk,
        );

        assert_eq!(alice.root_key, bob.root_key);
    }

    /// A tampered signature must be rejected.
    #[test]
    fn bad_signature_rejected() {
        let (_, b_id_pk, b_sign_sk, _, b_spk_pk, _, _, _) = make_bob();
        let a_id_sk = StaticSecret::random_from_rng(OsRng);
        let a_id_pk = PublicKey::from(&a_id_sk);

        // Sign something else to produce a wrong signature for b_spk_pk.
        let bad_sig = b_sign_sk.sign(b"wrong data, not the prekey bytes");
        let bundle = PrekeyBundle {
            identity_pk: b_id_pk,
            signing_pk: b_sign_sk.verifying_key(),
            signed_prekey_pk: b_spk_pk,
            signed_prekey_signature: bad_sig,
            one_time_prekey_pk: None,
        };
        let result = x3dh_initiate(&a_id_sk, a_id_pk, &bundle);
        assert!(
            matches!(result, Err(X3dhError::BadSignature)),
            "expected BadSignature, got {:?}",
            result
        );
    }

    /// Root keys from two independent handshakes must differ.
    #[test]
    fn two_sessions_produce_different_keys() {
        let (b_id_sk, b_id_pk, b_sign_sk, b_spk_sk, b_spk_pk, b_spk_sig, _, _) = make_bob();

        let bundle = PrekeyBundle {
            identity_pk: b_id_pk,
            signing_pk: b_sign_sk.verifying_key(),
            signed_prekey_pk: b_spk_pk,
            signed_prekey_signature: b_spk_sig,
            one_time_prekey_pk: None,
        };

        let a1_id_sk = StaticSecret::random_from_rng(OsRng);
        let a1_id_pk = PublicKey::from(&a1_id_sk);
        let s1 = x3dh_initiate(&a1_id_sk, a1_id_pk, &bundle).unwrap();

        let a2_id_sk = StaticSecret::random_from_rng(OsRng);
        let a2_id_pk = PublicKey::from(&a2_id_sk);
        let s2 = x3dh_initiate(&a2_id_sk, a2_id_pk, &bundle).unwrap();

        // Sanity: two different senders must get different root keys.
        assert_ne!(s1.root_key, s2.root_key);

        // Both sessions must still be valid on Bob's end.
        let b1 = x3dh_respond(&b_id_sk, b_id_pk, &b_spk_sk, None, a1_id_pk, s1.ephemeral_pk);
        let b2 = x3dh_respond(&b_id_sk, b_id_pk, &b_spk_sk, None, a2_id_pk, s2.ephemeral_pk);
        assert_eq!(s1.root_key, b1.root_key);
        assert_eq!(s2.root_key, b2.root_key);
    }

    // ─── Double Ratchet tests (6) ────────────────────────────────────────────────

    /// Helper: produce a shared root key and matching ratchet states via X3DH.
    fn ratchet_pair() -> (DoubleRatchet, DoubleRatchet) {
        let (b_id_sk, b_id_pk, b_sign_sk, b_spk_sk, b_spk_pk, b_spk_sig, _, _) = make_bob();
        let a_id_sk = StaticSecret::random_from_rng(OsRng);
        let a_id_pk = PublicKey::from(&a_id_sk);

        let bundle = PrekeyBundle {
            identity_pk: b_id_pk,
            signing_pk: b_sign_sk.verifying_key(),
            signed_prekey_pk: b_spk_pk,
            signed_prekey_signature: b_spk_sig,
            one_time_prekey_pk: None,
        };
        let alice_x3dh = x3dh_initiate(&a_id_sk, a_id_pk, &bundle).unwrap();
        let bob_x3dh = x3dh_respond(&b_id_sk, b_id_pk, &b_spk_sk, None, a_id_pk, alice_x3dh.ephemeral_pk);

        // Alice uses Bob's signed prekey as the initial DH public key.
        let alice_r = DoubleRatchet::init_alice(alice_x3dh.root_key, b_spk_pk);
        let bob_r = DoubleRatchet::init_bob(bob_x3dh.root_key, b_spk_sk);
        (alice_r, bob_r)
    }

    /// Alice sends one message; Bob decrypts it correctly.
    #[test]
    fn ratchet_alice_send_bob_receive() {
        let (mut alice, mut bob) = ratchet_pair();
        let msg = b"hello, Bob!";
        let ad = b"session-1";

        let (hdr, ct) = alice.encrypt(msg, ad).unwrap();
        let pt = bob.decrypt(&hdr, &ct, ad).unwrap();

        assert_eq!(pt, msg);
    }

    /// Bob replies after receiving Alice's first message.
    #[test]
    fn ratchet_bob_responds() {
        let (mut alice, mut bob) = ratchet_pair();
        let ad = b"session-2";

        let (h1, c1) = alice.encrypt(b"ping", ad).unwrap();
        bob.decrypt(&h1, &c1, ad).unwrap();

        let (h2, c2) = bob.encrypt(b"pong", ad).unwrap();
        let pt = alice.decrypt(&h2, &c2, ad).unwrap();

        assert_eq!(pt, b"pong");
    }

    /// Messages that arrive out of order are still decryptable.
    #[test]
    fn ratchet_out_of_order_messages() {
        let (mut alice, mut bob) = ratchet_pair();
        let ad = b"session-3";

        let (h0, c0) = alice.encrypt(b"msg-0", ad).unwrap();
        let (h1, c1) = alice.encrypt(b"msg-1", ad).unwrap();
        let (h2, c2) = alice.encrypt(b"msg-2", ad).unwrap();

        // Deliver in reverse order.
        assert_eq!(bob.decrypt(&h2, &c2, ad).unwrap(), b"msg-2");
        assert_eq!(bob.decrypt(&h1, &c1, ad).unwrap(), b"msg-1");
        assert_eq!(bob.decrypt(&h0, &c0, ad).unwrap(), b"msg-0");
    }

    /// Many back-and-forth messages stay consistent.
    #[test]
    fn ratchet_many_messages() {
        let (mut alice, mut bob) = ratchet_pair();
        let ad = b"session-4";

        for i in 0u32..20 {
            // Alice → Bob
            let payload = format!("a→b {i}");
            let (h, c) = alice.encrypt(payload.as_bytes(), ad).unwrap();
            let pt = bob.decrypt(&h, &c, ad).unwrap();
            assert_eq!(pt, payload.as_bytes());

            // Bob → Alice
            let payload = format!("b→a {i}");
            let (h, c) = bob.encrypt(payload.as_bytes(), ad).unwrap();
            let pt = alice.decrypt(&h, &c, ad).unwrap();
            assert_eq!(pt, payload.as_bytes());
        }
    }

    /// A DH ratchet step occurs naturally: after Bob replies, Alice's next message
    /// should still decrypt fine (different sending chain after ratchet).
    #[test]
    fn ratchet_dh_step_occurs() {
        let (mut alice, mut bob) = ratchet_pair();
        let ad = b"session-5";

        // Round 1.
        let (h, c) = alice.encrypt(b"r1-a", ad).unwrap();
        bob.decrypt(&h, &c, ad).unwrap();

        // Bob replies — this triggers a DH ratchet on his end.
        let (h, c) = bob.encrypt(b"r1-b", ad).unwrap();
        alice.decrypt(&h, &c, ad).unwrap();

        // Alice continues — after Bob's reply Alice knows Bob's new DH pub → ratchet.
        let (h, c) = alice.encrypt(b"r2-a", ad).unwrap();
        let pt = bob.decrypt(&h, &c, ad).unwrap();
        assert_eq!(pt, b"r2-a");
    }

    /// Attempting to skip more than MAX_SKIP messages must return SkipLimit.
    #[test]
    fn ratchet_skip_limit_exceeded() {
        use crate::ratchet::{RatchetError, MAX_SKIP};

        let (mut alice, mut bob) = ratchet_pair();
        let ad = b"session-6";

        // Alice sends MAX_SKIP+2 messages but we only deliver the last one.
        let mut last = None;
        for _ in 0..MAX_SKIP + 2 {
            last = Some(alice.encrypt(b"skip-me", ad).unwrap());
        }
        let (h, c) = last.unwrap();
        let result = bob.decrypt(&h, &c, ad);
        assert!(
            matches!(result, Err(RatchetError::SkipLimit)),
            "expected SkipLimit error"
        );
    }
}
