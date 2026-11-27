use super::*;
use core_crypto::ratchet::HEADER_SIZE;

/// Test shorthands that keep the pre-S2-B2 tests below unchanged while
/// running them on the durable path: `encrypt_message` is the committed
/// wire bytes of a `send_message` with a fresh client message id,
/// `decrypt_message` the plaintext of a
/// newly accepted `receive_message`. Test-only; not part of the FFI.
impl ArciumCore {
    fn encrypt_message(&self, session_id: u64, plaintext: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let client_id = NEXT.fetch_add(1, Ordering::Relaxed).to_be_bytes().to_vec();
        match self.send_message(session_id, client_id, plaintext)? {
            SendResult::Sent { message } => Ok(message.wire),
            other => panic!("expected a new message, got {other:?}"),
        }
    }

    fn decrypt_message(&self, session_id: u64, message: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        match self.receive_message(session_id, message)? {
            ReceiveResult::Accepted { message } => Ok(message.plaintext.0),
            other => panic!("expected a new message, got {other:?}"),
        }
    }
}
use tempfile::tempdir;

fn key32(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

#[test]
fn identity_generates_keys() {
    let id = Identity::generate();
    assert_ne!(id.public_key_bytes(), vec![0u8; 32], "public key must not be all zeros");
}

#[test]
fn identity_public_key_correct_size() {
    assert_eq!(Identity::generate().public_key_bytes().len(), 32);
}

#[test]
fn identity_dh_public_key_correct_size_and_distinct_from_signing_key() {
    let id = Identity::generate();
    let dh_pk = id.dh_public_key_bytes();
    assert_eq!(dh_pk.len(), 32);
    assert_ne!(dh_pk, id.public_key_bytes(), "DH key and signing key must differ");
}

#[test]
fn core_saves_and_loads_identity() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("db").to_str().unwrap().to_string();

    let core = ArciumCore::new(path, key32(0)).unwrap();
    let id = Identity::generate();
    let pk = id.public_key_bytes();
    core.save_identity(id).unwrap();

    let loaded = core.load_identity().unwrap().expect("identity must be present after save");
    assert_eq!(loaded.public_key_bytes(), pk);
}

#[test]
fn core_with_wrong_key_fails() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("db").to_str().unwrap().to_string();

    // Save with key 0x00…
    let core = ArciumCore::new(path.clone(), key32(0)).unwrap();
    core.save_identity(Identity::generate()).unwrap();

    // Open same file with key 0x01…: records are found by a name derived
    // from the master key, so this key finds no identity record at all.
    let core2 = ArciumCore::new(path, key32(1)).unwrap();
    assert!(matches!(core2.load_identity(), Ok(None)));
}

#[test]
fn core_new_rejects_short_master_key() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("db").to_str().unwrap().to_string();
    let result = ArciumCore::new(path, vec![0u8; 16]);
    assert!(matches!(result, Err(CoreError::InvalidKey { .. })));
}

/// `new` borrows the key it is given: every wrong length is refused with
/// the same error, and a right-length key opens a store that the by-value
/// `EncryptedStore::open` reads back — the construction path changed, the
/// store did not.
#[test]
fn core_new_checks_key_length_and_opens_the_same_store() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("db").to_str().unwrap().to_string();
    for len in [0usize, 1, 31, 33, 64] {
        match ArciumCore::new(path.clone(), vec![0u8; len]) {
            Err(CoreError::InvalidKey { msg }) => {
                assert_eq!(msg, "expected exactly 32 bytes", "length {len}")
            }
            other => panic!("length {len}: expected InvalidKey, got {:?}", other.err()),
        }
    }
    let core = ArciumCore::new(path.clone(), key32(5)).unwrap();
    let id = Identity::generate();
    let pk = id.public_key_bytes();
    core.save_identity(id).unwrap();
    drop(core);
    let store = EncryptedStore::open(&path, [5u8; 32]).unwrap();
    assert_eq!(store.get(IDENTITY_KEY).unwrap().len(), 64);
    drop(store);
    let again = ArciumCore::new(path, key32(5)).unwrap();
    assert_eq!(again.load_identity().unwrap().unwrap().public_key_bytes(), pk);
}

#[test]
fn save_identity_returns_ok_on_success() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("db").to_str().unwrap().to_string();
    let core = ArciumCore::new(path, key32(0)).unwrap();
    let result = core.save_identity(Identity::generate());
    assert!(result.is_ok(), "save_identity must return Ok on success");
}

#[test]
fn save_identity_returns_err_on_poisoned_mutex() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("db").to_str().unwrap().to_string();
    let core = Arc::new(ArciumCore::new(path, key32(0)).unwrap());
    // Poison the mutex by panicking while holding the lock in another thread.
    let core2 = Arc::clone(&core);
    let _ = std::thread::spawn(move || {
        let _guard = core2.store.lock().unwrap();
        panic!("poison");
    })
    .join();
    // The mutex is now poisoned; save_identity must return Err, not panic.
    let result = core.save_identity(Identity::generate());
    assert!(
        matches!(result, Err(CoreError::Storage { .. })),
        "poisoned mutex must surface as CoreError::Storage, got {:?}",
        result
    );
}

#[test]
fn load_identity_returns_err_on_poisoned_mutex() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("db").to_str().unwrap().to_string();
    let core = Arc::new(ArciumCore::new(path, key32(0)).unwrap());
    core.save_identity(Identity::generate()).unwrap();
    // Poison the mutex by panicking while holding the lock in another thread.
    let core2 = Arc::clone(&core);
    let _ = std::thread::spawn(move || {
        let _guard = core2.store.lock().unwrap();
        panic!("poison");
    })
    .join();
    // The mutex is now poisoned; load_identity must return Err — not
    // panic across FFI, and not report "no identity".
    assert!(
        matches!(core.load_identity(), Err(CoreError::Storage { .. })),
        "poisoned mutex must surface as CoreError::Storage"
    );
}

// ── Messaging FFI surface ────────────────────────────────────────────────

/// A structurally valid v1 handshake for a peer, with no one-time prekey
/// named. Used where a test needs the parser to pass so a *later* stage is
/// what fails; the identity is real, the ephemeral key is arbitrary.
fn synthetic_handshake(identity_pk: &[u8]) -> Vec<u8> {
    let mut hs = vec![0u8; INITIATOR_HANDSHAKE_V1_LEN];
    hs[0] = 0x01;
    hs[1] = 0x01;
    hs[4..36].copy_from_slice(identity_pk);
    hs[36..68].copy_from_slice(&[9u8; 32]);
    hs
}

fn fresh_core(byte: u8) -> Arc<ArciumCore> {
    let dir = tempdir().unwrap();
    // Leak the tempdir so the DB file survives for the life of the test
    // (the harness's short-lived arcium-msgffi scratch clone is disposed
    // separately; this only needs to survive one test function).
    let path = dir.keep().join("db").to_str().unwrap().to_string();
    ArciumCore::new(path, key32(byte)).unwrap()
}

#[test]
fn establish_prekeys_then_export_bundle_round_trips_stably() {
    let core = fresh_core(1);
    core.save_identity(Identity::generate()).unwrap();
    core.establish_prekeys().unwrap();

    let bundle1 = core.export_prekey_bundle().unwrap();
    let bundle2 = core.export_prekey_bundle().unwrap();
    assert_eq!(bundle1, bundle2, "export_prekey_bundle must be a pure read (D3), not regenerate");
    assert_eq!(
        bundle1.len(),
        PREKEY_BUNDLE_V1_LEN,
        "v1 bundles are always {PREKEY_BUNDLE_V1_LEN} bytes, with or without a one-time prekey"
    );
}

#[test]
fn export_prekey_bundle_fails_before_establish_prekeys() {
    let core = fresh_core(2);
    core.save_identity(Identity::generate()).unwrap();
    assert!(core.export_prekey_bundle().is_err());
}

#[test]
fn alice_to_bob_full_round_trip_recovers_exact_plaintext() {
    let session_id: u64 = 42;

    let bob = fresh_core(10);
    bob.save_identity(Identity::generate()).unwrap();
    bob.establish_prekeys().unwrap();
    let bob_bundle = bob.export_prekey_bundle().unwrap();

    let alice = fresh_core(20);
    alice.save_identity(Identity::generate()).unwrap();

    let alice_handshake_bytes = alice.establish_session_initiator(session_id, bob_bundle).unwrap();
    assert_eq!(alice_handshake_bytes.len(), INITIATOR_HANDSHAKE_V1_LEN);

    bob.establish_session_responder(session_id, alice_handshake_bytes.clone())
        .unwrap();

    let plaintext = b"hello arcium".to_vec();
    let message = alice.encrypt_message(session_id, plaintext.clone()).unwrap();

    // Ciphertext must not equal the plaintext — this is not a stub echo.
    assert_ne!(&message[HEADER_SIZE..], plaintext.as_slice());

    let recovered = bob.decrypt_message(session_id, message).unwrap();
    assert_eq!(recovered, plaintext, "Bob must recover exactly what Alice sent");
}

#[test]
fn forged_message_fails_and_does_not_desync_the_session() {
    let session_id: u64 = 7;

    let bob = fresh_core(30);
    bob.save_identity(Identity::generate()).unwrap();
    bob.establish_prekeys().unwrap();
    let bob_bundle = bob.export_prekey_bundle().unwrap();

    let alice = fresh_core(40);
    alice.save_identity(Identity::generate()).unwrap();
    let handshake = alice.establish_session_initiator(session_id, bob_bundle).unwrap();
    bob.establish_session_responder(session_id, handshake.clone())
        .unwrap();

    let genuine = alice.encrypt_message(session_id, b"real message".to_vec()).unwrap();

    // Tamper one byte of the ciphertext (not the header) before Bob ever
    // sees a genuine message — this is Bob's very first decrypt, so it
    // also exercises the F-1 path at the "no dhr set yet" boundary.
    let mut forged = genuine.clone();
    let last = forged.len() - 1;
    forged[last] ^= 0xFF;

    assert!(bob.decrypt_message(session_id, forged).is_err(), "forged ciphertext must fail authentication");

    // The genuine message, unmodified, must still decrypt correctly —
    // proof the failed forged attempt did not desync Bob's session.
    let recovered = bob.decrypt_message(session_id, genuine).unwrap();
    assert_eq!(recovered, b"real message");
}

#[test]
fn multi_message_both_directions_ratchet_advances() {
    let session_id: u64 = 99;

    let bob = fresh_core(50);
    bob.save_identity(Identity::generate()).unwrap();
    bob.establish_prekeys().unwrap();
    let bob_bundle = bob.export_prekey_bundle().unwrap();

    let alice = fresh_core(60);
    alice.save_identity(Identity::generate()).unwrap();
    let handshake = alice.establish_session_initiator(session_id, bob_bundle).unwrap();
    bob.establish_session_responder(session_id, handshake.clone())
        .unwrap();

    // Alice must send first: Bob's sending chain key isn't derived until
    // his receiving DH ratchet step runs on the first inbound message.
    let m1 = alice.encrypt_message(session_id, b"one".to_vec()).unwrap();
    assert_eq!(bob.decrypt_message(session_id, m1).unwrap(), b"one");

    let m2 = alice.encrypt_message(session_id, b"two".to_vec()).unwrap();
    assert_eq!(bob.decrypt_message(session_id, m2).unwrap(), b"two");

    // Now Bob can reply — his cks was derived by the DH step above.
    let r1 = bob.encrypt_message(session_id, b"reply one".to_vec()).unwrap();
    assert_eq!(alice.decrypt_message(session_id, r1).unwrap(), b"reply one");

    let r2 = bob.encrypt_message(session_id, b"reply two".to_vec()).unwrap();
    assert_eq!(alice.decrypt_message(session_id, r2).unwrap(), b"reply two");

    let m3 = alice.encrypt_message(session_id, b"three".to_vec()).unwrap();
    assert_eq!(bob.decrypt_message(session_id, m3).unwrap(), b"three");
}

#[test]
fn encrypt_and_decrypt_fail_with_no_session() {
    let core = fresh_core(70);
    core.save_identity(Identity::generate()).unwrap();
    assert!(matches!(
        core.encrypt_message(1, b"x".to_vec()),
        Err(CoreError::NoSession { session_id: 1 })
    ));
    assert!(matches!(
        core.decrypt_message(1, vec![0u8; HEADER_SIZE]),
        Err(CoreError::NoSession { session_id: 1 })
    ));
}

/// `session_id` is a purely local lookup handle, not part of the protocol.
/// The two peers here deliberately pick *different* ids for the same
/// cryptographic session — Alice 42, Bob 77 — and still exchange messages
/// in both directions.
///
/// The other round-trip tests all happen to use one id on both sides, so
/// they cannot distinguish "the id is local" from "the id must match".
/// This one can: if the id were bound into the handshake, the header, or
/// the associated data, the mismatch would surface as an authentication
/// failure rather than exact plaintext recovery.
#[test]
fn asymmetric_session_ids_still_round_trip_both_directions() {
    let alice_session_id: u64 = 42;
    let bob_session_id: u64 = 77;
    assert_ne!(alice_session_id, bob_session_id, "the point of this test is that they differ");

    let bob = fresh_core(80);
    bob.save_identity(Identity::generate()).unwrap();
    bob.establish_prekeys().unwrap();
    let bob_bundle = bob.export_prekey_bundle().unwrap();

    let alice = fresh_core(90);
    alice.save_identity(Identity::generate()).unwrap();

    let handshake = alice
        .establish_session_initiator(alice_session_id, bob_bundle)
        .unwrap();
    bob.establish_session_responder(bob_session_id, handshake.clone())
    .unwrap();

    // Alice must send first: Bob's sending chain key isn't derived until
    // his receiving DH ratchet step runs on the first inbound message.
    let outbound = b"from alice under id 42".to_vec();
    let message = alice
        .encrypt_message(alice_session_id, outbound.clone())
        .unwrap();
    assert_eq!(
        bob.decrypt_message(bob_session_id, message).unwrap(),
        outbound,
        "Bob must recover Alice's plaintext exactly while looking the session up under a different id",
    );

    let reply = b"from bob under id 77".to_vec();
    let reply_message = bob.encrypt_message(bob_session_id, reply.clone()).unwrap();
    assert_eq!(
        alice.decrypt_message(alice_session_id, reply_message).unwrap(),
        reply,
        "Alice must recover Bob's reply exactly under her own unrelated id",
    );

    // Each side's id is meaningless to the other: the peer's id resolves to
    // nothing locally, which is what "local handle" means in practice.
    assert!(matches!(
        alice.encrypt_message(bob_session_id, b"x".to_vec()),
        Err(CoreError::NoSession { session_id }) if session_id == bob_session_id
    ));
    assert!(matches!(
        bob.encrypt_message(alice_session_id, b"x".to_vec()),
        Err(CoreError::NoSession { session_id }) if session_id == alice_session_id
    ));
}

// ── local_session_handle ─────────────────────────────────────────────────

#[test]
fn local_session_handle_is_deterministic_and_key_dependent() {
    assert_eq!(
        local_session_handle(key32(3)).unwrap(),
        local_session_handle(key32(3)).unwrap()
    );
    assert_ne!(
        local_session_handle(key32(3)).unwrap(),
        local_session_handle(key32(4)).unwrap()
    );
}

#[test]
fn local_session_handle_rejects_wrong_length() {
    for len in [0usize, 31, 33, 64] {
        assert!(
            matches!(
                local_session_handle(vec![1u8; len]),
                Err(CoreError::InvalidKey { .. })
            ),
            "a {len}-byte key must be rejected, not silently truncated or padded"
        );
    }
}

/// A handle derived for a real peer must actually address that peer's session
/// end to end: establish under it, then encrypt/decrypt through it.
#[test]
fn derived_handle_addresses_a_real_session() {
    let bob = fresh_core(120);
    bob.save_identity(Identity::generate()).unwrap();
    bob.establish_prekeys().unwrap();
    let bob_bundle = bob.export_prekey_bundle().unwrap();
    // Bob's X25519 identity public key sits after the 4-byte v1 header.
    let bob_identity_pk = bob_bundle[4..36].to_vec();

    let alice = fresh_core(130);
    let alice_identity = Identity::generate();
    let alice_identity_dh_pk = alice_identity.dh_public_key_bytes();
    alice.save_identity(alice_identity).unwrap();

    // Each side derives a handle for the *other* peer; the two differ, which
    // is fine — handles are local and need not agree (see PR #75).
    let alice_handle = local_session_handle(bob_identity_pk).unwrap();
    let bob_handle = local_session_handle(alice_identity_dh_pk).unwrap();
    assert_ne!(alice_handle, bob_handle);

    let handshake = alice.establish_session_initiator(alice_handle, bob_bundle).unwrap();
    bob.establish_session_responder(bob_handle, handshake.clone())
    .unwrap();

    let plaintext = b"addressed by derived handle".to_vec();
    let message = alice.encrypt_message(alice_handle, plaintext.clone()).unwrap();
    assert_eq!(bob.decrypt_message(bob_handle, message).unwrap(), plaintext);
}

// ── Session ownership: no silent replacement ─────────────────────────────

/// Builds a peer that is ready to be established against, returning its core
/// and its exported prekey bundle.
fn peer_with_prekeys(byte: u8) -> (Arc<ArciumCore>, Vec<u8>) {
    let core = fresh_core(byte);
    core.save_identity(Identity::generate()).unwrap();
    core.establish_prekeys().unwrap();
    let bundle = core.export_prekey_bundle().unwrap();
    (core, bundle)
}

/// Re-establishing the same peer under a live handle must be refused, and —
/// the part that matters — the existing ratchet must survive intact. Before
/// this guard the second call replaced the session outright, discarding
/// message keys and desynchronising both devices without any error.
#[test]
fn duplicate_establishment_is_refused_and_the_live_ratchet_keeps_working() {
    let (bob, bob_bundle) = peer_with_prekeys(140);

    let alice = fresh_core(141);
    alice.save_identity(Identity::generate()).unwrap();
    let handle: u64 = 42;

    let handshake = alice
        .establish_session_initiator(handle, bob_bundle.clone())
        .unwrap();
    bob.establish_session_responder(handle, handshake.clone())
        .unwrap();

    // Move the ratchet forward so a reset would be observable.
    let first = b"first message, advances the ratchet".to_vec();
    let ct = alice.encrypt_message(handle, first.clone()).unwrap();
    assert_eq!(bob.decrypt_message(handle, ct).unwrap(), first);

    // Second establishment for the same peer under the same handle.
    let err = alice
        .establish_session_initiator(handle, bob_bundle)
        .expect_err("re-establishing a live session must fail");
    assert!(
        matches!(err, CoreError::SessionAlreadyExists { session_id } if session_id == handle),
        "expected SessionAlreadyExists, got {err:?}"
    );

    // The original session must still be the one in place and still usable.
    let second = b"sent after the rejected duplicate".to_vec();
    let ct2 = alice.encrypt_message(handle, second.clone()).unwrap();
    assert_eq!(
        bob.decrypt_message(handle, ct2).unwrap(),
        second,
        "the surviving session must still decrypt on the peer — a silent reset would break this"
    );
}

/// Two different peers deliberately given the same local id. Real SHA-256
/// collisions are not searched for; supplying the id directly is how the
/// insertion semantics are exercised.
#[test]
fn same_handle_for_a_different_peer_is_refused_and_the_first_peer_is_untouched() {
    let (bob, bob_bundle) = peer_with_prekeys(150);
    let (_carol, carol_bundle) = peer_with_prekeys(151);

    let alice = fresh_core(152);
    alice.save_identity(Identity::generate()).unwrap();
    let handle: u64 = 77;

    let handshake = alice.establish_session_initiator(handle, bob_bundle).unwrap();
    bob.establish_session_responder(handle, handshake.clone())
        .unwrap();

    let err = alice
        .establish_session_initiator(handle, carol_bundle)
        .expect_err("a different peer must not take an occupied handle");
    assert!(
        matches!(err, CoreError::SessionIdCollision { session_id } if session_id == handle),
        "expected SessionIdCollision, got {err:?}"
    );

    // Bob's session must be exactly the one still installed.
    let msg = b"bob still owns this handle".to_vec();
    let ct = alice.encrypt_message(handle, msg.clone()).unwrap();
    assert_eq!(bob.decrypt_message(handle, ct).unwrap(), msg);
}

/// A handshake that fails must leave no ownership behind: the id stays free,
/// which `encrypt_message` reports as NoSession rather than as a session
/// belonging to someone.
#[test]
fn failed_initiator_leaves_no_session() {
    let (_bob, mut bundle) = peer_with_prekeys(160);
    // Corrupt the signed-prekey signature (v1 places it at 100..164) so the
    // bundle is structurally valid and carries a real identity, but the
    // signed-prekey object fails to verify.
    bundle[100] ^= 0xFF;

    let alice = fresh_core(161);
    alice.save_identity(Identity::generate()).unwrap();
    let handle: u64 = 88;

    let err = alice
        .establish_session_initiator(handle, bundle)
        .expect_err("a bad signature must fail the handshake");
    assert!(
        matches!(err, CoreError::BadSignedPrekeySignature),
        "expected BadSignedPrekeySignature, got {err:?}"
    );

    assert!(
        matches!(
            alice.encrypt_message(handle, b"x".to_vec()),
            Err(CoreError::NoSession { session_id }) if session_id == handle
        ),
        "a failed handshake must not leave an owned session behind"
    );
}

/// Same invariant on the responder side: failing before insertion (here,
/// because prekeys were never established) leaves the id unowned.
#[test]
fn failed_responder_leaves_no_session() {
    let (_alice_peer, alice_bundle) = peer_with_prekeys(170);
    let alice_identity_pk = alice_bundle[4..36].to_vec();

    // Bob has an identity but never called establish_prekeys, so the
    // responder path fails when it reads the missing prekey record.
    let bob = fresh_core(171);
    bob.save_identity(Identity::generate()).unwrap();
    let handle: u64 = 99;

    let err = bob
        .establish_session_responder(handle, synthetic_handshake(&alice_identity_pk))
        .expect_err("responder without prekeys must fail");
    assert!(
        matches!(err, CoreError::Storage { .. }),
        "expected Storage error from the missing prekey record, got {err:?}"
    );

    assert!(
        matches!(
            bob.encrypt_message(handle, b"x".to_vec()),
            Err(CoreError::NoSession { session_id }) if session_id == handle
        ),
        "a failed responder handshake must not leave an owned session behind"
    );
}

/// Encrypting or decrypting on an unused id must not create ownership as a
/// side effect — a later genuine handshake on that id has to succeed.
#[test]
fn encrypt_or_decrypt_before_handshake_creates_no_ownership() {
    let (bob, bob_bundle) = peer_with_prekeys(180);
    let alice = fresh_core(181);
    alice.save_identity(Identity::generate()).unwrap();
    let handle: u64 = 123;

    assert!(matches!(
        alice.encrypt_message(handle, b"x".to_vec()),
        Err(CoreError::NoSession { session_id }) if session_id == handle
    ));
    assert!(matches!(
        alice.decrypt_message(handle, vec![0u8; HEADER_SIZE + 16]),
        Err(CoreError::NoSession { session_id }) if session_id == handle
    ));

    // The id must still be free, so a real handshake now works.
    let handshake = alice
        .establish_session_initiator(handle, bob_bundle)
        .expect("the id must not have been claimed by the failed calls");
    bob.establish_session_responder(handle, handshake.clone())
        .unwrap();

    let msg = b"works after the earlier failures".to_vec();
    let ct = alice.encrypt_message(handle, msg.clone()).unwrap();
    assert_eq!(bob.decrypt_message(handle, ct).unwrap(), msg);
}

/// Two threads racing to establish the same handle on one core: the check
/// and the insertion happen under a single mutex, so exactly one wins and
/// the other is refused rather than overwriting.
#[test]
fn concurrent_duplicate_establishment_admits_exactly_one() {
    use std::sync::mpsc;
    use std::thread;

    let (_bob, bob_bundle) = peer_with_prekeys(190);
    let alice = fresh_core(191);
    alice.save_identity(Identity::generate()).unwrap();
    let handle: u64 = 4242;

    let (tx, rx) = mpsc::channel();
    let mut handles = Vec::new();
    for _ in 0..2 {
        let core = Arc::clone(&alice);
        let bundle = bob_bundle.clone();
        let tx = tx.clone();
        handles.push(thread::spawn(move || {
            tx.send(core.establish_session_initiator(handle, bundle)).unwrap();
        }));
    }
    drop(tx);
    for h in handles {
        h.join().unwrap();
    }

    let results: Vec<_> = rx.iter().collect();
    assert_eq!(results.len(), 2);
    let successes = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(successes, 1, "exactly one establishment may win the race");
    assert!(
        results.iter().any(|r| matches!(
            r,
            Err(CoreError::SessionAlreadyExists { session_id }) if *session_id == handle
        )),
        "the loser must be refused as a duplicate, not silently overwrite: {results:?}"
    );
}

// ── ARCIUM_X3DH_FORMAT_V1 ────────────────────────────────────────────────

/// Reads the persisted record straight out of the store, so a test can assert
/// on durable state instead of inferring it from later behaviour.
fn read_record(core: &ArciumCore) -> Vec<u8> {
    core.store.lock().unwrap().get(PREKEYS_KEY).unwrap()
}

fn current_opk_id(core: &ArciumCore) -> Option<u64> {
    unpack_prekeys(&read_record(core)).unwrap().opk.map(|(id, _)| id)
}

/// Whether a handshake is recorded, unauthenticated, under `handle`.
fn has_provisional(core: &ArciumCore, handle: u64) -> bool {
    let (store, messenger) = core.lock().unwrap();
    messenger.provisional_handshake(&store, handle).unwrap().is_some()
}

// ── Parsing ──────────────────────────────────────────────────────────────

#[test]
fn v1_lengths_are_exactly_as_frozen() {
    assert_eq!(PREKEY_BUNDLE_V1_LEN, 204);
    assert_eq!(INITIATOR_HANDSHAKE_V1_LEN, 84);
    assert_eq!(PREKEY_RECORD_V2_LEN, 138);
    assert_eq!(PREKEYS_KEY, "prekeys/v2");
    assert_eq!(IDENTITY_KEY, "identity/v1", "identity storage must not change");
}

/// Neighbouring lengths — including both legacy bundle sizes — must be
/// refused. 161 and 193 are the strict-cutover cases: a pre-v1 bundle is not
/// a v1 bundle, and accepting one would reopen everything v1 closes.
#[test]
fn bundle_of_any_other_length_is_rejected() {
    let (_bob, bundle) = peer_with_prekeys(200);
    let alice = fresh_core(201);
    alice.save_identity(Identity::generate()).unwrap();

    for len in [0usize, 32, 161, 193, 203, 205, 408] {
        let mut malformed = bundle.clone();
        malformed.resize(len, 0);
        let err = alice
            .establish_session_initiator(1, malformed)
            .expect_err("a wrong-length bundle must be refused");
        assert!(
            matches!(err, CoreError::InvalidPrekeyBundle { .. }),
            "expected InvalidPrekeyBundle for length {len}, got {err:?}"
        );
    }
}

#[test]
fn handshake_of_any_other_length_is_rejected() {
    let (bob, _bundle) = peer_with_prekeys(202);
    for len in [0usize, 32, 64, 83, 85, 168] {
        let err = bob
            .establish_session_responder(1, vec![0u8; len])
            .expect_err("a wrong-length handshake must be refused");
        assert!(
            matches!(err, CoreError::InvalidHandshake { .. }),
            "expected InvalidHandshake for length {len}, got {err:?}"
        );
    }
}

#[test]
fn wrong_protocol_version_or_suite_is_reported_as_unsupported() {
    let (bob, bundle) = peer_with_prekeys(203);
    let alice = fresh_core(204);
    alice.save_identity(Identity::generate()).unwrap();

    for (idx, label) in [(0usize, "version"), (1usize, "suite")] {
        let mut b = bundle.clone();
        b[idx] = 0x02;
        let err = alice.establish_session_initiator(1, b).expect_err(label);
        assert!(
            matches!(err, CoreError::UnsupportedProtocolVersion { .. }),
            "bundle {label}: expected UnsupportedProtocolVersion, got {err:?}"
        );

        let mut hs = vec![0u8; INITIATOR_HANDSHAKE_V1_LEN];
        hs[0] = PROTOCOL_VERSION;
        hs[1] = CIPHER_SUITE;
        hs[idx] = 0x02;
        let err = bob.establish_session_responder(1, hs).expect_err(label);
        assert!(
            matches!(err, CoreError::UnsupportedProtocolVersion { .. }),
            "handshake {label}: expected UnsupportedProtocolVersion, got {err:?}"
        );
    }
}

/// The reserved byte and the undefined flag bits are refused rather than
/// ignored: a future version that uses them must not be silently downgraded
/// into this one.
#[test]
fn reserved_byte_and_unknown_flag_bits_are_rejected() {
    let (bob, bundle) = peer_with_prekeys(205);
    let alice = fresh_core(206);
    alice.save_identity(Identity::generate()).unwrap();

    for (idx, value) in [(3usize, 0x01u8), (2usize, 0b1000_0001)] {
        let mut b = bundle.clone();
        b[idx] = value;
        assert!(
            matches!(
                alice.establish_session_initiator(1, b),
                Err(CoreError::InvalidPrekeyBundle { .. })
            ),
            "bundle byte {idx} = {value:#04x} must be refused"
        );

        let mut hs = vec![0u8; INITIATOR_HANDSHAKE_V1_LEN];
        hs[0] = PROTOCOL_VERSION;
        hs[1] = CIPHER_SUITE;
        hs[idx] = value;
        assert!(
            matches!(
                bob.establish_session_responder(1, hs),
                Err(CoreError::InvalidHandshake { msg }) if !msg.contains("low order")
            ),
            "handshake byte {idx} = {value:#04x} must be refused"
        );
    }
}

/// "No one-time prekey" has exactly one encoding. Leaving the tail free would
/// carry a channel inside an otherwise authentic structure.
#[test]
fn absent_one_time_prekey_must_be_all_zero() {
    let (bob, bundle) = peer_with_prekeys(207);
    let alice = fresh_core(208);
    alice.save_identity(Identity::generate()).unwrap();

    let mut b = bundle.clone();
    b[2] = 0x00; // clear has_otp but leave the tail populated
    assert!(
        matches!(
            alice.establish_session_initiator(1, b),
            Err(CoreError::InvalidPrekeyBundle { .. })
        ),
        "bundle with has_otp=0 and a non-zero tail must be refused"
    );

    let mut hs = vec![0u8; INITIATOR_HANDSHAKE_V1_LEN];
    hs[0] = PROTOCOL_VERSION;
    hs[1] = CIPHER_SUITE;
    hs[76] = 0x01; // used_otp=0 but an id is present
    assert!(
        matches!(
            bob.establish_session_responder(1, hs),
            Err(CoreError::InvalidHandshake { msg }) if !msg.contains("low order")
        ),
        "handshake with used_otp=0 and a non-zero id must be refused"
    );
}

/// R-24: a handshake whose initiator identity or ephemeral key has low
/// order is refused on receipt, as a malformed one is.
#[test]
fn handshake_with_a_low_order_key_is_rejected() {
    let (bob, _bundle) = peer_with_prekeys(214);
    let good = PublicKey::from(&StaticSecret::random_from_rng(rand_core::OsRng));
    let mut low = [0u8; 32];
    low[0] = 1; // u = 1, order 4
    for (identity, ephemeral) in [(low, good.to_bytes()), (good.to_bytes(), low), ([0u8; 32], good.to_bytes())] {
        let mut hs = vec![0u8; INITIATOR_HANDSHAKE_V1_LEN];
        hs[0] = PROTOCOL_VERSION;
        hs[1] = CIPHER_SUITE;
        hs[4..36].copy_from_slice(&identity);
        hs[36..68].copy_from_slice(&ephemeral);
        let err = bob
            .establish_session_responder(1, hs)
            .expect_err("a low-order key must be refused");
        assert!(
            matches!(&err, CoreError::InvalidHandshake { msg } if msg.contains("low order")),
            "expected InvalidHandshake (low order), got {err:?}"
        );
    }
}

/// R-24: a contact card whose X25519 identity key has low order is
/// refused when it is added, and nothing is pinned. Every session keyed
/// from it would fail X3DH, so the card could never be used.
#[test]
fn a_contact_card_with_a_low_order_identity_key_is_refused() {
    let alice = fresh_core(216);
    alice.save_identity(Identity::generate()).unwrap();
    let card = fresh_core(217);
    card.save_identity(Identity::generate()).unwrap();
    let card = card.contact_card().unwrap();
    let mut low = [0u8; 32];
    low[0] = 1; // u = 1, order 4
    for key in [low, [0u8; 32]] {
        let mut forged = card.clone();
        forged[1..33].copy_from_slice(&key);
        let err = alice
            .add_contact(forged)
            .expect_err("a low-order identity key must be refused");
        assert!(
            matches!(&err, CoreError::InvalidContactCard { msg } if msg.contains("low order")),
            "expected InvalidContactCard (low order), got {err:?}"
        );
    }
    assert!(alice.contacts().unwrap().is_empty(), "nothing is pinned");
    alice.add_contact(card).expect("the genuine card is still accepted");
    assert_eq!(alice.contacts().unwrap().len(), 1);
}

/// `hsacc:` knows a handshake by the keys it derives (option B): every
/// ephemeral key a relay can put in place of the initiator's and still
/// derive the same keys gives the same identity, checked here with a
/// real Diffie-Hellman; a fresh ephemeral key, another prekey id or no
/// one-time prekey give another.
#[test]
fn a_handshake_is_known_in_every_encoding_of_its_keys() {
    use super::tests::net_harness::same_keys_other_encodings;
    let identity_pk = PublicKey::from(&StaticSecret::random_from_rng(rand_core::OsRng));
    let ephemeral = PublicKey::from(&StaticSecret::random_from_rng(rand_core::OsRng)).to_bytes();
    let handshake = |e: [u8; 32]| InitiatorHandshakeV1 {
        identity_pk,
        ephemeral_pk: PublicKey::from(e),
        spk_id: [7; SPK_ID_LEN],
        opk_id: Some(9),
    };
    let id = handshake_identity(&handshake(ephemeral));
    for other in same_keys_other_encodings(ephemeral) {
        assert_ne!(other, ephemeral);
        let any = StaticSecret::random_from_rng(rand_core::OsRng);
        assert_eq!(
            any.diffie_hellman(&PublicKey::from(other)).as_bytes(),
            any.diffie_hellman(&PublicKey::from(ephemeral)).as_bytes(),
            "the same keys"
        );
        assert_eq!(handshake_identity(&handshake(other)), id);
    }
    let fresh = PublicKey::from(&StaticSecret::random_from_rng(rand_core::OsRng)).to_bytes();
    assert_ne!(handshake_identity(&handshake(fresh)), id);
    for change in [
        |h: &mut InitiatorHandshakeV1| h.opk_id = Some(10),
        |h: &mut InitiatorHandshakeV1| h.opk_id = None,
        |h: &mut InitiatorHandshakeV1| h.spk_id = [8; SPK_ID_LEN],
    ] {
        let mut h = handshake(ephemeral);
        change(&mut h);
        assert_ne!(handshake_identity(&h), id);
    }
}

/// R-24: a bundle whose one-time prekey has low order is refused by the
/// initiator. That field is outside the signature, so anyone on the path
/// could set it; the signature still verifies.
#[test]
fn bundle_with_a_low_order_one_time_prekey_is_rejected() {
    let (_bob, bundle) = peer_with_prekeys(215);
    let alice = fresh_core(216);
    alice.save_identity(Identity::generate()).unwrap();
    assert_eq!(bundle[2], FLAG_OTP, "the bundle carries a one-time prekey");
    let mut forged = bundle.clone();
    forged[172..204].copy_from_slice(&[0u8; 32]);
    let err = alice
        .establish_session_initiator(1, forged)
        .expect_err("a low-order one-time prekey must be refused");
    assert!(
        matches!(&err, CoreError::Handshake { msg } if msg.contains("low order")),
        "expected Handshake (low order), got {err:?}"
    );
    assert!(alice.establish_session_initiator(1, bundle).is_ok(), "the genuine bundle works");
}

// ── Signed prekey ────────────────────────────────────────────────────────

/// The F-2 closure at the FFI boundary: pairing one peer's Ed25519 signing
/// key with another's X25519 identity no longer verifies.
#[test]
fn bundle_with_substituted_identity_key_is_rejected() {
    let (_bob, bob_bundle) = peer_with_prekeys(210);
    let (_carol, carol_bundle) = peer_with_prekeys(211);
    let alice = fresh_core(212);
    alice.save_identity(Identity::generate()).unwrap();

    // Bob's bundle carrying Carol's DH identity: structurally perfect, and
    // before v1 the signature would still have verified.
    let mut forged = bob_bundle.clone();
    forged[4..36].copy_from_slice(&carol_bundle[4..36]);

    let err = alice
        .establish_session_initiator(1, forged)
        .expect_err("a mismatched identity must not verify");
    assert!(
        matches!(err, CoreError::BadSignedPrekeySignature),
        "expected BadSignedPrekeySignature, got {err:?}"
    );
}

// ── One-time prekey state machine ────────────────────────────────────────

/// The accepted path: recording the handshake consumes nothing; the
/// initiator's first message consumes the named prekey exactly once and a
/// fresh one takes its place, in the transaction that creates the session.
#[test]
fn matching_one_time_prekey_is_consumed_and_replaced() {
    let (bob, bob_bundle) = peer_with_prekeys(220);
    let alice = fresh_core(221);
    alice.save_identity(Identity::generate()).unwrap();

    let published = current_opk_id(&bob).expect("establish_prekeys publishes one");
    assert_eq!(
        u64::from_be_bytes(bob_bundle[164..172].try_into().unwrap()),
        published,
        "the bundle must advertise the id actually held"
    );

    let handshake = alice.establish_session_initiator(1, bob_bundle).unwrap();
    let before = read_record(&bob);
    bob.establish_session_responder(1, handshake).unwrap();
    assert_eq!(
        read_record(&bob),
        before,
        "an unauthenticated handshake must not consume the prekey"
    );

    // Round trip proves dh4 was actually included on both sides.
    let msg = b"through a one-time prekey".to_vec();
    let ct = alice.encrypt_message(1, msg.clone()).unwrap();
    assert_eq!(bob.decrypt_message(1, ct).unwrap(), msg);

    let replacement = current_opk_id(&bob).expect("a replacement must be published");
    assert_ne!(replacement, published, "the consumed prekey must be replaced");
}

/// Replay. The one property claimed: a handshake whose session was
/// created here names an identifier that is no longer current, so it is
/// refused — and the refusal happens before any state changes.
#[test]
fn replaying_an_accepted_handshake_is_rejected_and_changes_nothing() {
    let (bob, bob_bundle) = peer_with_prekeys(222);
    let alice = fresh_core(223);
    alice.save_identity(Identity::generate()).unwrap();

    let handshake = alice.establish_session_initiator(1, bob_bundle).unwrap();
    bob.establish_session_responder(1, handshake.clone()).unwrap();
    let first = alice.encrypt_message(1, b"first".to_vec()).unwrap();
    bob.decrypt_message(1, first).unwrap();

    let before = read_record(&bob);
    let err = bob
        .establish_session_responder(2, handshake)
        .expect_err("a replayed handshake must be refused");
    assert!(
        matches!(err, CoreError::OneTimePrekeyUnavailable { .. }),
        "expected OneTimePrekeyUnavailable, got {err:?}"
    );
    assert_eq!(read_record(&bob), before, "a refused replay must not touch the record");
    assert!(
        !has_provisional(&bob, 2),
        "a refused replay must not even be recorded"
    );

    assert!(
        matches!(
            bob.encrypt_message(2, b"x".to_vec()),
            Err(CoreError::NoSession { session_id: 2 })
        ),
        "a refused replay must leave no session"
    );
}

/// A wrong identifier must be refused *without* spending the prekey it failed
/// to name — otherwise anyone could burn prekeys by guessing.
#[test]
fn wrong_one_time_prekey_id_does_not_consume_the_current_one() {
    let (bob, bob_bundle) = peer_with_prekeys(224);
    let alice = fresh_core(225);
    alice.save_identity(Identity::generate()).unwrap();

    let mut tampered = bob_bundle.clone();
    tampered[164..172].copy_from_slice(&0xDEAD_BEEF_u64.to_be_bytes());
    // Re-sign is impossible, but the id is outside the signature, so the
    // bundle still verifies — which is exactly why the responder checks it
    // against its own record.
    let handshake = alice.establish_session_initiator(1, tampered).unwrap();

    let before = read_record(&bob);
    let err = bob
        .establish_session_responder(1, handshake)
        .expect_err("an unknown id must be refused");
    assert!(
        matches!(err, CoreError::OneTimePrekeyUnavailable { opk_id } if opk_id == 0xDEAD_BEEF),
        "expected OneTimePrekeyUnavailable{{0xDEADBEEF}}, got {err:?}"
    );
    assert_eq!(read_record(&bob), before, "the held prekey must survive untouched");
}

/// Anti-downgrade. Stripping the one-time prekey from a bundle in flight
/// leaves a signature that still verifies, so the responder — not the
/// signature — is what must refuse the weaker handshake.
#[test]
fn stripping_the_one_time_prekey_is_refused_rather_than_downgraded() {
    let (bob, bob_bundle) = peer_with_prekeys(226);
    let alice = fresh_core(227);
    alice.save_identity(Identity::generate()).unwrap();

    let mut stripped = bob_bundle.clone();
    stripped[2] = 0x00;
    stripped[164..204].fill(0);

    // Alice accepts it: the signed object does not cover these bytes.
    let handshake = alice.establish_session_initiator(1, stripped).unwrap();
    assert_eq!(handshake[2] & FLAG_OTP, 0, "Alice built an SPK-only handshake");

    let before = read_record(&bob);
    let err = bob
        .establish_session_responder(1, handshake)
        .expect_err("Bob still publishes a one-time prekey, so this must be refused");
    assert!(
        matches!(err, CoreError::OneTimePrekeyRequired),
        "expected OneTimePrekeyRequired, got {err:?}"
    );
    assert_eq!(read_record(&bob), before);
}

/// A bundle from before a rotation names a signed prekey this device no
/// longer holds, and is refused explicitly rather than deriving a key the
/// peer cannot match.
#[test]
fn stale_signed_prekey_is_rejected() {
    let (bob, old_bundle) = peer_with_prekeys(228);
    let alice = fresh_core(229);
    alice.save_identity(Identity::generate()).unwrap();

    let handshake = alice.establish_session_initiator(1, old_bundle).unwrap();
    bob.establish_prekeys().unwrap(); // rotation

    let before = read_record(&bob);
    let err = bob
        .establish_session_responder(1, handshake)
        .expect_err("a stale signed prekey must be refused");
    assert!(
        matches!(err, CoreError::StaleSignedPrekey),
        "expected StaleSignedPrekey, got {err:?}"
    );
    assert_eq!(read_record(&bob), before);
}

/// X-6. A handshake without a one-time prekey is refused also when this
/// device holds none: on that path nothing would stop an exact replay
/// (the root key re-derives identically). No normal writer produces a
/// record without a one-time prekey — `establish_prekeys` and the consume
/// path both publish one — so the record is constructed directly.
#[test]
fn a_handshake_without_a_one_time_prekey_is_refused_even_when_none_is_held() {
    let (bob, bob_bundle) = peer_with_prekeys(230);
    let alice = fresh_core(231);
    alice.save_identity(Identity::generate()).unwrap();

    // Strip the one-time prekey from Bob's stored record.
    let mut record = unpack_prekeys(&read_record(&bob)).unwrap();
    record.opk = None;
    bob.store
        .lock()
        .unwrap()
        .put(PREKEYS_KEY, &pack_prekeys(&record))
        .unwrap();
    assert!(current_opk_id(&bob).is_none());

    // Alice must also hold an SPK-only bundle, or the two sides disagree
    // about dh4 — which is the mismatch the identifiers exist to surface.
    let mut spk_only = bob_bundle.clone();
    spk_only[2] = 0x00;
    spk_only[164..204].fill(0);

    let handshake = alice.establish_session_initiator(1, spk_only).unwrap();
    assert_eq!(handshake[2] & FLAG_OTP, 0, "Alice built an SPK-only handshake");
    let before = read_record(&bob);
    for attempt in 0..2 {
        let err = bob
            .establish_session_responder(1, handshake.clone())
            .expect_err("a handshake without a one-time prekey is never answered");
        assert!(
            matches!(err, CoreError::OneTimePrekeyRequired),
            "attempt {attempt}: expected OneTimePrekeyRequired, got {err:?}"
        );
        assert_eq!(read_record(&bob), before, "the refusal must not touch the record");
        assert!(!has_provisional(&bob, 1), "attempt {attempt}: nothing is recorded");
    }
    assert!(matches!(
        bob.encrypt_message(1, b"x".to_vec()),
        Err(CoreError::NoSession { session_id: 1 })
    ));

    // And a handshake that names a one-time prekey Bob does not hold must be
    // refused as unavailable — never quietly accepted on the SPK-only path.
    // The bundle keeps Bob's real signed prekey (so spk_id matches and this
    // reaches the OPK check), but advertises a one-time prekey that exists
    // nowhere; the OPK fields sit outside the signature, so it still verifies.
    let mut phantom = bob_bundle.clone();
    phantom[2] = FLAG_OTP;
    phantom[164..172].copy_from_slice(&0x5EED_5EED_5EED_5EEDu64.to_be_bytes());
    phantom[172..204].copy_from_slice(&[0x42u8; 32]);
    // A second initiator: Alice already holds her one session with Bob,
    // and sessions are stored one per peer identity.
    let dave = fresh_core(232);
    dave.save_identity(Identity::generate()).unwrap();
    let named = dave.establish_session_initiator(2, phantom).unwrap();
    assert_eq!(named[2] & FLAG_OTP, FLAG_OTP, "Alice must have set used_otp");

    let before = read_record(&bob);
    let err = bob
        .establish_session_responder(3, named)
        .expect_err("no one-time prekey is held, so naming one must fail");
    assert!(
        matches!(err, CoreError::OneTimePrekeyUnavailable { opk_id } if opk_id == 0x5EED_5EED_5EED_5EED),
        "expected OneTimePrekeyUnavailable, got {err:?}"
    );
    assert_eq!(read_record(&bob), before, "the refusal must not touch the record");
    assert!(matches!(
        bob.encrypt_message(3, b"x".to_vec()),
        Err(CoreError::NoSession { session_id: 3 })
    ));
}

/// Whether `wire` authenticates at `core` as the first message under
/// `handshake`, with the session derived from `core`'s identity, the
/// signed prekey of `record` and `opk`: what someone holding those
/// secrets could read. Read-only.
fn first_message_opens(
    core: &ArciumCore,
    record: &PrekeyRecord,
    opk: Option<&StaticSecret>,
    handshake: &[u8],
    wire: &[u8],
) -> bool {
    let identity = core.require_identity().unwrap();
    let our = PublicKey::from(&identity.dh_key);
    let hs = unpack_initiator_handshake(handshake).unwrap();
    let session = responder_session(&identity, our, &record.signed_prekey_sk, opk, &hs).unwrap();
    let (_store, messenger) = core.lock().unwrap();
    messenger
        .first_message_authenticates(our.to_bytes(), session, wire)
        .unwrap()
}

fn held_opk(record: &PrekeyRecord) -> Option<StaticSecret> {
    record.opk.as_ref().map(|(_, sk)| sk.clone())
}

fn opk_id_of(record: &PrekeyRecord) -> Option<u64> {
    record.opk.as_ref().map(|(id, _)| *id)
}

/// R-6: the signed prekey is kept until the next round rotates it. The
/// secrets this device keeps after accepting a first contact must not
/// decrypt that contact's first message again meanwhile: its identity,
/// its signed prekey and its prekey record, with the one-time prekey
/// that replaced the used one or with none. The one-time prekey
/// the handshake used (one is required since X-6) is gone, and without
/// it the root key cannot be derived. The control shows that the check
/// does open the message with that prekey. (A first contact checked
/// only beside an own session: the next tests.)
#[test]
fn what_a_device_keeps_after_a_first_contact_does_not_read_it_again() {
    let (bob, bob_bundle) = peer_with_prekeys(233);
    let alice = fresh_core(234);
    alice.save_identity(Identity::generate()).unwrap();

    let handshake = alice.establish_session_initiator(1, bob_bundle.clone()).unwrap();
    bob.establish_session_responder(1, handshake.clone()).unwrap();
    let first = alice.encrypt_message(1, b"first contact".to_vec()).unwrap();
    let before = unpack_prekeys(&read_record(&bob)).unwrap();
    assert_eq!(bob.decrypt_message(1, first.clone()).unwrap(), b"first contact");
    let after = unpack_prekeys(&read_record(&bob)).unwrap();

    assert_eq!(
        after.signed_prekey_pk(),
        before.signed_prekey_pk(),
        "a promotion does not rotate the signed prekey; the next maintenance does (E)"
    );
    assert!(opk_id_of(&after).is_some(), "a new one-time prekey is published");
    assert_ne!(opk_id_of(&after), opk_id_of(&before), "the used one-time prekey is replaced");

    let opens = |record: &PrekeyRecord, opk: Option<StaticSecret>| {
        first_message_opens(&bob, record, opk.as_ref(), &handshake, &first)
    };
    assert!(
        opens(&before, held_opk(&before)),
        "control: the one-time prekey it used opens the first message"
    );
    assert!(
        !opens(&after, held_opk(&after)),
        "what is kept, with the new one-time prekey, must not open it"
    );
    assert!(
        !opens(&after, None),
        "what is kept, without a one-time prekey, must not open it"
    );

    // Nor is the signed prekey the session's own ratchet key any more:
    // the first message moved it on (Bob's reply names his new one).
    let reply = bob.encrypt_message(1, b"reply".to_vec()).unwrap();
    assert_ne!(
        reply[..32],
        bob_bundle[68..100],
        "the session no longer uses the signed prekey"
    );
}

/// Alice and Bob start sessions with each other at once; each holds an
/// unconfirmed session of its own. Alice records Bob's handshake beside
/// hers, and Bob's first message authenticates there (read with Alice's
/// one-time prekey, never accepted). Bob gives his session up and
/// accepts Alice's, as the conflict resolution does.
struct SimultaneousStart {
    alice: Arc<ArciumCore>,
    bob: Arc<ArciumCore>,
    bob_hs: Vec<u8>,
    bob_first: Vec<u8>,
    /// Bob's answer under Alice's session, which confirms it at Alice.
    bob_answer: Vec<u8>,
}

fn simultaneous_start(seed: u8) -> SimultaneousStart {
    let (alice, alice_bundle) = peer_with_prekeys(seed);
    let (bob, bob_bundle) = peer_with_prekeys(seed + 1);
    let alice_hs = alice.establish_session_initiator(1, bob_bundle.clone()).unwrap();
    let bob_hs = bob.establish_session_initiator(1, alice_bundle).unwrap();

    alice.record_handshake_beside(1, &bob_hs).unwrap();
    let bob_first = bob.encrypt_message(1, b"under bob's session".to_vec()).unwrap();
    let bob_pk: [u8; 32] = bob_bundle[4..36].try_into().unwrap();
    assert!(
        alice.beside_authenticates(1, &bob_pk, &bob_first).unwrap(),
        "Bob's first message authenticates beside Alice's session"
    );

    for m in bob.pending_outgoing(1).unwrap() {
        bob.abandon_outgoing(1, m.message_id).unwrap();
    }
    bob.remove_session(1).unwrap();
    bob.establish_session_responder(1, alice_hs).unwrap();
    let alice_first = alice.encrypt_message(1, b"under alice's session".to_vec()).unwrap();
    bob.decrypt_message(1, alice_first).unwrap();
    let bob_answer = bob.encrypt_message(1, b"answer".to_vec()).unwrap();
    SimultaneousStart {
        alice,
        bob,
        bob_hs,
        bob_first,
        bob_answer,
    }
}

/// R-6 at a simultaneous start (above). When Bob's answer confirms
/// Alice's session, the handshake beside it goes, and with it, in the
/// same transaction, the one-time prekey it named: Alice's kept secrets
/// no longer read the first message Bob gave up. The control shows that
/// they did before.
#[test]
fn a_one_time_prekey_read_beside_a_session_that_wins_is_replaced() {
    let s = simultaneous_start(237);
    let (alice, _bob) = (&s.alice, &s.bob);
    let before = unpack_prekeys(&read_record(alice)).unwrap();
    assert!(
        first_message_opens(alice, &before, held_opk(&before).as_ref(), &s.bob_hs, &s.bob_first),
        "control: before the confirmation, what Alice keeps reads Bob's first message"
    );

    assert_eq!(alice.decrypt_message(1, s.bob_answer.clone()).unwrap(), b"answer");
    assert!(!has_provisional(alice, 1), "the handshake beside the session is gone");
    let after = unpack_prekeys(&read_record(alice)).unwrap();
    assert_eq!(after.signed_prekey_pk(), before.signed_prekey_pk());
    assert!(opk_id_of(&after).is_some(), "a new one-time prekey is published");
    assert_ne!(opk_id_of(&after), opk_id_of(&before), "the one Bob's handshake named is replaced");
    for opk in [held_opk(&after), None] {
        assert!(
            !first_message_opens(alice, &after, opk.as_ref(), &s.bob_hs, &s.bob_first),
            "what Alice keeps no longer reads Bob's given-up first message"
        );
    }
    // The session goes on.
    let next = s.bob.encrypt_message(1, b"next".to_vec()).unwrap();
    assert_eq!(alice.decrypt_message(1, next).unwrap(), b"next");
}

/// The one-time prekey is replaced by every confirmation of an own
/// initiator session (option B), also when the handshake beside it names
/// a prekey another contact's first message already consumed, and by
/// nothing else: not by a receive on a responder session, nor by a later
/// receive on the confirmed session.
#[test]
fn a_confirmation_of_an_own_session_replaces_the_prekey_and_nothing_else_does() {
    let s = simultaneous_start(239);
    let alice = &s.alice;
    let carol = fresh_core(241);
    carol.save_identity(Identity::generate()).unwrap();
    // The bundle Bob used names the same one-time prekey.
    let bundle = alice.export_prekey_bundle().unwrap();
    let carol_hs = carol.establish_session_initiator(2, bundle).unwrap();
    alice.establish_session_responder(2, carol_hs).unwrap();
    let carol_first = carol.encrypt_message(2, b"carol".to_vec()).unwrap();
    let named = current_opk_id(alice);
    alice.decrypt_message(2, carol_first).unwrap();
    let after_carol = current_opk_id(alice);
    assert_ne!(after_carol, named, "Carol's first message consumed it");

    assert_eq!(alice.decrypt_message(1, s.bob_answer.clone()).unwrap(), b"answer");
    assert!(!has_provisional(alice, 1));
    let confirmed = current_opk_id(alice);
    assert!(confirmed.is_some());
    assert_ne!(confirmed, after_carol, "the confirmation replaced it all the same");

    let before = read_record(alice);
    // Alice's session with Carol is a responder session.
    let to_carol = alice.encrypt_message(2, b"to carol".to_vec()).unwrap();
    carol.decrypt_message(2, to_carol).unwrap();
    let carol_reply = carol.encrypt_message(2, b"reply".to_vec()).unwrap();
    alice.decrypt_message(2, carol_reply).unwrap();
    // And Bob's next message on the confirmed session.
    let next = s.bob.encrypt_message(1, b"next".to_vec()).unwrap();
    alice.decrypt_message(1, next).unwrap();
    assert_eq!(read_record(alice), before, "no other receive replaces it");
}

// ── Atomicity ────────────────────────────────────────────────────────────

/// Two cores on one database receive the same valid first message at
/// the same time, for one recorded handshake. The session is created once,
/// the one-time prekey is consumed once, and the loser reports the
/// winner's acceptance as a duplicate instead of creating a second session
/// or a second acceptance.
#[test]
fn concurrent_first_messages_create_one_session_and_consume_the_prekey_once() {
    use std::sync::mpsc;
    use std::thread;

    let path = tempdir().unwrap().keep().join("db").to_str().unwrap().to_string();
    let bob = ArciumCore::new(path.clone(), key32(240)).unwrap();
    bob.save_identity(Identity::generate()).unwrap();
    bob.establish_prekeys().unwrap();
    let alice = fresh_core(241);
    alice.save_identity(Identity::generate()).unwrap();

    let published = current_opk_id(&bob).unwrap();
    let handshake = alice
        .establish_session_initiator(1, bob.export_prekey_bundle().unwrap())
        .unwrap();
    bob.establish_session_responder(10, handshake).unwrap();
    let first = alice.encrypt_message(1, b"first".to_vec()).unwrap();

    // Separate connections, released together by the barrier, so each
    // reads the provisional handshake and the prekeys before either
    // commits.
    let gate = Arc::new(std::sync::Barrier::new(2));
    let (tx, rx) = mpsc::channel();
    let mut joins = Vec::new();
    for _ in 0..2 {
        let core = ArciumCore::new(path.clone(), key32(240)).unwrap();
        let (wire, tx, gate) = (first.clone(), tx.clone(), Arc::clone(&gate));
        joins.push(thread::spawn(move || {
            gate.wait();
            tx.send(core.receive_message(10, wire)).unwrap();
        }));
    }
    drop(tx);
    for j in joins {
        j.join().unwrap();
    }

    let results: Vec<_> = rx.iter().collect();
    let accepted = results
        .iter()
        .filter(|r| matches!(r, Ok(ReceiveResult::Accepted { .. })))
        .count();
    assert_eq!(accepted, 1, "exactly one acceptance: {results:?}");
    for r in &results {
        assert!(
            matches!(
                r,
                Ok(ReceiveResult::Accepted { .. } | ReceiveResult::Duplicate { .. })
                    | Err(CoreError::Storage { .. })
            ),
            "the loser is a duplicate or a busy store, never a second session: {results:?}"
        );
    }
    let after = current_opk_id(&bob).unwrap();
    assert_ne!(after, published, "the durable state must have advanced");
    assert_eq!(bob.pending_incoming(10).unwrap().len(), 1, "accepted once");
    assert!(!has_provisional(&bob, 10));
    // A retry of a busy loser is a duplicate too, and changes nothing more.
    assert!(matches!(
        bob.receive_message(10, first).unwrap(),
        ReceiveResult::Duplicate { .. }
    ));
    assert_eq!(current_opk_id(&bob).unwrap(), after);
}

/// A handshake refused because the handle already belongs to another
/// peer's authenticated session consumes nothing and records nothing:
/// only an authenticated first message spends a one-time prekey.
#[test]
fn a_refused_handshake_consumes_no_prekey() {
    let (bob, first_bundle) = peer_with_prekeys(242);
    let alice = fresh_core(243);
    alice.save_identity(Identity::generate()).unwrap();

    // Occupy the handle with an authenticated session first.
    let hs1 = alice.establish_session_initiator(1, first_bundle).unwrap();
    bob.establish_session_responder(7, hs1).unwrap();
    let m = alice.encrypt_message(1, b"first".to_vec()).unwrap();
    bob.decrypt_message(7, m).unwrap();

    // A second, different initiator aims at the same handle.
    let second_bundle = bob.export_prekey_bundle().unwrap();
    let carol = fresh_core(244);
    carol.save_identity(Identity::generate()).unwrap();
    let hs2 = carol.establish_session_initiator(1, second_bundle).unwrap();

    let before = read_record(&bob);
    let err = bob
        .establish_session_responder(7, hs2)
        .expect_err("the handle is taken by a different peer");
    assert!(
        matches!(err, CoreError::SessionIdCollision { session_id: 7 }),
        "expected SessionIdCollision, got {err:?}"
    );
    assert_eq!(read_record(&bob), before, "nothing was consumed");
    assert!(!has_provisional(&bob, 7), "nothing was recorded");
}

mod responder;
mod ack_probe;
mod cancel_text;
mod chat;
mod delete_contact;
mod durable;
mod net_harness;
mod network;
mod network_crash;
mod delivery_consistency;
mod first_contact;
mod net_limits;
mod send_refusal;
mod history_paging;
mod net_peer;
mod legacy_upgrade;
mod mailbox_scan;
mod debug_redaction;
mod outgoing;
mod identity;
mod unresolved;
mod false_conflict;
mod restart;
mod prekey_record;
mod spk_rotation;
mod relay_v2;
mod relay_onion;
mod beyond_recall;
mod far_skip;
mod rollback;
