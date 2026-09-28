//! Responder sessions stored by builds before ARCIUM-SESSION-CONFIRMATION-001
//! (`legacy.rs`): the classifier, the atomic retirement, what blocks it,
//! competing instances, simulated commit faults and the recovery of a
//! receive staged on a retired session. Real process deaths are in
//! `crash.rs`; databases written by the old build itself are exercised in
//! `mobile-ffi` (`tests::legacy_upgrade`).
//!
//! `setup()` stores Bob's responder session with `create_session`, exactly
//! as the old build did on receipt of a handshake: generation 0, the
//! ratchet as `DoubleRatchet::init_bob` left it, and the handle record.

use std::collections::BTreeMap;

use super::*;
use crate::checkpoint::encode_session_checkpoint;
use crate::durable::Conflict;

const PREKEYS: &str = "prekeys/v2";
/// Every namespace these tests write, plus unrelated application data.
const NAMESPACES: [&str; 9] = [
    "session:", "handle:", "hsin:", "hsout:", "outbox:", "inbox:", "seen:", "sendid:", "app:",
];

/// Every record in `store`, by key.
fn snapshot(store: &EncryptedStore) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for ns in NAMESPACES {
        for key in store.list_keys_with_prefix(ns).unwrap() {
            let value = store.get(&key).unwrap();
            out.insert(key, value);
        }
    }
    if let Ok(v) = store.get(PREKEYS) {
        out.insert(PREKEYS.into(), v);
    }
    out
}

/// Alice's initiator session and Bob's legacy responder session from the
/// same X3DH result, Bob's prekey record, and history the retirement must
/// leave alone: a seen and a send-id record for Alice, application data,
/// and Carol's own session with Bob.
fn legacy(a: EncryptedStore, b: EncryptedStore) -> Peers {
    let mut p = setup(a, b);
    p.b.put(PREKEYS, b"current").unwrap();
    p.b.put(&seen_key(&p.alice_pk, &[1; 32]), &encode_id_record(SEEN_MAGIC, &[1; 32]))
        .unwrap();
    p.b.put(
        &sendid_key(&p.alice_pk, b"old"),
        &encode_id_record(ABANDONED_MAGIC, &[2; 32]),
    )
    .unwrap();
    p.b.put("app:v1/queued-text", b"still queued").unwrap();
    let carol = pair();
    let mut carol_session = new_session(0xCA201, carol.bob, SessionRole::Responder);
    carol_session.session.ad = [carol.alice_pk, p.bob_pk].concat();
    p.bm.create_session(&mut p.b, p.bob_pk, carol_session).unwrap();
    p
}

fn memory_legacy() -> Peers {
    legacy(
        EncryptedStore::open_in_memory(KEY).unwrap(),
        EncryptedStore::open_in_memory(KEY).unwrap(),
    )
}

fn hs(peer: &[u8; 32], bytes: &[u8]) -> ProvisionalHandshake {
    ProvisionalHandshake {
        peer_identity_pk: *peer,
        handshake: bytes.to_vec(),
    }
}

/// Records `h` as `mobile-ffi` does: against the prekey record as it stands.
fn record(
    m: &Messenger,
    db: &mut EncryptedStore,
    our: [u8; 32],
    handle: u64,
    h: &ProvisionalHandshake,
) -> Result<(), MessagingError> {
    let validated = ValidatedRecord {
        key: PREKEYS.into(),
        value: Zeroizing::new(db.get(PREKEYS).unwrap()),
    };
    m.record_provisional_handshake(db, our, handle, h, &validated)
}

impl Peers {
    fn record(&mut self, h: &[u8]) -> Result<(), MessagingError> {
        record(&self.bm, &mut self.b, self.bob_pk, BOB_HANDLE, &hs(&self.alice_pk, h))
    }

    fn is_legacy(&mut self) -> bool {
        self.bm
            .is_legacy_unconfirmed(&mut self.b, self.bob_pk, BOB_HANDLE)
            .unwrap()
    }

    fn alice_key(&self) -> String {
        session_storage_key(&self.alice_pk)
    }

    /// `before` with Alice's session and Bob's handle for her replaced by
    /// the provisional handshake `h`: all a retirement may change.
    fn retired(&self, before: &BTreeMap<String, Vec<u8>>, h: &[u8]) -> BTreeMap<String, Vec<u8>> {
        let mut want = before.clone();
        want.remove(&self.alice_key()).unwrap();
        want.remove(&handle_key(BOB_HANDLE)).unwrap();
        let recorded = encode_provisional(&hs(&self.alice_pk, h)).unwrap();
        want.insert(provisional_key(BOB_HANDLE), recorded.to_vec());
        want
    }

    /// Writes `session` over Alice's record at Bob, as `role` at `generation`.
    fn store_crafted(&mut self, session: &Session, role: SessionRole, generation: u64) {
        let record = encode_session_checkpoint(session, role, &self.bob_pk, generation).unwrap();
        self.b.put(&self.alice_key(), &record).unwrap();
    }
}

/// A new X3DH result for the same two identities: what the responder
/// derives from a second, genuine handshake.
fn second_pair(alice_pk: [u8; 32], bob_pk: [u8; 32]) -> (Session, Session) {
    let ad = [alice_pk, bob_pk].concat();
    let spk = StaticSecret::random_from_rng(OsRng);
    let root = [0x5A; 32];
    (
        Session {
            ratchet: DoubleRatchet::init_alice(&root, PublicKey::from(&spk)),
            ad: ad.clone(),
            peer_identity_pk: bob_pk,
        },
        Session {
            ratchet: DoubleRatchet::init_bob(&root, spk),
            ad,
            peer_identity_pk: alice_pk,
        },
    )
}

// ── The classifier ────────────────────────────────────────────────────────

#[test]
fn only_the_untouched_old_responder_shape_is_legacy_unconfirmed() {
    let mut p = memory_legacy();
    assert!(p.is_legacy());
    // Alice's initiator session at generation 0 is not.
    assert!(!p
        .am
        .is_legacy_unconfirmed(&mut p.a, p.alice_pk, ALICE_HANDLE)
        .unwrap());
    // No session, and a session under another peer's handle, are not.
    assert!(!p.bm.is_legacy_unconfirmed(&mut p.b, p.bob_pk, 7).unwrap());
    // Bound to another local identity: never eligible.
    let stranger = pair().bob_pk;
    assert!(!p
        .bm
        .is_legacy_unconfirmed(&mut p.b, stranger, BOB_HANDLE)
        .unwrap());

    // One authenticated message ends it.
    let m = p.alice_sends(b"hi");
    accepted(p.bob_receives(&m.wire).unwrap());
    assert!(!p.is_legacy());
}

/// Each shape that differs from the old responder's in one respect is
/// refused, and refusing writes nothing.
#[test]
fn every_other_shape_keeps_its_session_and_changes_nothing() {
    type Craft = fn(&mut Peers);
    let cases: [(&str, Craft); 6] = [
        ("initiator role, generation 0", |p| {
            let s = pair();
            let session = Session {
                ratchet: s.bob.ratchet,
                ad: [p.bob_pk, p.alice_pk].concat(),
                peer_identity_pk: p.alice_pk,
            };
            p.store_crafted(&session, SessionRole::Initiator, 0);
        }),
        ("responder with a receiving chain", |p| {
            let m = p.alice_sends(b"hi");
            accepted(p.bob_receives(&m.wire).unwrap());
            let (session, _) = p.bm.load(&mut p.b, p.bob_pk, BOB_HANDLE).unwrap();
            assert!(session.has_received());
        }),
        ("responder with a receiving chain, stored at generation 0", |p| {
            let (mut alice, bob) = second_pair(p.alice_pk, p.bob_pk);
            let mut bob = bob;
            let (h, c) = alice.ratchet.encrypt(b"x", &alice.ad).unwrap();
            bob.ratchet.decrypt(&h, &c, &bob.ad).unwrap();
            p.store_crafted(&bob, SessionRole::Responder, 0);
        }),
        ("responder with a sending chain but no receiving chain", |p| {
            let (alice, _) = second_pair(p.alice_pk, p.bob_pk);
            let session = Session {
                ratchet: alice.ratchet,
                ad: [p.alice_pk, p.bob_pk].concat(),
                peer_identity_pk: p.alice_pk,
            };
            p.store_crafted(&session, SessionRole::Responder, 0);
        }),
        ("initial responder ratchet at generation 5", |p| {
            let (_, bob) = second_pair(p.alice_pk, p.bob_pk);
            p.store_crafted(&bob, SessionRole::Responder, 5);
        }),
        ("corrupt session record", |p| {
            let key = p.alice_key();
            p.b.put(&key, b"not a checkpoint").unwrap();
        }),
    ];
    for (name, craft) in cases {
        let mut p = memory_legacy();
        craft(&mut p);
        assert!(!p.is_legacy(), "{name}: classified as legacy");
        let before = snapshot(&p.b);
        assert!(
            matches!(p.record(b"hs2"), Err(MessagingError::AlreadyExists { .. })),
            "{name}: not refused"
        );
        assert_eq!(snapshot(&p.b), before, "{name}: something changed");
    }
}

#[test]
fn a_session_bound_to_another_local_identity_is_never_retired() {
    let mut p = memory_legacy();
    let before = snapshot(&p.b);
    let stranger = pair().bob_pk;
    assert!(matches!(
        record(&p.bm, &mut p.b, stranger, BOB_HANDLE, &hs(&p.alice_pk, b"hs2")),
        Err(MessagingError::AlreadyExists { .. })
    ));
    assert_eq!(snapshot(&p.b), before);
}

#[test]
fn a_handle_of_another_peer_or_another_handle_for_the_peer_is_refused() {
    let mut p = memory_legacy();
    let before = snapshot(&p.b);
    // Bob's handle for Alice named with Carol's handshake.
    let carol = pair().alice_pk;
    assert!(matches!(
        record(&p.bm, &mut p.b, p.bob_pk, BOB_HANDLE, &hs(&carol, b"hs")),
        Err(MessagingError::HandleCollision { .. })
    ));
    // Alice's handshake under a handle that is not the one her session has.
    assert!(matches!(
        record(&p.bm, &mut p.b, p.bob_pk, 7, &hs(&p.alice_pk, b"hs")),
        Err(MessagingError::AlreadyExists { .. })
    ));
    assert_eq!(snapshot(&p.b), before);
}

// ── The retirement ────────────────────────────────────────────────────────

/// The whole compatibility path: the old session is replaced by the new
/// handshake in one transaction that touches nothing else; the new
/// handshake then becomes a session only through its authenticated first
/// message, and the conversation works both ways.
#[test]
fn a_legacy_session_is_retired_into_the_new_handshake_and_nothing_else_changes() {
    let mut p = memory_legacy();
    let before = snapshot(&p.b);
    p.record(b"hs2").unwrap();
    assert_eq!(snapshot(&p.b), p.retired(&before, b"hs2"));
    assert_eq!(p.bm.peer_of(&p.b, BOB_HANDLE).unwrap(), None, "no authority");
    // Recording it again changes nothing; a newer one replaces it.
    p.record(b"hs2").unwrap();
    assert_eq!(snapshot(&p.b), p.retired(&before, b"hs2"));
    p.record(b"hs3").unwrap();
    assert_eq!(snapshot(&p.b), p.retired(&before, b"hs3"));

    // The initiator of hs3 (Alice, with a new session of her own).
    let (alice2, bob2) = second_pair(p.alice_pk, p.bob_pk);
    let mut a2 = EncryptedStore::open_in_memory(KEY).unwrap();
    let mut am2 = Messenger::new();
    am2.create_session(&mut a2, p.alice_pk, new_session(ALICE_HANDLE, alice2, SessionRole::Initiator))
        .unwrap();
    let m1 = am2
        .send(&mut a2, p.alice_pk, ALICE_HANDLE, &cid(), b"first")
        .map(new_message)
        .unwrap();
    let first = FirstContact {
        handle: BOB_HANDLE,
        session: bob2,
        provisional: hs(&p.alice_pk, b"hs3"),
        extra: vec![SideWrite::replace(
            PREKEYS.into(),
            Zeroizing::new(b"current".to_vec()),
            Zeroizing::new(b"rotated".to_vec()),
        )
        .unwrap()],
    };
    let got = accepted(
        p.bm.accept_first_message(&mut p.b, p.bob_pk, first, &m1.wire)
            .unwrap(),
    );
    assert_eq!((got.generation, &**got.plaintext), (1, &b"first"[..]));
    assert!(p.bm.has_received(&mut p.b, p.bob_pk, BOB_HANDLE).unwrap());
    assert!(!p.is_legacy());
    assert_eq!(p.b.get(PREKEYS).unwrap(), b"rotated");

    let reply = p
        .bm
        .send(&mut p.b, p.bob_pk, BOB_HANDLE, &cid(), b"reply")
        .map(new_message)
        .unwrap();
    assert_eq!(
        *accepted(am2.receive(&mut a2, p.alice_pk, ALICE_HANDLE, &reply.wire).unwrap()).plaintext,
        b"reply"
    );

    // History and everything unrelated survived all of it.
    let after = snapshot(&p.b);
    for key in [
        seen_key(&p.alice_pk, &[1; 32]),
        sendid_key(&p.alice_pk, b"old"),
        "app:v1/queued-text".to_string(),
        handle_key(0xCA201),
    ] {
        assert_eq!(after.get(&key), before.get(&key), "{key}");
    }
    // A message of the retired session no longer authenticates anywhere.
    let old = p.alice_sends(b"old session");
    assert!(p.bob_receives(&old.wire).is_err());
}

#[test]
fn an_old_responder_cannot_encrypt_before_its_first_receive() {
    let mut p = memory_legacy();
    let before = snapshot(&p.b);
    assert!(matches!(
        p.bm.send(&mut p.b, p.bob_pk, BOB_HANDLE, &cid(), b"x"),
        Err(MessagingError::Ratchet(RatchetError::NotInitialized))
    ));
    assert_eq!(snapshot(&p.b), before, "no outbox, no send id, no new state");
    assert!(p.is_legacy());
}

/// A message of the old session's own handshake still completes it the
/// ordinary way, after which no handshake replaces it.
#[test]
fn the_old_handshakes_first_message_still_completes_the_old_session() {
    let mut p = memory_legacy();
    let m = p.alice_sends(b"late but genuine");
    assert_eq!(
        *accepted(p.bob_receives(&m.wire).unwrap()).plaintext,
        b"late but genuine"
    );
    let before = snapshot(&p.b);
    assert!(matches!(p.record(b"hs2"), Err(MessagingError::AlreadyExists { .. })));
    assert_eq!(snapshot(&p.b), before);
}

// ── Obligations ───────────────────────────────────────────────────────────

/// A legacy-shaped session beside state it never produces is kept, and
/// nothing is abandoned to make it eligible.
#[test]
fn obligations_beside_a_legacy_session_keep_it() {
    type Add = fn(&mut Peers);
    let cases: [(&str, Add, &str); 4] = [
        (
            "pending outgoing",
            |p| {
                let key = outbox_key(&p.alice_pk, &message_id(b"w"));
                let rec = encode_outbox(1, &message_id(b"w"), b"c", b"w");
                p.b.put(&key, &rec).unwrap();
            },
            "pending outgoing messages",
        ),
        (
            "pending incoming",
            |p| {
                let key = inbox_key(&p.alice_pk, &[3; 32]);
                p.b.put(&key, &encode_inbox(1, &[3; 32], b"text")).unwrap();
            },
            "pending incoming messages",
        ),
        (
            "stored initiator handshake",
            |p| p.b.put(&handshake_key(&p.alice_pk), b"ours").unwrap(),
            "an initiator handshake is stored",
        ),
        (
            "provisional handshake already recorded",
            |p| {
                let rec = encode_provisional(&hs(&p.alice_pk, b"hs0")).unwrap();
                p.b.put(&provisional_key(BOB_HANDLE), &rec).unwrap();
            },
            "a provisional handshake is already recorded",
        ),
    ];
    for (name, add, reason) in cases {
        let mut p = memory_legacy();
        add(&mut p);
        assert!(p.is_legacy(), "{name}: the session itself is legacy-shaped");
        let before = snapshot(&p.b);
        match p.record(b"hs2") {
            Err(MessagingError::SessionNotRetirable(r)) => assert_eq!(r, reason, "{name}"),
            other => panic!("{name}: expected a refusal, got {other:?}"),
        }
        assert_eq!(snapshot(&p.b), before, "{name}: something changed");
    }
}

#[test]
fn an_authenticated_responder_with_pending_messages_is_never_retired() {
    let mut p = memory_legacy();
    let m = p.alice_sends(b"hi");
    accepted(p.bob_receives(&m.wire).unwrap());
    p.bob_sends(b"reply pending");
    let before = snapshot(&p.b);
    assert!(matches!(p.record(b"hs2"), Err(MessagingError::AlreadyExists { .. })));
    assert_eq!(snapshot(&p.b), before);
    assert_eq!(p.bm.pending_outgoing(&p.b, BOB_HANDLE).unwrap().len(), 1);
}

#[test]
fn an_unresolved_commit_in_this_instance_blocks_the_retirement() {
    let mut p = memory_legacy();
    let m = p.alice_sends(b"maybe");
    test_hooks::inject(CommitFault::UnknownLost);
    assert!(matches!(
        p.bob_receives(&m.wire),
        Err(MessagingError::OutcomeUnknown { .. })
    ));
    let before = snapshot(&p.b);
    assert!(matches!(p.record(b"hs2"), Err(MessagingError::Unresolved { .. })));
    assert_eq!(snapshot(&p.b), before);
}

#[test]
fn prekeys_changed_since_validation_block_the_retirement() {
    let mut p = memory_legacy();
    let validated = ValidatedRecord {
        key: PREKEYS.into(),
        value: Zeroizing::new(b"what the handshake was checked against".to_vec()),
    };
    let before = snapshot(&p.b);
    assert!(matches!(
        p.bm.record_provisional_handshake(
            &mut p.b,
            p.bob_pk,
            BOB_HANDLE,
            &hs(&p.alice_pk, b"hs2"),
            &validated
        ),
        Err(MessagingError::Conflict(Conflict::RecordChanged))
    ));
    assert_eq!(snapshot(&p.b), before);
}

// ── Competing instances ───────────────────────────────────────────────────

fn file_legacy(dir: &Path) -> Peers {
    legacy(
        EncryptedStore::open(dir.join("a.db"), KEY).unwrap(),
        EncryptedStore::open(dir.join("b.db"), KEY).unwrap(),
    )
}

/// A inspects the legacy session; B then authenticates a message on it and
/// commits. A's retirement fails and B's state is untouched.
#[test]
fn a_retirement_staged_before_another_instance_received_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = file_legacy(dir.path());
    let m = p.alice_sends(b"genuine");
    let (path, bob_pk, wire) = (dir.path().join("b.db"), p.bob_pk, m.wire.clone());
    crate::messaging::race_hook::set(move || {
        let mut db = EncryptedStore::open(&path, KEY).unwrap();
        let got = Messenger::new()
            .receive(&mut db, bob_pk, BOB_HANDLE, &wire)
            .unwrap();
        assert_eq!(*accepted(got).plaintext, b"genuine");
    });
    assert!(matches!(
        p.record(b"hs2"),
        Err(MessagingError::Conflict(Conflict::RecordChanged))
    ));
    let after = snapshot(&p.b);
    assert_eq!(generation(&mut p.b, p.bob_pk, BOB_HANDLE), 1);
    assert!(!after.contains_key(&provisional_key(BOB_HANDLE)));
    let pending = p.bm.pending_incoming(&p.b, BOB_HANDLE).unwrap();
    assert_eq!(*pending[0].plaintext, b"genuine");
    // B's session keeps working.
    let next = p.alice_sends(b"next");
    assert_eq!(*accepted(p.bob_receives(&next.wire).unwrap()).plaintext, b"next");
}

/// B stages a receive on the legacy session; A retires it first. B's commit
/// writes nothing and releases no plaintext.
#[test]
fn a_receive_staged_before_another_instance_retired_the_session_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = file_legacy(dir.path());
    let m = p.alice_sends(b"never shown");
    let (path, bob_pk, alice_pk) = (dir.path().join("b.db"), p.bob_pk, p.alice_pk);
    crate::messaging::race_hook::set(move || {
        let mut db = EncryptedStore::open(&path, KEY).unwrap();
        record(&Messenger::new(), &mut db, bob_pk, BOB_HANDLE, &hs(&alice_pk, b"hs2")).unwrap();
    });
    let before = snapshot(&p.b);
    match p.bob_receives(&m.wire) {
        Err(MessagingError::Conflict(Conflict::RecordMissing)) => {}
        other => panic!("expected a conflict, got {other:?}"),
    }
    assert_eq!(snapshot(&p.b), p.retired(&before, b"hs2"));
    assert!(p.bm.unresolved_generation(BOB_HANDLE).is_none());
}

// ── Commit faults ─────────────────────────────────────────────────────────

#[test]
fn a_retirement_with_an_unknown_or_failed_commit_is_whole_or_absent_and_repeatable() {
    for fault in [
        CommitFault::NotCommitted,
        CommitFault::UnknownLost,
        CommitFault::UnknownStored,
    ] {
        let mut p = memory_legacy();
        let before = snapshot(&p.b);
        test_hooks::inject(fault);
        let r = p.record(b"hs2");
        let now = snapshot(&p.b);
        match fault {
            CommitFault::NotCommitted => {
                assert!(matches!(r, Err(MessagingError::NotCommitted(_))));
                assert_eq!(now, before);
            }
            CommitFault::UnknownLost => {
                assert!(matches!(r, Err(MessagingError::RepeatableOutcomeUnknown(_))));
                assert_eq!(now, before);
            }
            CommitFault::UnknownStored => {
                assert!(matches!(r, Err(MessagingError::RepeatableOutcomeUnknown(_))));
                assert_eq!(now, p.retired(&before, b"hs2"));
            }
        }
        // Repeating the call completes it, or recognises it completed.
        p.record(b"hs2").unwrap();
        assert_eq!(snapshot(&p.b), p.retired(&before, b"hs2"), "{fault:?}");
    }
}

// ── A receive left unresolved on a session retired since ──────────────────

/// B's receive on the legacy session reports an unknown outcome but was
/// rolled back; A then retires the session. B's recovery reads the
/// retirement and the absence of the receive's records, and clears.
#[test]
fn a_receive_rolled_back_on_a_retired_session_is_recovered() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = file_legacy(dir.path());
    let m = p.alice_sends(b"lost");
    test_hooks::inject(CommitFault::UnknownLost);
    assert!(matches!(
        p.bob_receives(&m.wire),
        Err(MessagingError::OutcomeUnknown { attempted_generation: 1, .. })
    ));
    let mut other = EncryptedStore::open(dir.path().join("b.db"), KEY).unwrap();
    record(&Messenger::new(), &mut other, p.bob_pk, BOB_HANDLE, &hs(&p.alice_pk, b"hs2")).unwrap();

    let rec = p.bm.recover(&mut p.b, p.bob_pk, BOB_HANDLE).unwrap().unwrap();
    assert_eq!(
        rec,
        Recovery {
            attempted_generation: 1,
            stored_generation: 0,
            artifact_committed: false
        }
    );
    assert_eq!(p.bm.unresolved_generation(BOB_HANDLE), None);
    assert_eq!(
        p.bm.provisional_handshake(&p.b, BOB_HANDLE).unwrap(),
        Some(hs(&p.alice_pk, b"hs2"))
    );
}

/// Anything short of that reading keeps the handle unresolved.
#[test]
fn a_retired_session_alone_does_not_resolve_an_unknown_receive() {
    type Disturb = fn(&mut EncryptedStore, &Peers, &[u8]);
    let cases: [(&str, Disturb); 3] = [
        ("the receive's inbox record exists", |db, p, wire| {
            let id = message_id(wire);
            db.put(&inbox_key(&p.alice_pk, &id), &encode_inbox(1, &id, b"x"))
                .unwrap();
        }),
        ("no provisional handshake is recorded", |db, _, _| {
            db.delete(&provisional_key(BOB_HANDLE)).unwrap();
        }),
        ("the provisional handshake names another peer", |db, _, _| {
            let rec = encode_provisional(&hs(&pair().alice_pk, b"x")).unwrap();
            db.put(&provisional_key(BOB_HANDLE), &rec).unwrap();
        }),
    ];
    for (name, disturb) in cases {
        let dir = tempfile::tempdir().unwrap();
        let mut p = file_legacy(dir.path());
        let m = p.alice_sends(b"lost");
        test_hooks::inject(CommitFault::UnknownLost);
        assert!(p.bob_receives(&m.wire).is_err());
        let mut other = EncryptedStore::open(dir.path().join("b.db"), KEY).unwrap();
        record(&Messenger::new(), &mut other, p.bob_pk, BOB_HANDLE, &hs(&p.alice_pk, b"hs2"))
            .unwrap();
        disturb(&mut other, &p, &m.wire);
        assert!(
            p.bm.recover(&mut p.b, p.bob_pk, BOB_HANDLE).is_err(),
            "{name}: recovered"
        );
        assert_eq!(p.bm.unresolved_generation(BOB_HANDLE), Some(1), "{name}");
    }
}

/// The recovery is limited to receives staged on a legacy session: any
/// other unresolved operation whose session disappeared stays unresolved.
#[test]
fn a_missing_session_never_resolves_other_unknown_operations() {
    let mut p = memory_legacy();
    let m = p.alice_sends(b"hi");
    accepted(p.bob_receives(&m.wire).unwrap());
    let next = p.alice_sends(b"maybe");
    test_hooks::inject(CommitFault::UnknownLost);
    assert!(p.bob_receives(&next.wire).is_err());
    // Removed behind this instance's back, with a provisional record put in
    // place — exactly what a retirement would leave.
    let key = p.alice_key();
    p.b.delete(&key).unwrap();
    p.b.delete(&handle_key(BOB_HANDLE)).unwrap();
    let rec = encode_provisional(&hs(&p.alice_pk, b"hs2")).unwrap();
    p.b.put(&provisional_key(BOB_HANDLE), &rec).unwrap();
    assert!(p.bm.recover(&mut p.b, p.bob_pk, BOB_HANDLE).is_err());
    assert_eq!(p.bm.unresolved_generation(BOB_HANDLE), Some(2));
}

/// The unknown receive did commit: the session then has a receiving chain,
/// is not retired, and the ordinary recovery reports it.
#[test]
fn a_receive_that_did_commit_blocks_the_retirement_and_recovers_normally() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = file_legacy(dir.path());
    let m = p.alice_sends(b"stored");
    test_hooks::inject(CommitFault::UnknownStored);
    assert!(p.bob_receives(&m.wire).is_err());
    let mut other = EncryptedStore::open(dir.path().join("b.db"), KEY).unwrap();
    assert!(matches!(
        record(&Messenger::new(), &mut other, p.bob_pk, BOB_HANDLE, &hs(&p.alice_pk, b"hs2")),
        Err(MessagingError::AlreadyExists { .. })
    ));
    let rec = p.bm.recover(&mut p.b, p.bob_pk, BOB_HANDLE).unwrap().unwrap();
    assert_eq!((rec.stored_generation, rec.artifact_committed), (1, true));
}
