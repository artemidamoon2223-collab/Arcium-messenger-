//! Adversarial acceptance tests: repeated logical sends, cross-session
//! isolation, and bounded listing of acknowledged history.

use super::*;

fn send_cid(p: &mut Peers, cid: &[u8], m: &[u8]) -> SendOutcome {
    p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, cid, m)
        .unwrap()
}

// ── D1: one logical message, one ciphertext ───────────────────────────────────

#[test]
fn a_repeated_send_of_one_logical_message_encrypts_once() {
    let mut p = memory_peers();
    let first = new_message(send_cid(&mut p, b"logical-1", b"hello"));
    let gen = generation(&mut p.a, p.alice_pk, ALICE_HANDLE);
    // The repeat returns the stored message byte for byte; its plaintext is
    // ignored and nothing is encrypted.
    assert_eq!(
        send_cid(&mut p, b"logical-1", b"something else"),
        SendOutcome::AlreadyPending(first.clone())
    );
    assert_eq!(generation(&mut p.a, p.alice_pk, ALICE_HANDLE), gen);
    assert_eq!(
        p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap(),
        vec![first.clone()]
    );
    assert_eq!(first.client_message_id, b"logical-1");

    assert!(matches!(
        p.bob_receives(&first.wire).unwrap(),
        Received::Accepted(_)
    ));
    p.am.acknowledge_outgoing(&mut p.a, ALICE_HANDLE, &first.message_id)
        .unwrap();
    assert_eq!(
        send_cid(&mut p, b"logical-1", b"hello"),
        SendOutcome::AlreadyAcknowledged {
            message_id: first.message_id
        }
    );
    assert_eq!(generation(&mut p.a, p.alice_pk, ALICE_HANDLE), gen);
}

#[test]
fn client_message_ids_must_be_1_to_64_bytes() {
    let mut p = memory_peers();
    for bad in [vec![], vec![7u8; MAX_CLIENT_MESSAGE_ID_LEN + 1]] {
        assert!(matches!(
            p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, &bad, b"x"),
            Err(MessagingError::InvalidClientMessageId)
        ));
    }
    assert!(matches!(
        send_cid(&mut p, &[7u8; MAX_CLIENT_MESSAGE_ID_LEN], b"x"),
        SendOutcome::Sent(_)
    ));
    assert_eq!(generation(&mut p.a, p.alice_pk, ALICE_HANDLE), 1);
}

/// Two connections send the same logical message concurrently: exactly one
/// ciphertext exists for it, and the peer accepts it once.
#[test]
fn concurrent_sends_of_one_logical_message_produce_one_ciphertext() {
    for _ in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.db");
        let mut p = setup(
            EncryptedStore::open(&path, KEY).unwrap(),
            EncryptedStore::open_in_memory(KEY).unwrap(),
        );
        let alice_pk = p.alice_pk;
        let barrier = Arc::new(Barrier::new(3));
        let threads: Vec<_> = (0..3)
            .map(|_| {
                let (path, barrier) = (path.clone(), barrier.clone());
                std::thread::spawn(move || {
                    let mut db = EncryptedStore::open(&path, KEY).unwrap();
                    let mut m = Messenger::new();
                    barrier.wait();
                    // A caller that sees a conflict simply asks again.
                    loop {
                        match m.send(&mut db, alice_pk, ALICE_HANDLE, b"same", b"once") {
                            Ok(o) => return o,
                            Err(MessagingError::Conflict(_) | MessagingError::NotCommitted(_)) => {}
                            Err(e) => panic!("{e:?}"),
                        }
                    }
                })
            })
            .collect();
        let outcomes: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        let sent: Vec<_> = outcomes
            .iter()
            .filter(|o| matches!(o, SendOutcome::Sent(_)))
            .collect();
        assert_eq!(sent.len(), 1, "{outcomes:?}");
        let SendOutcome::Sent(m) = sent[0] else {
            unreachable!()
        };
        for o in &outcomes {
            if let SendOutcome::AlreadyPending(x) = o {
                assert_eq!(x, m);
            }
        }
        assert_eq!(
            p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap(),
            vec![m.clone()]
        );
        assert!(matches!(
            p.bob_receives(&m.wire).unwrap(),
            Received::Accepted(_)
        ));
    }
}

/// After an unknown commit outcome, recovering and repeating the same
/// logical send never yields a second ciphertext, whichever way the commit
/// went.
#[test]
fn repeating_a_send_after_an_unknown_outcome_does_not_duplicate_it() {
    for fault in [CommitFault::UnknownStored, CommitFault::UnknownLost] {
        let mut p = memory_peers();
        test_hooks::inject(fault);
        assert!(matches!(
            p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, b"L", b"maybe"),
            Err(MessagingError::OutcomeUnknown { .. })
        ));
        p.am.recover(&mut p.a, p.alice_pk, ALICE_HANDLE).unwrap();
        let m = match send_cid(&mut p, b"L", b"maybe") {
            SendOutcome::AlreadyPending(m) => {
                assert!(matches!(fault, CommitFault::UnknownStored));
                m
            }
            SendOutcome::Sent(m) => {
                assert!(matches!(fault, CommitFault::UnknownLost));
                m
            }
            other => panic!("{other:?}"),
        };
        assert_eq!(
            p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap(),
            vec![m.clone()]
        );
        assert_eq!(
            *accepted(p.bob_receives(&m.wire).unwrap()).plaintext,
            b"maybe"
        );
    }
}

// ── D3: acknowledged history is not listed ────────────────────────────────────

#[test]
fn acknowledged_history_is_not_scanned_and_still_detects_duplicates() {
    let mut p = memory_peers();
    let mut wires = Vec::new();
    for i in 0..200u16 {
        let m = p.alice_sends(&i.to_be_bytes());
        let id = accepted(p.bob_receives(&m.wire).unwrap()).message_id;
        assert!(p
            .bm
            .acknowledge_incoming(&mut p.b, BOB_HANDLE, &id)
            .unwrap());
        p.am.acknowledge_outgoing(&mut p.a, ALICE_HANDLE, &m.message_id)
            .unwrap();
        wires.push(m.wire);
    }
    // Nothing pending, and nothing left in the listed namespaces.
    assert!(p.b.list_keys_with_prefix("inbox:").unwrap().is_empty());
    assert!(p.a.list_keys_with_prefix("outbox:").unwrap().is_empty());
    let gen = generation(&mut p.b, p.bob_pk, BOB_HANDLE);
    for w in [&wires[0], &wires[199]] {
        assert!(matches!(
            p.bob_receives(w).unwrap(),
            Received::Duplicate {
                undelivered: None,
                ..
            }
        ));
    }
    assert_eq!(generation(&mut p.b, p.bob_pk, BOB_HANDLE), gen);
    // A repeated acknowledgement is harmless.
    let id = message_id(&wires[5]);
    assert!(!p
        .bm
        .acknowledge_incoming(&mut p.b, BOB_HANDLE, &id)
        .unwrap());
}

// ── Q5: sessions are isolated ─────────────────────────────────────────────────

#[test]
fn one_sessions_message_ids_do_not_reach_another_session() {
    // Bob talks to Alice (BOB_HANDLE) and to Carol (handle 77).
    let mut p = memory_peers();
    let carol_pair = pair();
    let carol_pk = carol_pair.alice_pk;
    let mut bob_side = carol_pair.bob;
    // Rebind Carol's session to Bob's real identity.
    let mut ad = carol_pk.to_vec();
    ad.extend_from_slice(&p.bob_pk);
    bob_side.ad = ad.clone();
    let mut carol_session = carol_pair.alice;
    carol_session.ad = ad;
    carol_session.peer_identity_pk = p.bob_pk;
    p.bm.create_session(
        &mut p.b,
        p.bob_pk,
        new_session(77, bob_side, SessionRole::Responder),
    )
    .unwrap();
    let mut c = EncryptedStore::open_in_memory(KEY).unwrap();
    let mut cm = Messenger::new();
    cm.create_session(
        &mut c,
        carol_pk,
        new_session(1, carol_session, SessionRole::Initiator),
    )
    .unwrap();

    let from_carol = new_message(cm.send(&mut c, carol_pk, 1, b"c1", b"from carol").unwrap());
    let got = accepted(
        p.bm.receive(&mut p.b, p.bob_pk, 77, &from_carol.wire)
            .unwrap(),
    );
    // Carol's message cannot be acknowledged, or received, through Alice's session.
    assert!(matches!(
        p.bm.acknowledge_incoming(&mut p.b, BOB_HANDLE, &got.message_id),
        Err(MessagingError::UnknownMessage)
    ));
    assert!(matches!(
        p.bob_receives(&from_carol.wire),
        Err(MessagingError::Ratchet(_))
    ));
    assert_eq!(p.bm.pending_incoming(&p.b, 77).unwrap(), vec![got]);
    assert!(p.bm.pending_incoming(&p.b, BOB_HANDLE).unwrap().is_empty());
    // A client id used with Carol is independent of the same id with Alice.
    assert!(matches!(
        p.bm.send(&mut p.b, p.bob_pk, BOB_HANDLE, b"c1", b"to alice"),
        Err(MessagingError::Ratchet(_)) // Bob cannot send before Alice's first message
    ));
}
