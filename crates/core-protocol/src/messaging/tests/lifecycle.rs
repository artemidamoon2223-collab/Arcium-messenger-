//! Session lifecycle: which obligations block removal, what survives it, and
//! what a replacement session can and cannot inherit.

use super::*;

/// A new matching session pair for the identities of `p`.
fn replacement(p: &Peers) -> (Session, Session) {
    let fresh = pair();
    let mut ad = p.alice_pk.to_vec();
    ad.extend_from_slice(&p.bob_pk);
    let alice = Session {
        ad: ad.clone(),
        peer_identity_pk: p.bob_pk,
        ..fresh.alice
    };
    let bob = Session {
        ad,
        peer_identity_pk: p.alice_pk,
        ..fresh.bob
    };
    (alice, bob)
}

fn remove_alice(p: &mut Peers) -> Result<(), MessagingError> {
    p.am.remove_session(&mut p.a, p.alice_pk, ALICE_HANDLE)
}

fn remove_bob(p: &mut Peers) -> Result<(), MessagingError> {
    p.bm.remove_session(&mut p.b, p.bob_pk, BOB_HANDLE)
}

fn recreate_alice(p: &mut Peers, s: Session) -> Result<(), MessagingError> {
    let mut ns = new_session(ALICE_HANDLE, s, SessionRole::Initiator);
    ns.initial_outbound = Some(b"handshake 2".to_vec());
    p.am.create_session(&mut p.a, p.alice_pk, ns)
}

fn send(p: &mut Peers, cid: &[u8], m: &[u8]) -> SendOutcome {
    p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, cid, m)
        .unwrap()
}

fn keys(store: &EncryptedStore, prefix: &str) -> usize {
    store.list_keys_with_prefix(prefix).unwrap().len()
}

/// Scenarios 1 and 9: pending outgoing messages block removal until each is
/// acknowledged or explicitly abandoned; afterwards their logical ids keep
/// their outcome, and the new session inherits no message or acknowledgement.
#[test]
fn pending_outgoing_blocks_removal_until_acknowledged_or_abandoned() {
    let mut p = memory_peers();
    let m1 = new_message(send(&mut p, b"L1", b"one"));
    let m2 = new_message(send(&mut p, b"L2", b"two"));
    assert!(matches!(
        remove_alice(&mut p),
        Err(MessagingError::PendingOutgoing { count: 2 })
    ));
    assert_eq!(generation(&mut p.a, p.alice_pk, ALICE_HANDLE), 2);
    assert_eq!(keys(&p.a, "outbox:"), 2);

    assert!(p
        .am
        .acknowledge_outgoing(&mut p.a, ALICE_HANDLE, &m1.message_id)
        .unwrap());
    assert!(matches!(
        remove_alice(&mut p),
        Err(MessagingError::PendingOutgoing { count: 1 })
    ));
    assert!(p
        .am
        .abandon_outgoing(&mut p.a, ALICE_HANDLE, &m2.message_id)
        .unwrap());
    assert!(!p
        .am
        .abandon_outgoing(&mut p.a, ALICE_HANDLE, &m2.message_id)
        .unwrap());
    assert!(!p
        .am
        .abandon_outgoing(&mut p.a, ALICE_HANDLE, &m1.message_id)
        .unwrap());
    // Acknowledging an abandoned message claims nothing either.
    assert!(!p
        .am
        .acknowledge_outgoing(&mut p.a, ALICE_HANDLE, &m2.message_id)
        .unwrap());
    remove_alice(&mut p).unwrap();
    assert_eq!(
        keys(&p.a, "session:") + keys(&p.a, "handle:") + keys(&p.a, "outbox:"),
        0
    );

    let (s2, _) = replacement(&p);
    recreate_alice(&mut p, s2).unwrap();
    // Neither logical message is encrypted again under the new session.
    let gen = generation(&mut p.a, p.alice_pk, ALICE_HANDLE);
    assert_eq!(
        send(&mut p, b"L1", b"one"),
        SendOutcome::AlreadyAcknowledged {
            message_id: m1.message_id
        }
    );
    assert_eq!(
        send(&mut p, b"L2", b"two"),
        SendOutcome::Abandoned {
            message_id: m2.message_id
        }
    );
    assert_eq!(generation(&mut p.a, p.alice_pk, ALICE_HANDLE), gen);
    assert!(p
        .am
        .pending_outgoing(&p.a, ALICE_HANDLE)
        .unwrap()
        .is_empty());
    for old in [&m1.message_id, &m2.message_id] {
        assert!(!p
            .am
            .acknowledge_outgoing(&mut p.a, ALICE_HANDLE, old)
            .unwrap());
        assert!(!p.am.abandon_outgoing(&mut p.a, ALICE_HANDLE, old).unwrap());
        assert!(matches!(
            p.am.acknowledge_incoming(&mut p.a, ALICE_HANDLE, old),
            Err(MessagingError::UnknownMessage)
        ));
    }
    let fresh = new_message(send(&mut p, b"L3", b"three"));
    assert_eq!(fresh.generation, 1);
}

/// Scenario 2: once a session has committed a message from the peer, the
/// peer holds it too, and it is never removed — with or without undelivered
/// incoming messages, on either side.
#[test]
fn an_established_session_is_not_removed() {
    let mut p = memory_peers();
    let m = p.alice_sends(b"unread");
    let got = accepted(p.bob_receives(&m.wire).unwrap());
    assert!(matches!(
        remove_bob(&mut p),
        Err(MessagingError::SessionEstablished)
    ));
    assert_eq!(p.bm.pending_incoming(&p.b, BOB_HANDLE).unwrap().len(), 1);
    p.bm.acknowledge_incoming(&mut p.b, BOB_HANDLE, &got.message_id)
        .unwrap();
    assert!(matches!(
        remove_bob(&mut p),
        Err(MessagingError::SessionEstablished)
    ));

    p.am.acknowledge_outgoing(&mut p.a, ALICE_HANDLE, &m.message_id)
        .unwrap();
    let reply = p.bob_sends(b"reply");
    accepted(p.alice_receives(&reply.wire).unwrap());
    assert!(matches!(
        remove_alice(&mut p),
        Err(MessagingError::SessionEstablished)
    ));
    assert_eq!(generation(&mut p.b, p.bob_pk, BOB_HANDLE), 2);
}

/// CX-B: a logical message the peer accepted is never accepted again through
/// a replacement session.
#[test]
fn a_logical_message_is_never_accepted_under_two_sessions() {
    let mut p = memory_peers();
    let m = new_message(send(&mut p, b"L", b"pay 10"));
    let got = accepted(p.bob_receives(&m.wire).unwrap());
    p.bm.acknowledge_incoming(&mut p.b, BOB_HANDLE, &got.message_id)
        .unwrap();
    // No transport acknowledgement reached Alice. She gives up on the
    // message and replaces the session; Bob keeps his.
    p.am.abandon_outgoing(&mut p.a, ALICE_HANDLE, &m.message_id)
        .unwrap();
    remove_alice(&mut p).unwrap();
    let (s2a, s2b) = replacement(&p);
    recreate_alice(&mut p, s2a).unwrap();
    assert!(matches!(
        p.bm.create_session(
            &mut p.b,
            p.bob_pk,
            new_session(7, s2b, SessionRole::Responder)
        ),
        Err(MessagingError::AlreadyExists { .. })
    ));
    assert_eq!(
        send(&mut p, b"L", b"pay 10"),
        SendOutcome::Abandoned {
            message_id: m.message_id
        }
    );
    // Even content sent anew under a new logical id cannot reach Bob's
    // application through the refused session.
    let again = new_message(send(&mut p, b"L-resent", b"pay 10"));
    assert!(matches!(
        p.bob_receives(&again.wire),
        Err(MessagingError::Ratchet(_))
    ));
    assert_eq!(generation(&mut p.b, p.bob_pk, BOB_HANDLE), 1);
}

/// Scenarios 3 and 4: the stored handshake of an unconfirmed session goes
/// only with the session, and a refused handshake is replaced after a
/// restart.
#[test]
fn a_refused_handshake_is_replaced_after_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.db");
    let mut p = setup(
        EncryptedStore::open(&path, KEY).unwrap(),
        EncryptedStore::open_in_memory(KEY).unwrap(),
    );
    remove_alice(&mut p).unwrap();
    let (s1, _) = replacement(&p);
    recreate_alice(&mut p, s1).unwrap();
    let m = new_message(send(&mut p, b"first", b"hi"));
    // The peer refused the handshake; the process restarts.
    p.a = EncryptedStore::open(&path, KEY).unwrap();
    p.am = Messenger::new();
    assert_eq!(
        p.am.initial_outbound(&p.a, ALICE_HANDLE).unwrap(),
        Some(b"handshake 2".to_vec())
    );
    assert!(matches!(
        remove_alice(&mut p),
        Err(MessagingError::PendingOutgoing { count: 1 })
    ));
    assert_eq!(keys(&p.a, "hsout:"), 1);
    p.am.abandon_outgoing(&mut p.a, ALICE_HANDLE, &m.message_id)
        .unwrap();
    remove_alice(&mut p).unwrap();
    assert_eq!(keys(&p.a, "hsout:"), 0);
    let (s2a, s2b) = replacement(&p);
    recreate_alice(&mut p, s2a).unwrap();
    let mut b = EncryptedStore::open_in_memory(KEY).unwrap();
    let mut bm = Messenger::new();
    bm.create_session(
        &mut b,
        p.bob_pk,
        new_session(BOB_HANDLE, s2b, SessionRole::Responder),
    )
    .unwrap();
    let hi = new_message(send(&mut p, b"first-again", b"hi"));
    assert_eq!(
        *accepted(bm.receive(&mut b, p.bob_pk, BOB_HANDLE, &hi.wire).unwrap()).plaintext,
        b"hi"
    );
}

/// Scenarios 5 and 8: a handshake whose delivery is unknown. Locally it is
/// indistinguishable from a refused one, so Alice may replace it; a peer that
/// did accept it refuses the replacement, and old messages from either
/// session never pass as messages of the other.
#[test]
fn replacing_a_handshake_the_peer_accepted_forks_nothing() {
    let mut p = memory_peers();
    let m = new_message(send(&mut p, b"L", b"to S1"));
    accepted(p.bob_receives(&m.wire).unwrap());
    p.am.acknowledge_outgoing(&mut p.a, ALICE_HANDLE, &m.message_id)
        .unwrap();
    let late = p.bob_sends(b"from S1, arriving late");
    remove_alice(&mut p).unwrap();
    let (s2a, s2b) = replacement(&p);
    recreate_alice(&mut p, s2a).unwrap();
    assert!(matches!(
        p.bm.create_session(
            &mut p.b,
            p.bob_pk,
            new_session(7, s2b, SessionRole::Responder)
        ),
        Err(MessagingError::AlreadyExists { .. })
    ));
    let gen = generation(&mut p.a, p.alice_pk, ALICE_HANDLE);
    assert!(matches!(
        p.alice_receives(&late.wire),
        Err(MessagingError::Ratchet(_))
    ));
    assert_eq!(generation(&mut p.a, p.alice_pk, ALICE_HANDLE), gen);
    assert_eq!(keys(&p.a, "inbox:"), 0);

    // The other direction: an unconfirmed responder session replaced, and a
    // message of the old one delivered afterwards.
    let mut q = memory_peers();
    let old = q.alice_sends(b"of the old session");
    remove_bob(&mut q).unwrap();
    let (_, s2b) = replacement(&q);
    q.bm.create_session(
        &mut q.b,
        q.bob_pk,
        new_session(BOB_HANDLE, s2b, SessionRole::Responder),
    )
    .unwrap();
    assert!(matches!(
        q.bob_receives(&old.wire),
        Err(MessagingError::Ratchet(_))
    ));
    assert_eq!(generation(&mut q.b, q.bob_pk, BOB_HANDLE), 0);
    assert_eq!(keys(&q.b, "inbox:") + keys(&q.b, "seen:"), 0);
}

/// CX-A, scenario 6: a send staged from a session that another connection
/// then removes and replaces commits nothing over the replacement.
#[test]
fn a_stale_send_never_overwrites_a_replacement_session() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.db");
    let mut p = setup(
        EncryptedStore::open(&path, KEY).unwrap(),
        EncryptedStore::open_in_memory(KEY).unwrap(),
    );
    let (s2a, s2b) = replacement(&p);
    let (alice_pk, other) = (p.alice_pk, path.clone());
    crate::messaging::race_hook::set(move || {
        let mut db = EncryptedStore::open(&other, KEY).unwrap();
        let mut m = Messenger::new();
        m.remove_session(&mut db, alice_pk, ALICE_HANDLE).unwrap();
        let mut ns = new_session(ALICE_HANDLE, s2a, SessionRole::Initiator);
        ns.initial_outbound = Some(b"handshake 2".to_vec());
        m.create_session(&mut db, alice_pk, ns).unwrap();
    });
    assert!(matches!(
        p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, b"stale", b"from S1"),
        Err(MessagingError::Conflict(Conflict::Superseded))
    ));
    assert_eq!(keys(&p.a, "outbox:") + keys(&p.a, "sendid:"), 0);
    assert_eq!(generation(&mut p.a, p.alice_pk, ALICE_HANDLE), 0);
    // The replacement is intact: its peer reads Alice's next message.
    let mut b = EncryptedStore::open_in_memory(KEY).unwrap();
    let mut bm = Messenger::new();
    bm.create_session(
        &mut b,
        p.bob_pk,
        new_session(BOB_HANDLE, s2b, SessionRole::Responder),
    )
    .unwrap();
    let m = new_message(send(&mut p, b"fresh", b"on S2"));
    assert_eq!(
        *accepted(bm.receive(&mut b, p.bob_pk, BOB_HANDLE, &m.wire).unwrap()).plaintext,
        b"on S2"
    );
}

/// Scenario 6: a send or a receive committed by another connection between
/// the removal's checks and its transaction makes the removal refuse and
/// delete nothing.
#[test]
fn removal_refuses_if_a_send_or_receive_commits_meanwhile() {
    for racing_receive in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.db");
        let mut p = setup(
            EncryptedStore::open(&path, KEY).unwrap(),
            EncryptedStore::open_in_memory(KEY).unwrap(),
        );
        let m = p.alice_sends(b"hello");
        accepted(p.bob_receives(&m.wire).unwrap());
        p.am.acknowledge_outgoing(&mut p.a, ALICE_HANDLE, &m.message_id)
            .unwrap();
        let reply = p.bob_sends(b"reply");
        let (alice_pk, other) = (p.alice_pk, path.clone());
        crate::messaging::race_hook::set(move || {
            let mut db = EncryptedStore::open(&other, KEY).unwrap();
            let mut m = Messenger::new();
            if racing_receive {
                accepted(
                    m.receive(&mut db, alice_pk, ALICE_HANDLE, &reply.wire)
                        .unwrap(),
                );
            } else {
                m.send(
                    &mut db,
                    alice_pk,
                    ALICE_HANDLE,
                    b"racing",
                    b"sent meanwhile",
                )
                .unwrap();
            }
        });
        assert!(matches!(
            remove_alice(&mut p),
            Err(MessagingError::Conflict(Conflict::RecordChanged))
        ));
        assert_eq!(p.am.peer_of(&p.a, ALICE_HANDLE).unwrap(), Some(p.bob_pk));
        let (inbox, outbox) = (keys(&p.a, "inbox:"), keys(&p.a, "outbox:"));
        assert_eq!(
            (inbox, outbox),
            if racing_receive { (1, 0) } else { (0, 1) }
        );
        assert_eq!(generation(&mut p.a, p.alice_pk, ALICE_HANDLE), 2);
    }
}

/// Scenario 6: an acknowledgement and an abandonment of one message on two
/// connections settle it exactly once, and its logical id agrees.
#[test]
fn acknowledging_and_abandoning_one_message_concurrently_settle_it_once() {
    for _ in 0..8 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.db");
        let mut p = setup(
            EncryptedStore::open(&path, KEY).unwrap(),
            EncryptedStore::open_in_memory(KEY).unwrap(),
        );
        let id = new_message(send(&mut p, b"L", b"x")).message_id;
        let barrier = Arc::new(Barrier::new(2));
        let threads: Vec<_> = [false, true]
            .into_iter()
            .map(|abandon| {
                let (path, barrier) = (path.clone(), barrier.clone());
                std::thread::spawn(move || {
                    let mut db = EncryptedStore::open(&path, KEY).unwrap();
                    let m = Messenger::new();
                    barrier.wait();
                    let won = if abandon {
                        m.abandon_outgoing(&mut db, ALICE_HANDLE, &id)
                    } else {
                        m.acknowledge_outgoing(&mut db, ALICE_HANDLE, &id)
                    };
                    (abandon, won.unwrap())
                })
            })
            .collect();
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        let winners: Vec<_> = results.iter().filter(|r| r.1).collect();
        assert_eq!(winners.len(), 1, "{results:?}");
        let expected = if winners[0].0 {
            SendOutcome::Abandoned { message_id: id }
        } else {
            SendOutcome::AlreadyAcknowledged { message_id: id }
        };
        assert_eq!(send(&mut p, b"L", b"x"), expected);
    }
}

/// Scenario 10: removal waits for an unknown commit outcome to be resolved,
/// and then applies the same rules to what the commit left.
#[test]
fn removal_after_an_unknown_outcome_waits_for_recovery() {
    for fault in [CommitFault::UnknownStored, CommitFault::UnknownLost] {
        let mut p = memory_peers();
        test_hooks::inject(fault);
        assert!(matches!(
            p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, b"U", b"maybe"),
            Err(MessagingError::OutcomeUnknown { .. })
        ));
        assert!(matches!(
            remove_alice(&mut p),
            Err(MessagingError::Unresolved {
                attempted_generation: 1
            })
        ));
        assert_eq!(p.am.peer_of(&p.a, ALICE_HANDLE).unwrap(), Some(p.bob_pk));
        let r =
            p.am.recover(&mut p.a, p.alice_pk, ALICE_HANDLE)
                .unwrap()
                .unwrap();
        if matches!(fault, CommitFault::UnknownStored) {
            assert!(r.artifact_committed);
            assert!(matches!(
                remove_alice(&mut p),
                Err(MessagingError::PendingOutgoing { count: 1 })
            ));
            let id = p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap()[0].message_id;
            p.am.abandon_outgoing(&mut p.a, ALICE_HANDLE, &id).unwrap();
        } else {
            assert!(!r.artifact_committed);
        }
        remove_alice(&mut p).unwrap();
    }
}

/// The removal's own commit: an unknown outcome is reported as such, and
/// repeating the call tells which way it went. A definite failure removes
/// nothing.
#[test]
fn an_unknown_removal_outcome_is_resolved_by_repeating_it() {
    for (fault, took_effect) in [
        (CommitFault::UnknownStored, true),
        (CommitFault::UnknownLost, false),
    ] {
        let mut p = memory_peers();
        test_hooks::inject(fault);
        assert!(matches!(
            remove_alice(&mut p),
            Err(MessagingError::RepeatableOutcomeUnknown(_))
        ));
        match remove_alice(&mut p) {
            Err(MessagingError::NoSession { .. }) => assert!(took_effect),
            Ok(()) => assert!(!took_effect),
            other => panic!("{other:?}"),
        }
    }
    let mut p = memory_peers();
    test_hooks::inject(CommitFault::NotCommitted);
    assert!(matches!(
        remove_alice(&mut p),
        Err(MessagingError::NotCommitted(_))
    ));
    assert_eq!(generation(&mut p.a, p.alice_pk, ALICE_HANDLE), 0);
}

/// A session record that cannot be read is never removed: whether it holds
/// obligations cannot be decided.
#[test]
fn an_unreadable_session_is_not_removed() {
    let mut p = memory_peers();
    let key = session_storage_key(&p.bob_pk);
    p.a.put(&key, b"garbage").unwrap();
    assert!(matches!(
        remove_alice(&mut p),
        Err(MessagingError::InvalidSession(_))
    ));
    assert_eq!(p.a.get(&key).unwrap(), b"garbage");
    assert_eq!(p.am.peer_of(&p.a, ALICE_HANDLE).unwrap(), Some(p.bob_pk));
    assert!(matches!(
        p.am.remove_session(&mut p.a, p.alice_pk, 999),
        Err(MessagingError::NoSession { .. })
    ));
}
