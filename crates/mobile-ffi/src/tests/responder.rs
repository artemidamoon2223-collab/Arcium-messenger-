//! The responder lifecycle (ARCIUM-SESSION-CONFIRMATION-001): a received
//! handshake is only provisional and has no authority; the session is
//! created when the initiator's first message authenticates under it.
//!
//! Every peer here is a legitimate protocol peer driven through the FFI.
//! No handshake is forged: the handshakes a responder must not treat as
//! authoritative are ordinary ones whose first message never arrives, is
//! damaged, or belongs to another session.

use super::net_harness::*;
use super::*;
use crate::network::chat::ChatSessionState;
use crate::network::wire::Envelope;

/// Nothing listens here: these devices never touch the network.
const NO_RELAY: &str = "127.0.0.1:9";

/// Alice and Bob, pinned to each other, Bob with prekeys.
fn pair() -> (Device, Device) {
    let (alice, bob) = (Device::new(NO_RELAY, 1), Device::new(NO_RELAY, 2));
    alice.knows(&bob);
    bob.knows(&alice);
    bob.core.establish_prekeys().unwrap();
    (alice, bob)
}

/// `of`'s handle in the other device's store.
fn handle(of: &Device) -> u64 {
    local_session_handle(of.pk.clone()).unwrap()
}

/// `from` starts a session with `to` from `to`'s current bundle.
fn handshake(from: &Device, to: &Device) -> Vec<u8> {
    from.core
        .establish_session_initiator(handle(to), to.core.export_prekey_bundle().unwrap())
        .unwrap()
}

/// `from`'s next message to `to`, committed on `from`'s side.
fn says(from: &Device, to: &Device, id: &[u8], text: &[u8]) -> OutgoingMessage {
    match from
        .core
        .send_message(handle(to), id.to_vec(), text.to_vec())
        .unwrap()
    {
        SendResult::Sent { message } => message,
        other => panic!("expected a new message, got {other:?}"),
    }
}

fn accepted(r: Result<ReceiveResult, CoreError>) -> IncomingMessage {
    match r {
        Ok(ReceiveResult::Accepted { message }) => message,
        other => panic!("expected a new message, got {other:?}"),
    }
}

fn keys(d: &Device, namespace: &str) -> usize {
    d.core
        .store
        .lock()
        .unwrap()
        .list_keys_with_prefix(namespace)
        .unwrap()
        .len()
}

/// The one stored session record, byte for byte.
fn session_record(d: &Device) -> Vec<u8> {
    let store = d.core.store.lock().unwrap();
    let keys = store.list_keys_with_prefix("session:").unwrap();
    assert_eq!(keys.len(), 1);
    store.get(&keys[0]).unwrap()
}

fn provisional(d: &Device, handle: u64) -> Option<Vec<u8>> {
    let (store, messenger) = d.core.lock().unwrap();
    messenger
        .provisional_handshake(&store, handle)
        .unwrap()
        .map(|p| p.handshake)
}

/// Whether a message from the peer has authenticated under the session.
fn confirmed(d: &Device, handle: u64) -> bool {
    let our = d.core.our_identity_pk().unwrap();
    let (mut store, messenger) = d.core.lock().unwrap();
    messenger.has_received(&mut store, our, handle).unwrap()
}

fn state(d: &Device, with: &Device) -> ChatSessionState {
    d.net.conversation(with.pk.clone()).unwrap().session
}

/// 1, 2: the handshake is recorded and nothing else. No session, no handle,
/// no consumed prekey, and nothing reports a session.
#[test]
fn a_received_handshake_is_provisional_and_has_no_authority() {
    let (alice, bob) = pair();
    let h = handle(&alice);
    let prekeys = read_record(&bob.core);
    bob.core
        .establish_session_responder(h, handshake(&alice, &bob))
        .unwrap();

    assert_eq!(
        (
            keys(&bob, "session:"),
            keys(&bob, "handle:"),
            keys(&bob, "hsin:")
        ),
        (0, 0, 1)
    );
    assert_eq!(read_record(&bob.core), prekeys, "no prekey was consumed");
    assert!(!bob.core.has_session(h).unwrap());
    assert_eq!(state(&bob, &alice), ChatSessionState::None);
    for r in [
        bob.core
            .send_message(h, b"x".to_vec(), b"x".to_vec())
            .map(|_| ()),
        bob.core.remove_session(h),
        bob.core.initiator_handshake(h).map(|_| ()),
        bob.core.pending_incoming(h).map(|_| ()),
    ] {
        assert!(matches!(r, Err(CoreError::NoSession { .. })), "{r:?}");
    }
}

/// 3, 4, 6: the first message that authenticates creates the session — once.
/// The same message again is a duplicate that changes nothing, and the
/// session then works in both directions.
#[test]
fn the_first_authenticated_message_creates_the_session_exactly_once() {
    let (alice, bob) = pair();
    let h = handle(&alice);
    bob.core
        .establish_session_responder(h, handshake(&alice, &bob))
        .unwrap();
    let published = current_opk_id(&bob.core).unwrap();

    let m1 = says(&alice, &bob, b"1", b"first");
    let got = accepted(bob.core.receive_message(h, m1.wire.clone()));
    assert_eq!(
        (got.plaintext.0, got.message_id.clone()),
        (b"first".to_vec(), m1.message_id.clone())
    );
    assert!(bob.core.has_session(h).unwrap());
    assert!(
        confirmed(&bob, h),
        "created with the peer's message accepted"
    );
    assert_eq!(bob.generation_with(&alice), 1);
    assert_eq!(
        (
            keys(&bob, "session:"),
            keys(&bob, "handle:"),
            keys(&bob, "hsin:")
        ),
        (1, 1, 0)
    );
    assert_ne!(
        current_opk_id(&bob.core).unwrap(),
        published,
        "prekey consumed"
    );
    assert_eq!(state(&bob, &alice), ChatSessionState::Established);

    let (record, prekeys) = (session_record(&bob), read_record(&bob.core));
    assert!(matches!(
        bob.core.receive_message(h, m1.wire.clone()),
        Ok(ReceiveResult::Duplicate {
            undelivered: Some(_),
            ..
        })
    ));
    assert_eq!(session_record(&bob), record, "no second promotion");
    assert_eq!(read_record(&bob.core), prekeys, "no second consumption");
    assert_eq!(
        bob.core.pending_incoming(h).unwrap().len(),
        1,
        "delivered once"
    );
    assert!(bob
        .core
        .acknowledge_incoming(h, m1.message_id.clone())
        .unwrap());
    assert!(matches!(
        bob.core.receive_message(h, m1.wire),
        Ok(ReceiveResult::Duplicate {
            undelivered: None,
            ..
        })
    ));

    let m2 = says(&alice, &bob, b"2", b"second");
    assert_eq!(
        accepted(bob.core.receive_message(h, m2.wire)).plaintext.0,
        b"second"
    );
    let reply = says(&bob, &alice, b"r", b"reply");
    assert_eq!(
        accepted(alice.core.receive_message(handle(&bob), reply.wire))
            .plaintext
            .0,
        b"reply"
    );
}

/// 5: a first message that does not authenticate — damaged, another
/// session's, or not a message — writes nothing and leaves the handshake
/// recorded, so the genuine first message still works.
#[test]
fn a_first_message_that_does_not_authenticate_creates_nothing() {
    let (alice, bob) = pair();
    let carol = Device::new(NO_RELAY, 3);
    let h = handle(&alice);
    bob.core
        .establish_session_responder(h, handshake(&alice, &bob))
        .unwrap();
    let (prekeys, recorded) = (read_record(&bob.core), provisional(&bob, h));

    let m1 = says(&alice, &bob, b"1", b"first");
    let mut damaged = m1.wire.clone();
    *damaged.last_mut().unwrap() ^= 1;
    // Carol's genuine first message, of her own session with Bob.
    handshake(&carol, &bob);
    let carols = says(&carol, &bob, b"c", b"from carol");
    for bad in [
        damaged,
        carols.wire,
        m1.wire[..HEADER_SIZE].to_vec(),
        vec![0u8; 3],
    ] {
        assert!(
            matches!(
                bob.core.receive_message(h, bad),
                Err(CoreError::Crypto { .. })
            ),
            "must not authenticate"
        );
        assert!(!bob.core.has_session(h).unwrap());
        assert_eq!(
            (
                keys(&bob, "session:"),
                keys(&bob, "handle:"),
                keys(&bob, "inbox:")
            ),
            (0, 0, 0)
        );
        assert_eq!(read_record(&bob.core), prekeys);
        assert_eq!(provisional(&bob, h), recorded);
    }
    assert_eq!(
        accepted(bob.core.receive_message(h, m1.wire)).plaintext.0,
        b"first"
    );
}

/// 7: after a restart the handshake is still recorded, still without
/// authority, and still answerable by its first message.
#[test]
fn a_restart_while_provisional_keeps_the_handshake_without_authority() {
    let (alice, bob) = pair();
    let h = handle(&alice);
    bob.core
        .establish_session_responder(h, handshake(&alice, &bob))
        .unwrap();
    let restarted = bob.restart(NO_RELAY);
    drop(bob);

    assert!(!restarted.core.has_session(h).unwrap());
    assert!(provisional(&restarted, h).is_some());
    assert_eq!(state(&restarted, &alice), ChatSessionState::None);
    let m1 = says(&alice, &restarted, b"1", b"after restart");
    assert_eq!(
        accepted(restarted.core.receive_message(h, m1.wire))
            .plaintext
            .0,
        b"after restart"
    );
    assert_eq!(state(&restarted, &alice), ChatSessionState::Established);
}

/// 9: an instance that saw the handshake while it was provisional cannot
/// create a second session, record the handshake again, or change the
/// session another instance created from it.
#[test]
fn a_stale_instance_cannot_overwrite_the_authenticated_session() {
    let (alice, bob) = pair();
    let h = handle(&alice);
    let hs = handshake(&alice, &bob);
    bob.core.establish_session_responder(h, hs.clone()).unwrap();
    let stale = Device::reopen(&bob.path, bob.byte, NO_RELAY);
    assert!(provisional(&stale, h).is_some());

    let m1 = says(&alice, &bob, b"1", b"first");
    accepted(bob.core.receive_message(h, m1.wire.clone()));
    let record = session_record(&bob);

    assert!(matches!(
        stale.core.receive_message(h, m1.wire),
        Ok(ReceiveResult::Duplicate { .. })
    ));
    assert!(matches!(
        stale.core.establish_session_responder(h, hs),
        Err(CoreError::OneTimePrekeyUnavailable { .. })
    ));
    assert_eq!(session_record(&bob), record);
    assert_eq!(keys(&bob, "hsin:"), 0);
}

/// 10: once a message authenticated under the session, no later handshake
/// replaces it — not a new one from the same peer, not another peer's on
/// the same handle — and nothing is recorded or consumed for it.
#[test]
fn an_authenticated_session_is_never_replaced_by_a_later_handshake() {
    let (alice, bob) = pair();
    let h = handle(&alice);
    bob.core
        .establish_session_responder(h, handshake(&alice, &bob))
        .unwrap();
    let m1 = says(&alice, &bob, b"1", b"first");
    accepted(bob.core.receive_message(h, m1.wire));
    assert!(alice
        .core
        .acknowledge_outgoing(handle(&bob), m1.message_id)
        .unwrap());
    let (record, prekeys) = (session_record(&bob), read_record(&bob.core));

    // Alice cannot tell whether Bob answered and starts over.
    alice.core.remove_session(handle(&bob)).unwrap();
    let again = handshake(&alice, &bob);
    assert!(matches!(
        bob.core.establish_session_responder(h, again),
        Err(CoreError::SessionAlreadyExists { .. })
    ));
    let m = says(&alice, &bob, b"n", b"on the new session");
    assert!(matches!(
        bob.core.receive_message(h, m.wire),
        Err(CoreError::Crypto { .. })
    ));

    let carol = Device::new(NO_RELAY, 3);
    assert!(matches!(
        bob.core
            .establish_session_responder(h, handshake(&carol, &bob)),
        Err(CoreError::SessionIdCollision { .. })
    ));
    assert_eq!(session_record(&bob), record);
    assert_eq!(read_record(&bob.core), prekeys);
    assert_eq!(keys(&bob, "hsin:"), 0);
}

/// 11: the initiator retransmits its handshake until it hears back. While
/// provisional a repeat changes nothing; after the session exists it is
/// refused and changes nothing either.
#[test]
fn a_retransmitted_handshake_is_harmless() {
    let (alice, bob) = pair();
    let h = handle(&alice);
    let hs = handshake(&alice, &bob);
    bob.core.establish_session_responder(h, hs.clone()).unwrap();
    let (prekeys, recorded) = (read_record(&bob.core), provisional(&bob, h));
    bob.core.establish_session_responder(h, hs.clone()).unwrap();
    assert_eq!(
        (read_record(&bob.core), provisional(&bob, h)),
        (prekeys, recorded)
    );

    let m1 = says(&alice, &bob, b"1", b"first");
    accepted(bob.core.receive_message(h, m1.wire));
    let (record, prekeys) = (session_record(&bob), read_record(&bob.core));
    assert!(matches!(
        bob.core.establish_session_responder(h, hs),
        Err(CoreError::OneTimePrekeyUnavailable { .. })
    ));
    assert_eq!(
        (session_record(&bob), read_record(&bob.core)),
        (record, prekeys)
    );
    assert_eq!(keys(&bob, "hsin:"), 0);
}

/// A provisional handshake has no authority, so a newer handshake for the
/// handle replaces it: the older one's messages then create nothing, and
/// the newer one's first message creates the session.
#[test]
fn a_newer_handshake_replaces_an_unconfirmed_one() {
    let (alice, bob) = pair();
    let (h, to_bob) = (handle(&alice), handle(&bob));
    let first = handshake(&alice, &bob);
    let old = says(&alice, &bob, b"old", b"under the first handshake");
    bob.core.establish_session_responder(h, first).unwrap();

    // Alice gives up on that session before Bob answered and starts again
    // from the same bundle, whose one-time prekey is still unconsumed.
    assert!(alice
        .core
        .abandon_outgoing(to_bob, old.message_id.clone())
        .unwrap());
    alice.core.remove_session(to_bob).unwrap();
    let second = handshake(&alice, &bob);
    bob.core
        .establish_session_responder(h, second.clone())
        .unwrap();
    assert_eq!(provisional(&bob, h), Some(second));

    assert!(matches!(
        bob.core.receive_message(h, old.wire.clone()),
        Err(CoreError::Crypto { .. })
    ));
    assert!(!bob.core.has_session(h).unwrap());
    let m = says(&alice, &bob, b"new", b"under the second handshake");
    assert_eq!(
        accepted(bob.core.receive_message(h, m.wire)).plaintext.0,
        b"under the second handshake"
    );
    assert!(matches!(
        bob.core.receive_message(h, old.wire),
        Err(CoreError::Crypto { .. })
    ));
}

/// The prekeys are checked again when the first message arrives. A
/// rotation since the handshake was recorded refuses it; so does a one-time
/// prekey that another initiator's first message consumed first — a
/// one-time prekey contributes to one session only. Nothing is written.
#[test]
fn prekeys_that_changed_since_recording_refuse_the_first_message() {
    let (alice, bob) = pair();
    let h = handle(&alice);
    bob.core
        .establish_session_responder(h, handshake(&alice, &bob))
        .unwrap();
    bob.core.establish_prekeys().unwrap(); // rotation
    let m1 = says(&alice, &bob, b"1", b"first");
    assert!(matches!(
        bob.core.receive_message(h, m1.wire),
        Err(CoreError::StaleSignedPrekey)
    ));
    assert!(!bob.core.has_session(h).unwrap());
    assert!(provisional(&bob, h).is_some());

    let (alice, bob) = pair();
    let carol = Device::new(NO_RELAY, 3);
    let bundle = bob.core.export_prekey_bundle().unwrap();
    let opk = current_opk_id(&bob.core).unwrap();
    for (peer, hs) in [
        (
            &alice,
            alice
                .core
                .establish_session_initiator(handle(&bob), bundle.clone()),
        ),
        (
            &carol,
            carol.core.establish_session_initiator(handle(&bob), bundle),
        ),
    ] {
        bob.core
            .establish_session_responder(handle(peer), hs.unwrap())
            .unwrap();
    }
    let from_carol = says(&carol, &bob, b"c", b"carol first");
    accepted(bob.core.receive_message(handle(&carol), from_carol.wire));
    let prekeys = read_record(&bob.core);
    let from_alice = says(&alice, &bob, b"a", b"alice first");
    assert!(matches!(
        bob.core.receive_message(handle(&alice), from_alice.wire),
        Err(CoreError::OneTimePrekeyUnavailable { opk_id }) if opk_id == opk
    ));
    assert!(!bob.core.has_session(handle(&alice)).unwrap());
    assert_eq!(read_record(&bob.core), prekeys);
}

// ── Over the relay ────────────────────────────────────────────────────────────

/// Deletes the handshakes (`handshakes`) or the messages waiting for `to` on
/// the relay, as a relay that withholds them could.
fn withhold(relay: &relay::server::RelayHandle, addr: &str, to: &Device, handshakes: bool) {
    let key: [u8; 32] = to.pk.as_slice().try_into().unwrap();
    let seqs: Vec<u64> = relay
        .stored(&key)
        .into_iter()
        .filter(|(_, e)| {
            matches!(Envelope::decode(e), Some(Envelope::Handshake { .. })) == handshakes
        })
        .map(|(s, _)| s)
        .collect();
    relay::client::Connection::connect(addr, std::time::Duration::from_secs(2))
        .unwrap()
        .delete(key, seqs)
        .unwrap();
}

/// 2, 13: over the relay, a handshake whose first message has not arrived
/// creates no session and reads as none; the retransmitted first message
/// creates it.
#[test]
fn over_the_relay_a_handshake_without_its_first_message_is_not_a_session() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    alice.knows(&bob);
    bob.knows(&alice);
    bob.net.publish_prekeys().unwrap();
    alice.net.start_session(bob.pk.clone()).unwrap();
    alice.sync();
    withhold(&relay, &addr, &bob, false); // only the handshake stays

    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.sessions_accepted, r.accepted), (0, 0), "{r:?}");
    assert!(!bob.core.has_session(handle(&alice)).unwrap());
    assert!(provisional(&bob, handle(&alice)).is_some());
    assert_eq!(state(&bob, &alice), ChatSessionState::None);

    settle(&[&alice, &bob]);
    assert!(confirmed(&bob, handle(&alice)));
    assert_eq!(state(&bob, &alice), ChatSessionState::Established);
    assert_eq!(state(&alice, &bob), ChatSessionState::Established);
    relay.stop();
}

/// 12: a recorded handshake does not stop this device from starting its own
/// session. Both sides then hold an unconfirmed session of their own — the
/// existing simultaneous-initiation conflict — which resolves as before.
#[test]
fn a_recorded_handshake_does_not_block_simultaneous_initiation_or_its_resolution() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    for (a, b) in [(&alice, &bob), (&bob, &alice)] {
        a.net
            .add_named_contact(b.core.contact_card().unwrap(), "peer".into())
            .unwrap();
    }
    bob.net.publish_prekeys().unwrap();
    alice.net.publish_prekeys().unwrap();
    alice.net.start_session(bob.pk.clone()).unwrap();
    alice.sync();
    withhold(&relay, &addr, &bob, false);
    assert!(bob.sync().errors.is_empty());
    assert!(provisional(&bob, handle(&alice)).is_some());

    // Bob writes first: with no session he starts his own.
    bob.net
        .chat_send(alice.pk.clone(), b"b".to_vec(), "from bob".into())
        .unwrap();
    for d in [&bob, &alice, &bob, &alice] {
        let r = d.net.sync_conversations();
        assert!(r.errors.is_empty(), "{:?}", r.errors);
    }
    let (g, s) = if alice.pk > bob.pk {
        (&alice, &bob)
    } else {
        (&bob, &alice)
    };
    assert_eq!(
        state(g, s),
        ChatSessionState::Conflict { can_resolve: true }
    );
    assert_eq!(
        state(s, g),
        ChatSessionState::Conflict { can_resolve: false }
    );

    g.net.resolve_session_conflict(s.pk.clone()).unwrap();
    for _ in 0..3 {
        for d in [g, s] {
            let r = d.net.sync_conversations();
            assert!(r.errors.is_empty(), "{:?}", r.errors);
        }
    }
    assert_eq!(state(g, s), ChatSessionState::Established);
    assert_eq!(state(s, g), ChatSessionState::Established);
    relay.stop();
}
