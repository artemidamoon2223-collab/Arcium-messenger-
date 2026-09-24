//! Network messaging between independent devices over a real relay on a TCP
//! port: first contact, both directions, an offline recipient, broken
//! connections and hostile relay contents. Process deaths are in
//! `network_crash.rs`.

use super::net_harness::*;
use super::*;
use crate::contacts::contact_card_fingerprint;
use crate::network::wire::{Envelope, Payload};
use crate::network::TextState;
use relay::server::{serve, RelayConfig};
use std::net::TcpListener;

// ── V1: first contact and identity binding ─────────────────────────────────────

#[test]
fn first_contact_establishes_a_session_and_delivers_end_to_end() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    alice.knows(&bob);
    bob.knows(&alice);
    bob.net.publish_prekeys().unwrap();
    alice.net.start_session(bob.pk.clone()).unwrap();
    let id = alice.send(&bob, "m1", "hello bob");
    assert_eq!(alice.undelivered(&bob), 1);

    settle(&[&alice, &bob]);
    assert_eq!(bob.texts(&alice), vec!["hello bob"]);
    assert_eq!(alice.undelivered(&bob), 0, "Bob's receipt confirmed it");
    assert_eq!(
        alice
            .net
            .send_text(bob.pk.clone(), b"m1".to_vec(), vec![])
            .unwrap(),
        crate::network::SentText {
            message_id: id,
            state: TextState::Delivered
        }
    );
    assert_eq!(relay.canary_hits(), 0, "no plaintext reached the relay");
    relay.stop();
}

#[test]
fn a_bundle_that_does_not_match_the_pinned_card_is_refused() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob, mallory) = (
        Device::new(&addr, 1),
        Device::new(&addr, 2),
        Device::new(&addr, 3),
    );
    alice.knows(&bob);
    // Mallory publishes her own bundle under Bob's key.
    let mut c =
        relay::client::Connection::connect(&addr, std::time::Duration::from_secs(2)).unwrap();
    mallory.core.establish_prekeys().unwrap();
    c.put_bundle(
        bob.pk.as_slice().try_into().unwrap(),
        mallory.core.export_prekey_bundle().unwrap(),
    )
    .unwrap();
    assert!(matches!(
        alice.net.start_session(bob.pk.clone()),
        Err(CoreError::PeerIdentityMismatch)
    ));
    assert!(!alice
        .core
        .has_session(local_session_handle(bob.pk.clone()).unwrap())
        .unwrap());
    // Bob's genuine bundle works.
    bob.net.publish_prekeys().unwrap();
    alice.net.start_session(bob.pk.clone()).unwrap();
    relay.stop();
}

#[test]
fn identities_are_pinned_and_strangers_are_ignored() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob, carol) = (
        Device::new(&addr, 1),
        Device::new(&addr, 2),
        Device::new(&addr, 3),
    );
    alice.knows(&bob);
    alice.knows(&bob); // the same card again is harmless
                       // A different card for Bob's identity key is refused.
    let mut forged = bob.core.contact_card().unwrap();
    forged[40] ^= 1;
    assert!(matches!(
        alice.core.add_contact(forged),
        Err(CoreError::ContactIdentityChanged)
    ));
    assert!(matches!(
        alice.net.start_session(carol.pk.clone()),
        Err(CoreError::UnknownContact)
    ));
    // Carol knows Bob, but Bob does not know Carol: her handshake and
    // messages are dropped and create nothing.
    carol.knows(&bob);
    bob.net.publish_prekeys().unwrap();
    carol.net.start_session(bob.pk.clone()).unwrap();
    carol.send(&bob, "c1", "hi");
    carol.sync();
    let r = bob.sync();
    assert_eq!((r.sessions_accepted, r.accepted), (0, 0));
    assert!(r.dropped >= 2, "{r:?}");
    assert!(!bob
        .core
        .has_session(local_session_handle(carol.pk.clone()).unwrap())
        .unwrap());
    assert_eq!(
        contact_card_fingerprint(bob.core.contact_card().unwrap())
            .unwrap()
            .len(),
        39
    );
    relay.stop();
}

// ── V2: both directions, restarts ─────────────────────────────────────────────

#[test]
fn both_directions_and_both_histories_survive_restarts() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    alice.send(&bob, "a1", "question");
    settle(&[&alice, &bob]);
    let q = bob.net.received_texts(alice.pk.clone()).unwrap();
    assert!(bob
        .net
        .mark_read(alice.pk.clone(), q[0].message_id.clone())
        .unwrap());
    bob.send(&alice, "b1", "answer");
    settle(&[&alice, &bob]);
    assert_eq!(alice.texts(&bob), vec!["answer"]);
    assert_eq!((alice.undelivered(&bob), bob.undelivered(&alice)), (0, 0));

    // Both restart and keep going; each history is its own.
    let (alice, bob) = (alice.restart(&addr), bob.restart(&addr));
    for i in 0..3 {
        alice.send(&bob, &format!("a{}", i + 2), &format!("a{i}"));
        bob.send(&alice, &format!("b{}", i + 2), &format!("b{i}"));
        settle(&[&alice, &bob]);
    }
    assert_eq!(bob.texts(&alice), vec!["a0", "a1", "a2"]);
    assert_eq!(alice.texts(&bob), vec!["answer", "b0", "b1", "b2"]);
    // Every step of each side is one committed transition on the other.
    assert_eq!(alice.generation_with(&bob), bob.generation_with(&alice));
    assert_eq!(relay.canary_hits(), 0);
    relay.stop();
}

// ── V3: offline recipient ─────────────────────────────────────────────────────

#[test]
fn messages_to_an_offline_recipient_wait_on_the_relay() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    let ids: Vec<_> = (0..5)
        .map(|i| alice.send(&bob, &format!("m{i}"), &format!("t{i}")))
        .collect();
    for _ in 0..3 {
        alice.sync(); // retransmits; the relay keeps one copy of each
    }
    assert_eq!(stored_messages(&relay, &bob).len(), 5);
    assert_eq!(
        alice.undelivered(&bob),
        5,
        "the relay accepting them is not delivery"
    );

    settle(&[&bob, &alice]);
    assert_eq!(bob.texts(&alice), vec!["t0", "t1", "t2", "t3", "t4"]);
    assert_eq!(alice.undelivered(&bob), 0);
    assert_eq!(ids.len(), 5);
    relay.stop();
}

// ── V4: broken network ────────────────────────────────────────────────────────

#[test]
fn a_relay_outage_loses_nothing_and_creates_no_second_ciphertext() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    let stored_before = alice
        .core
        .pending_outgoing(local_session_handle(bob.pk.clone()).unwrap())
        .unwrap()
        .len();
    assert_eq!(stored_before, 0);
    alice.send(&bob, "m", "during outage");
    let wire = alice
        .core
        .pending_outgoing(local_session_handle(bob.pk.clone()).unwrap())
        .unwrap()[0]
        .wire
        .clone();
    alice.sync();
    relay.stop(); // everything the relay held is gone
    let r = alice.sync();
    assert!(!r.errors.is_empty(), "the outage is reported");
    assert_eq!(alice.undelivered(&bob), 1);

    let relay = serve(TcpListener::bind(&addr).unwrap(), RelayConfig::default()).unwrap();
    settle(&[&alice, &bob]);
    assert_eq!(bob.texts(&alice), vec!["during outage"]);
    assert_eq!(alice.undelivered(&bob), 0);
    // The one ciphertext for the message is the one stored before the outage.
    let received = bob.net.received_texts(alice.pk.clone()).unwrap();
    assert_eq!(
        received[0].message_id,
        core_protocol::messaging::message_id(&wire).to_vec()
    );
    relay.stop();
}

/// A connection breaks at each point that matters: a publication whose
/// response is lost, a fetch whose response is lost, a delete that never
/// arrives, a receipt whose response is lost. Each time the round fails, the
/// next one completes, and every message is accepted exactly once.
#[test]
fn broken_connections_at_each_step_recover_without_double_acceptance() {
    let relay = start_relay();
    let proxy = Proxy::start(&relay.addr().to_string());
    let (alice, bob) = connected(&proxy.addr);
    let steps = [
        (3u8, Cut::Response, "alice"), // SEND: stored, answer lost
        (4, Cut::Response, "bob"),     // FETCH: answer lost
        (5, Cut::Request, "bob"),      // DELETE: never arrives
        (3, Cut::Response, "bob"),     // SEND of the receipt: answer lost
    ];
    for (i, (op, cut, who)) in steps.into_iter().enumerate() {
        alice.send(&bob, &format!("m{i}"), &format!("t{i}"));
        let accepted_before = bob.accepted_total();
        proxy.arm(op, cut);
        for _ in 0..4 {
            let d = if who == "alice" { &alice } else { &bob };
            d.sync();
            let other = if who == "alice" { &bob } else { &alice };
            other.sync();
        }
        assert!(proxy.fired(), "step {i} broke a connection");
        settle(&[&alice, &bob]);
        assert_eq!(bob.texts(&alice).len(), i + 1, "step {i}");
        assert_eq!(alice.undelivered(&bob), 0, "step {i}");
        // Retransmissions may arrive again as duplicates; the ratchet accepts
        // the message once.
        assert_eq!(bob.accepted_total(), accepted_before + 1, "step {i}");
    }
    relay.stop();
}

// ── V6: hostile relay contents ────────────────────────────────────────────────

#[test]
fn replayed_reordered_and_malformed_envelopes_advance_nothing_wrongly() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    for i in 0..3 {
        alice.send(&bob, &format!("m{i}"), &format!("t{i}"));
    }
    alice.sync();
    // Reorder: take the three envelopes off the relay and put them back
    // newest first.
    let bob_key: [u8; 32] = bob.pk.as_slice().try_into().unwrap();
    let mut items = relay.stored(&bob_key);
    let mut c =
        relay::client::Connection::connect(&addr, std::time::Duration::from_secs(2)).unwrap();
    c.delete(bob_key, items.iter().map(|(s, _)| *s).collect())
        .unwrap();
    items.reverse();
    for (_, env) in &items {
        c.send(bob_key, env.clone()).unwrap();
    }
    // Garbage, a truncated message and an unknown kind alongside them.
    inject(&addr, &bob, b"not an envelope".to_vec());
    let mut truncated = items[0].1.clone();
    truncated.truncate(60);
    inject(&addr, &bob, truncated);
    let mut odd = items[0].1.clone();
    odd[4] = 9;
    inject(&addr, &bob, odd);
    let gen = bob.generation_with(&alice);
    let r = bob.sync();
    assert_eq!(r.accepted, 3, "{r:?}");
    assert_eq!(r.dropped, 3, "{r:?}");
    assert_eq!(
        bob.generation_with(&alice),
        gen + 3 + 3,
        "3 messages and 3 receipts"
    );
    let mut got = bob.texts(&alice);
    got.sort();
    assert_eq!(got, vec!["t0", "t1", "t2"]);

    // Replays of the same envelopes after they were deleted: duplicates, no
    // ratchet step, and no second text for the application.
    for (_, env) in &items {
        inject(&addr, &bob, env.clone());
    }
    let gen = bob.generation_with(&alice);
    let r = bob.sync();
    assert_eq!((r.accepted, r.duplicates), (0, 3), "{r:?}");
    assert_eq!(bob.texts(&alice).len(), 3);
    // Duplicates only add receipts, never accept anything.
    assert!(bob.generation_with(&alice) <= gen + 3);
    relay.stop();
}

#[test]
fn forged_and_cross_session_receipts_confirm_nothing() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    let carol = Device::new(&addr, 3);
    alice.knows(&carol);
    carol.knows(&alice);
    alice.net.publish_prekeys().unwrap();
    carol.net.start_session(alice.pk.clone()).unwrap();
    settle(&[&alice, &carol]);

    let id = alice.send(&bob, "m", "for bob only");
    alice.sync(); // on the relay, Bob offline

    // 1. A receipt-shaped envelope claiming to be Bob's, not encrypted by him.
    let mut wire = vec![0u8; 40];
    wire.extend_from_slice(&Payload::Receipt(vec![id.clone().try_into().unwrap()]).encode());
    let forged = Envelope::Message {
        sender: bob.pk.clone().try_into().unwrap(),
        wire,
    };
    inject(&addr, &alice, forged.encode());
    // 2. A genuine receipt for the same id, but from Carol's session.
    let carol_handle = local_session_handle(alice.pk.clone()).unwrap();
    let receipt = carol
        .core
        .send_message(
            carol_handle,
            b"rX".to_vec(),
            Payload::Receipt(vec![id.clone().try_into().unwrap()]).encode(),
        )
        .unwrap();
    let SendResult::Sent { message } = receipt else {
        panic!()
    };
    // 3. The same genuine receipt relabelled as coming from Bob.
    let relabelled = Envelope::Message {
        sender: bob.pk.clone().try_into().unwrap(),
        wire: message.wire.clone(),
    };
    inject(&addr, &alice, relabelled.encode());
    carol.sync();

    let r = alice.sync();
    assert_eq!(r.delivered, 0, "{r:?}");
    assert_eq!(
        alice.undelivered(&bob),
        1,
        "only Bob's own receipt confirms delivery"
    );
    assert!(r.dropped >= 2, "{r:?}");

    settle(&[&bob, &alice]);
    assert_eq!(alice.undelivered(&bob), 0);
    assert_eq!(bob.texts(&alice), vec!["for bob only"]);
    relay.stop();
}

#[test]
fn a_replayed_handshake_does_not_disturb_an_established_session() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    let hs = alice
        .core
        .initiator_handshake(local_session_handle(bob.pk.clone()).unwrap())
        .unwrap()
        .unwrap();
    let env = Envelope::Handshake {
        sender: alice.pk.clone().try_into().unwrap(),
        handshake: hs,
    };
    inject(&addr, &bob, env.encode());
    let gen = bob.generation_with(&alice);
    let r = bob.sync();
    assert_eq!((r.sessions_accepted, r.dropped), (0, 1), "{r:?}");
    assert_eq!(bob.generation_with(&alice), gen);
    alice.send(&bob, "after", "still works");
    settle(&[&alice, &bob]);
    assert_eq!(bob.texts(&alice), vec!["still works"]);
    relay.stop();
}

#[test]
fn a_message_that_arrives_before_its_handshake_waits_for_it() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    alice.knows(&bob);
    bob.knows(&alice);
    bob.net.publish_prekeys().unwrap();
    alice.net.start_session(bob.pk.clone()).unwrap();
    alice.send(&bob, "early", "early bird");
    alice.sync();
    // Hold the handshake back: remove it from the relay.
    let bob_key: [u8; 32] = bob.pk.as_slice().try_into().unwrap();
    let hs: Vec<u64> = relay
        .stored(&bob_key)
        .into_iter()
        .filter(|(_, e)| matches!(Envelope::decode(e), Some(Envelope::Handshake { .. })))
        .map(|(s, _)| s)
        .collect();
    relay::client::Connection::connect(&addr, std::time::Duration::from_secs(2))
        .unwrap()
        .delete(bob_key, hs)
        .unwrap();
    let r = bob.sync();
    assert_eq!((r.accepted, r.deferred), (0, 2), "{r:?}");
    // Alice retransmits the handshake; everything is then accepted.
    settle(&[&alice, &bob]);
    assert_eq!(bob.texts(&alice), vec!["early bird"]);
    assert_eq!(alice.undelivered(&bob), 0);
    relay.stop();
}

/// The relay loses Bob's receipt after accepting it. Alice keeps the text and
/// sends it again; Bob receives it as a duplicate and answers with a new
/// receipt, and only that makes the text delivered.
#[test]
fn a_lost_receipt_is_answered_again_when_the_text_is_repeated() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    let before = bob.accepted_total();
    alice.send(&bob, "m", "confirm");
    alice.sync();
    bob.sync(); // accepts, sends the receipt
    let alice_key: [u8; 32] = alice.pk.as_slice().try_into().unwrap();
    let lost: Vec<u64> = relay
        .stored(&alice_key)
        .into_iter()
        .map(|(s, _)| s)
        .collect();
    assert_eq!(lost.len(), 1, "exactly Bob's receipt is waiting for Alice");
    relay::client::Connection::connect(&addr, std::time::Duration::from_secs(2))
        .unwrap()
        .delete(alice_key, lost)
        .unwrap();
    assert_eq!(alice.sync().delivered, 0);
    assert_eq!(alice.undelivered(&bob), 1);
    settle(&[&bob, &alice]);
    assert_eq!(alice.undelivered(&bob), 0);
    assert_eq!(bob.texts(&alice), vec!["confirm"]);
    assert_eq!(
        bob.accepted_total(),
        before + 1,
        "the repeat was a duplicate"
    );
    relay.stop();
}
