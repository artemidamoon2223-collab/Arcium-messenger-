//! R-21: a message that reaches its recipient after its key was evicted can
//! never be read. The recipient names it in a GONE message; the sender stops
//! sending it, and the text reads as abandoned (NotDelivered in a history).

use super::net_harness::*;
use crate::network::chat::ChatEntryState;
use crate::network::wire::{client_id, Envelope, Payload};
use crate::SendResult;

/// Deletes everything the relay holds for `of`, as a relay that loses it.
fn lose_mailbox(addr: &str, of: &Device) -> usize {
    let key: [u8; 32] = of.pk.as_slice().try_into().unwrap();
    let mut c = relay::client::Connection::connect(addr, std::time::Duration::from_secs(2)).unwrap();
    let seqs: Vec<u64> = c.fetch_after(key, 0, 1000).unwrap().into_iter().map(|(s, _)| s).collect();
    let n = seqs.len();
    c.delete(key, seqs).unwrap();
    n
}

#[test]
fn a_message_whose_key_is_gone_is_named_back_and_abandoned() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    let to_bob = crate::local_session_handle(bob.pk.clone()).unwrap();
    let to_alice = crate::local_session_handle(alice.pk.clone()).unwrap();

    // Alice commits 2,101 texts in one sending chain; none is sent yet.
    // Text 0 is written in the conversation history.
    alice
        .net
        .chat_send(bob.pk.clone(), b"g0".to_vec(), "late".into())
        .unwrap();
    let mut ids: Vec<Vec<u8>> = vec![Vec::new()];
    ids.extend((1..2101).map(|i| alice.send(&bob, &format!("g{i}"), "x")));
    let pending = alice.core.pending_outgoing(to_bob).unwrap();
    ids[0] = pending
        .iter()
        .find(|m| m.client_message_id == client_id::text(b"g0"))
        .expect("text 0 pending")
        .message_id
        .clone();
    let wire = |i: usize| {
        pending
            .iter()
            .find(|m| m.message_id == ids[i])
            .expect("pending")
            .wire
            .clone()
    };
    let late = wire(0);

    // Bob reads three of them, skipping about 2,100 keys: more than the
    // 2,000 the store holds, so the oldest (that of text 0) is evicted.
    for i in [900, 1800, 2100] {
        bob.core.receive_committed(to_alice, &wire(i)).unwrap();
    }
    // Only text 0 stays pending at Alice; the others are not the point here.
    for id in &ids[1..] {
        alice.core.abandon_outgoing(to_bob, id.clone()).unwrap();
    }

    // Bob settles what he read: its receipts go to Alice, who ignores them.
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);

    // Alice sends text 0. It reaches Bob late: it cannot be read, and Bob
    // names it.
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(alice.undelivered(&bob), 1);
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.dropped, r.published), (1, 1), "{r:?}");

    // The relay loses that GONE message after accepting it.
    assert_eq!(lose_mailbox(&addr, &alice), 1);

    // Alice sends text 0 again: Bob names it again, in a new GONE message.
    // Bob's clock reads minute 1,000 from here on.
    bob.net.set_minute(Some(1_000));
    let again = || {
        inject(
            &addr,
            &bob,
            Envelope::Message {
                sender: alice.core.our_identity_pk().unwrap(),
                wire: late.clone(),
            }
            .encode(),
        )
    };
    again();
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.dropped, r.published), (1, 1), "named again: {r:?}");

    // Alice reads it and stops sending text 0.
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(alice.undelivered(&bob), 0, "text 0 is no longer pending");
    let record = alice.core.prior_send(&bob.core.our_identity_pk().unwrap(), &client_id::text(b"g0"));
    assert!(
        matches!(record, Ok(Some(SendResult::Abandoned { .. }))),
        "text 0 reads as abandoned: {record:?}"
    );
    let history = alice.net.chat_entries(bob.pk.clone()).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].state, ChatEntryState::NotDelivered);

    // A copy still on its way reaches Bob within the same minute: it is
    // found again, and nothing new is committed (one GONE a minute).
    again();
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert!(r.dropped >= 1, "{r:?}");
    assert_eq!(r.published, 0, "no third GONE message within a minute: {r:?}");

    // A minute later, another copy is named once more; Alice, who no longer
    // has text 0 pending, ignores it.
    bob.net.set_minute(Some(1_001));
    again();
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.published, 1, "named again a minute later: {r:?}");
    again();
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.published, 0, "and not again within that minute: {r:?}");
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(alice.undelivered(&bob), 0);
    relay.stop();
}

/// R-21 for a chain the recipient has left: Alice's text 0, whose key Bob
/// evicted, reaches Bob only after the ratchet turned (Bob answered, Alice
/// wrote on a new chain, and Bob read that). Bob still names it, from the
/// end he remembers of Alice's earlier chain, and Alice gives it up.
#[test]
fn a_late_message_of_an_earlier_chain_is_named_back_too() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    let to_bob = crate::local_session_handle(bob.pk.clone()).unwrap();
    let to_alice = crate::local_session_handle(alice.pk.clone()).unwrap();

    alice
        .net
        .chat_send(bob.pk.clone(), b"g0".to_vec(), "late".into())
        .unwrap();
    let mut ids: Vec<Vec<u8>> = vec![Vec::new()];
    ids.extend((1..2101).map(|i| alice.send(&bob, &format!("g{i}"), "x")));
    let pending = alice.core.pending_outgoing(to_bob).unwrap();
    ids[0] = pending
        .iter()
        .find(|m| m.client_message_id == client_id::text(b"g0"))
        .expect("text 0 pending")
        .message_id
        .clone();
    let wire = |i: usize| {
        pending
            .iter()
            .find(|m| m.message_id == ids[i])
            .expect("pending")
            .wire
            .clone()
    };
    let late = wire(0);
    // Bob reads three of them: the key of text 0 is evicted.
    for i in [900, 1800, 2100] {
        bob.core.receive_committed(to_alice, &wire(i)).unwrap();
    }
    for id in &ids[1..] {
        alice.core.abandon_outgoing(to_bob, id.clone()).unwrap();
    }
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);

    // The ratchet turns: Bob answers, Alice reads it and writes on a new
    // chain. Whatever reached Bob's mailbox meanwhile is lost; only the new
    // text arrives.
    bob.send(&alice, "b1", "turn");
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    let new_id = alice.send(&bob, "a2", "on a new chain");
    let new_wire = alice
        .core
        .pending_outgoing(to_bob)
        .unwrap()
        .into_iter()
        .find(|m| m.message_id == new_id)
        .expect("pending")
        .wire;
    lose_mailbox(&addr, &bob);
    let alice_key = alice.core.our_identity_pk().unwrap();
    inject(&addr, &bob, Envelope::Message { sender: alice_key, wire: new_wire }.encode());
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.accepted, 1, "Bob is on Alice's new chain: {r:?}");

    // Text 0 arrives late, on the chain Bob left: named back.
    inject(&addr, &bob, Envelope::Message { sender: alice_key, wire: late }.encode());
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    // Bob's counts cannot tell a GONE from a retransmission; Alice's side
    // below shows that text 0 was named.
    assert!(r.dropped >= 1 && r.published >= 1, "{r:?}");
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    let record = alice.core.prior_send(&bob.core.our_identity_pk().unwrap(), &client_id::text(b"g0"));
    assert!(
        matches!(record, Ok(Some(SendResult::Abandoned { .. }))),
        "text 0 reads as abandoned: {record:?}"
    );
    let history = alice.net.chat_entries(bob.pk.clone()).unwrap();
    assert_eq!(history[0].state, ChatEntryState::NotDelivered);
    relay.stop();
}

/// A GONE message changes nothing for an id the sender has not pending as a
/// text: another message, a message that is not a text, or one already
/// delivered.
#[test]
fn a_gone_message_ignores_ids_it_does_not_hold_pending() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    let to_bob = crate::local_session_handle(bob.pk.clone()).unwrap();
    let to_alice = crate::local_session_handle(alice.pk.clone()).unwrap();
    let delivered = alice.send(&bob, "d", "delivered");
    settle(&[&alice, &bob]);
    assert_eq!(alice.undelivered(&bob), 0);
    let kept = alice.send(&bob, "k", "kept");
    let other = match alice
        .core
        .send_message(to_bob, b"app-1".to_vec(), b"not a text".to_vec())
        .unwrap()
    {
        SendResult::Sent { message } => message.message_id,
        r => panic!("{r:?}"),
    };

    let named = vec![
        [0x55; 32],
        <[u8; 32]>::try_from(delivered.as_slice()).unwrap(),
        <[u8; 32]>::try_from(other.as_slice()).unwrap(),
    ];
    bob.core
        .send_committed(to_alice, &client_id::gone(&named, 0), &Payload::Gone(named.clone()).encode())
        .unwrap();
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(alice.undelivered(&bob), 1, "the pending text stays");
    assert_eq!(alice.net.undelivered(bob.pk.clone()).unwrap(), vec![kept]);
    let still: Vec<Vec<u8>> = alice
        .core
        .pending_outgoing(to_bob)
        .unwrap()
        .into_iter()
        .map(|m| m.message_id)
        .collect();
    assert!(still.contains(&other), "the message that is not a text stays");
    relay.stop();
}

/// Puts `n` copies of a message Bob has read into his mailbox, each with
/// the last four bytes of its tag changed, so none decrypts. Anyone who saw
/// the message can make them, and each looks late.
fn altered_copies(addr: &str, alice: &Device, bob: &Device, n: u32) {
    let to_bob = crate::local_session_handle(bob.pk.clone()).unwrap();
    let id = alice.send(bob, "seen", "read by Bob");
    let wire = alice
        .core
        .pending_outgoing(to_bob)
        .unwrap()
        .into_iter()
        .find(|m| m.message_id == id)
        .expect("pending")
        .wire;
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    let sender = alice.core.our_identity_pk().unwrap();
    for i in 1..=n {
        let mut w = wire.clone();
        let len = w.len();
        let tail = u32::from_be_bytes(w[len - 4..].try_into().unwrap()) ^ i;
        w[len - 4..].copy_from_slice(&tail.to_be_bytes());
        inject(addr, bob, Envelope::Message { sender, wire: w }.encode());
    }
}

/// However many messages look late in one round, a session draws one GONE
/// message, naming at most 256 of them.
#[test]
fn messages_that_look_late_draw_one_gone_message_per_round() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    settle(&[&alice, &bob]);
    altered_copies(&addr, &alice, &bob, 300);
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.dropped, r.published), (300, 1), "{r:?}");
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(alice.undelivered(&bob), 0, "nothing of Alice's was named");
    relay.stop();
}

/// A round that fails after finding messages beyond recall, before naming
/// them, keeps nothing: the record does not grow across failing rounds.
#[test]
fn a_failed_round_keeps_no_messages_to_name() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    settle(&[&alice, &bob]);
    altered_copies(&addr, &alice, &bob, 20);
    let proxy = Proxy::start(&addr);
    let bob = bob.restart(&proxy.addr);
    for round in 0..3 {
        proxy.arm(5, Cut::Request); // DELETE never arrives: the round fails.
        let r = bob.sync();
        assert!(!r.errors.is_empty(), "round {round}: {r:?}");
        assert!(proxy.fired(), "round {round}");
        assert_eq!(bob.net.gone_len(), 0, "round {round}");
    }
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.dropped, r.published), (20, 1), "{r:?}");
    relay.stop();
}

/// R-21 with 32 earlier chains remembered (Owner, 2026-11-19), through the
/// stored session: Alice's message 0, whose key Bob evicted, is still
/// recognised as beyond recall after every turn of the conversation up to
/// 32 (four were remembered before), and no longer after the 33rd. Bob's
/// session is written to the store and read back at every message, so the
/// chains survive `RATCHET_STATE_V2` each time.
#[test]
fn a_late_message_is_recognised_for_32_turns_through_the_stored_session() {
    // The number decided, not the constant: a test counting turns by
    // `MAX_PREV_CHAINS` would pass whatever its value.
    const REMEMBERED: usize = 32;
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    let to_bob = crate::local_session_handle(bob.pk.clone()).unwrap();
    let to_alice = crate::local_session_handle(alice.pk.clone()).unwrap();

    let wires: Vec<Vec<u8>> = (0..2101u32)
        .map(|i| alice.core.encrypt_message(to_bob, i.to_be_bytes().to_vec()).unwrap())
        .collect();
    for i in [900, 1800, 2100] {
        bob.core.decrypt_message(to_alice, wires[i].clone()).unwrap();
    }
    let late = &wires[0];
    assert!(bob.core.beyond_recall(to_alice, late).unwrap(), "evicted, on the current chain");

    // Remembered for 32 turns, then a chain Bob no longer knows, which is
    // recognised as well (Owner, 2026-11-20): no turn in between misses it.
    for turn in 1..=REMEMBERED + 2 {
        let b = bob.core.encrypt_message(to_alice, b"turn".to_vec()).unwrap();
        alice.core.decrypt_message(to_bob, b).unwrap();
        let a = alice.core.encrypt_message(to_bob, b"turn".to_vec()).unwrap();
        bob.core.decrypt_message(to_alice, a).unwrap();
        assert!(bob.core.beyond_recall(to_alice, late).unwrap(), "after {turn} turns");
    }
    relay.stop();
}

/// R-21 beyond the remembered chains (Owner, 2026-11-20): Alice's text 0,
/// whose key Bob evicted, reaches Bob only after 33 turns of the
/// conversation, when he no longer remembers its chain. Bob names it all the
/// same, and Alice gives it up. (Before, it was deleted silently and Alice
/// kept sending it until the user cancelled it.)
#[test]
fn a_late_message_of_a_forgotten_chain_is_named_back() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    let to_bob = crate::local_session_handle(bob.pk.clone()).unwrap();
    let to_alice = crate::local_session_handle(alice.pk.clone()).unwrap();

    alice
        .net
        .chat_send(bob.pk.clone(), b"g0".to_vec(), "late".into())
        .unwrap();
    let mut ids: Vec<Vec<u8>> = vec![Vec::new()];
    ids.extend((1..2101).map(|i| alice.send(&bob, &format!("g{i}"), "x")));
    let pending = alice.core.pending_outgoing(to_bob).unwrap();
    ids[0] = pending
        .iter()
        .find(|m| m.client_message_id == client_id::text(b"g0"))
        .expect("text 0 pending")
        .message_id
        .clone();
    let wire = |i: usize| {
        pending
            .iter()
            .find(|m| m.message_id == ids[i])
            .expect("pending")
            .wire
            .clone()
    };
    let late = wire(0);
    // Bob reads three of them: the key of text 0 is evicted.
    for i in [900, 1800, 2100] {
        bob.core.receive_committed(to_alice, &wire(i)).unwrap();
    }
    for id in &ids[1..] {
        alice.core.abandon_outgoing(to_bob, id.clone()).unwrap();
    }
    // 33 turns, directly on the sessions: Alice does not sync meanwhile, so
    // text 0 is not sent again before its chain is forgotten. Each turn
    // message is a receipt for an id nobody holds, which a round settles
    // without effect.
    let turn = Payload::Receipt(vec![[0x55; 32]]).encode().to_vec();
    for _ in 0..33 {
        let b = bob.core.encrypt_message(to_alice, turn.clone()).unwrap();
        alice.core.decrypt_message(to_bob, b).unwrap();
        let a = alice.core.encrypt_message(to_bob, turn.clone()).unwrap();
        bob.core.decrypt_message(to_alice, a).unwrap();
    }
    // The turns are not the point: their messages are given up.
    for m in bob.core.pending_outgoing(to_alice).unwrap() {
        bob.core.abandon_outgoing(to_alice, m.message_id).unwrap();
    }
    for m in alice.core.pending_outgoing(to_bob).unwrap() {
        if m.message_id != ids[0] {
            alice.core.abandon_outgoing(to_bob, m.message_id).unwrap();
        }
    }

    lose_mailbox(&addr, &bob);
    let alice_key = alice.core.our_identity_pk().unwrap();
    inject(&addr, &bob, Envelope::Message { sender: alice_key, wire: late }.encode());
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    // Bob also sends receipts for the three texts he read; Alice's side
    // below shows that text 0 was named.
    assert!(r.dropped == 1 && r.published >= 1, "{r:?}");
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    let record = alice.core.prior_send(&bob.core.our_identity_pk().unwrap(), &client_id::text(b"g0"));
    assert!(
        matches!(record, Ok(Some(SendResult::Abandoned { .. }))),
        "text 0 reads as abandoned: {record:?}"
    );
    let history = alice.net.chat_entries(bob.pk.clone()).unwrap();
    assert_eq!(history[0].state, ChatEntryState::NotDelivered);
    relay.stop();
}

/// A message under a header the session does not know is named back only
/// once the session has received from the contact: before that, on this
/// device's own unconfirmed start, it may be the contact's first message
/// under a handshake of its own (a simultaneous start), and draws no GONE.
/// Afterwards a forged one is named like a late one (the contact ignores
/// an id it has not pending).
#[test]
fn an_unknown_header_draws_no_gone_before_the_session_is_confirmed() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    alice.knows(&bob);
    bob.knows(&alice);
    bob.net.publish_prekeys().unwrap();
    alice.net.start_session(bob.pk.clone()).unwrap();
    let forged = || {
        let header = core_crypto::ratchet::Header {
            dh: [7; 32],
            pn: 0,
            n: 0,
        };
        Envelope::Message {
            sender: bob.core.our_identity_pk().unwrap(),
            wire: [&header.to_bytes()[..], &[0u8; 40][..]].concat(),
        }
        .encode()
    };
    let base = alice.sync();
    assert!(base.errors.is_empty(), "{:?}", base.errors);
    let base = alice.sync();
    inject(&addr, &alice, forged());
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.dropped, r.published), (1, base.published), "no GONE: {r:?}");

    settle(&[&alice, &bob]);
    inject(&addr, &alice, forged());
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.dropped, r.published), (1, 1), "named once confirmed: {r:?}");
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(bob.undelivered(&alice), 0, "nothing of Bob's was named");
    relay.stop();
}
