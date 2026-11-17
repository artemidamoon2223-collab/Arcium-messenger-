//! R-21: a message that reaches its recipient after its key was evicted can
//! never be read. The recipient names it in a GONE message; the sender stops
//! sending it, and the text reads as abandoned (NotDelivered in a history).

use super::net_harness::*;
use crate::network::wire::{client_id, Envelope, Payload};
use crate::SendResult;

#[test]
fn a_message_whose_key_is_gone_is_named_back_and_abandoned() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    let to_bob = crate::local_session_handle(bob.pk.clone()).unwrap();
    let to_alice = crate::local_session_handle(alice.pk.clone()).unwrap();

    // Alice commits 2,101 texts in one sending chain; none is sent yet.
    let ids: Vec<Vec<u8>> = (0..2101).map(|i| alice.send(&bob, &format!("g{i}"), "x")).collect();
    let pending = alice.core.pending_outgoing(to_bob).unwrap();
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

    // Text 0 reaches Bob late: it cannot be read, and Bob names it.
    inject(
        &addr,
        &bob,
        Envelope::Message {
            sender: alice.core.our_identity_pk().unwrap(),
            wire: late,
        }
        .encode(),
    );
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.dropped, 1, "{r:?}");

    // Alice reads the GONE message and stops sending text 0.
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(alice.undelivered(&bob), 0, "text 0 is no longer pending");
    let record = alice.core.prior_send(&bob.core.our_identity_pk().unwrap(), &client_id::text(b"g0"));
    assert!(
        matches!(record, Ok(Some(SendResult::Abandoned { .. }))),
        "text 0 reads as abandoned: {record:?}"
    );

    // Its last retransmission reaches Bob: found again, named under the same
    // client id, so nothing new is committed.
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.published, 0, "no second GONE message: {r:?}");
    relay.stop();
}

/// A GONE message changes nothing for an id the sender has not pending as a
/// text: another message, or one already delivered.
#[test]
fn a_gone_message_ignores_ids_it_does_not_hold_pending() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    let to_alice = crate::local_session_handle(alice.pk.clone()).unwrap();
    let delivered = alice.send(&bob, "d", "delivered");
    settle(&[&alice, &bob]);
    assert_eq!(alice.undelivered(&bob), 0);
    let kept = alice.send(&bob, "k", "kept");

    let named = vec![[0x55; 32], <[u8; 32]>::try_from(delivered.as_slice()).unwrap()];
    bob.core
        .send_committed(to_alice, &client_id::gone(&named), &Payload::Gone(named.clone()).encode())
        .unwrap();
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(alice.undelivered(&bob), 1, "the pending text stays");
    assert_eq!(alice.net.undelivered(bob.pk.clone()).unwrap(), vec![kept]);
    relay.stop();
}
