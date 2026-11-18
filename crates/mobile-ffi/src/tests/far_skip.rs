//! R-14: more than `MAX_SKIP` (1,000) of a contact's messages in a row that
//! never arrive used to stop that direction for good: every later message of
//! the chain lay too far ahead to decrypt. Such a message is now read with a
//! far skip (up to `MAX_FAR_SKIP` positions): one try per session, at most
//! four per round.

use super::net_harness::*;
use crate::network::wire::{client_id, Envelope};
use crate::SendResult;
use core_crypto::ratchet::{Header, HEADER_SIZE, MAX_SKIP};

const GAP: usize = MAX_SKIP as usize + 500;

/// Bob commits `GAP + 1` texts to Alice in one chain; nothing is sent yet.
/// Returns their ids and wires, in order.
fn texts_in_one_chain(alice: &Device, bob: &Device) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let to_alice = crate::local_session_handle(alice.pk.clone()).unwrap();
    let ids: Vec<Vec<u8>> = (0..=GAP).map(|i| bob.send(alice, &format!("f{i}"), &format!("t{i}"))).collect();
    let pending = bob.core.pending_outgoing(to_alice).unwrap();
    let wires = ids
        .iter()
        .map(|id| pending.iter().find(|m| &m.message_id == id).expect("pending").wire.clone())
        .collect();
    (ids, wires)
}

fn message_from(bob: &Device, wire: Vec<u8>) -> Vec<u8> {
    Envelope::Message {
        sender: bob.core.our_identity_pk().unwrap(),
        wire,
    }
    .encode()
}

/// R-14 (and R-20): Bob gives up the first `GAP` of his texts after they
/// were encrypted, so they are never sent. The last one lies `GAP`
/// positions ahead of what Alice read. Before, she could never read it, nor
/// anything after it in that chain; now it arrives, and both directions go
/// on.
#[test]
fn a_gap_of_more_than_max_skip_in_one_chain_is_crossed() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    settle(&[&alice, &bob]);
    let to_alice = crate::local_session_handle(alice.pk.clone()).unwrap();
    let (ids, _) = texts_in_one_chain(&alice, &bob);
    for id in &ids[..GAP] {
        bob.core.abandon_outgoing(to_alice, id.clone()).unwrap();
    }
    settle(&[&bob, &alice]);
    assert_eq!(alice.texts(&bob).last().map(String::as_str), Some(format!("t{GAP}").as_str()));
    assert_eq!(bob.undelivered(&alice), 0, "delivered");

    bob.send(&alice, "after", "after the gap");
    alice.send(&bob, "back", "and back");
    settle(&[&bob, &alice]);
    assert_eq!(alice.texts(&bob).last().map(String::as_str), Some("after the gap"));
    assert_eq!(bob.texts(&alice).last().map(String::as_str), Some("and back"));
    assert_eq!((alice.undelivered(&bob), bob.undelivered(&alice)), (0, 0));
    relay.stop();
}

/// A far skip may derive up to `MAX_FAR_SKIP` keys per chain before the
/// message authenticates, so a session gets one try per round. A forged far
/// message ahead of the genuine one takes it; the genuine one is then
/// deleted like any message that does not decrypt (nothing is kept on the
/// relay for whoever wrote the forgery to count, R-9), and is read when it
/// is sent again.
#[test]
fn far_messages_get_one_try_per_session_per_round() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    settle(&[&alice, &bob]);
    let to_alice = crate::local_session_handle(alice.pk.clone()).unwrap();
    let (ids, wires) = texts_in_one_chain(&alice, &bob);
    for id in &ids[..GAP] {
        bob.core.abandon_outgoing(to_alice, id.clone()).unwrap();
    }
    let genuine = &wires[GAP];
    let header = Header::from_bytes(&genuine[..HEADER_SIZE]).unwrap();
    let forged = Header {
        n: header.n + MAX_SKIP,
        ..header
    };
    let wire = [&forged.to_bytes()[..], &genuine[HEADER_SIZE..]].concat();
    inject(&addr, &alice, message_from(&bob, wire));
    let r = bob.sync(); // Sends the genuine text, behind the forged one.
    assert!(r.errors.is_empty(), "{:?}", r.errors);

    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.dropped, r.deferred, r.accepted), (2, 0, 0), "{r:?}");
    assert_eq!(alice.net.far_tries(), 1, "one try");
    assert!(stored_messages(&relay, &alice).is_empty(), "nothing kept");

    // Bob sends it again.
    inject(&addr, &alice, message_from(&bob, genuine.clone()));
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.accepted, 1, "{r:?}");
    assert_eq!(alice.net.far_tries(), 2);
    assert_eq!(alice.texts(&bob).last().map(String::as_str), Some(format!("t{GAP}").as_str()));
    relay.stop();
}

/// Over all sessions, at most `FAR_TRIES_PER_ROUND` far skips are tried in
/// one round: a forged far message "from" each of six contacts costs four
/// tries. A far header needs no knowledge of the session: a key the session
/// never saw and a position past `MAX_SKIP` are enough.
#[test]
fn at_most_four_far_skips_are_tried_per_round() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let alice = Device::new(&addr, 40);
    let peers: Vec<Device> = (41..47).map(|b| Device::new(&addr, b)).collect();
    for p in &peers {
        alice.knows(p);
        p.knows(&alice);
        p.net.publish_prekeys().unwrap();
        alice.net.start_session(p.pk.clone()).unwrap();
    }
    let all: Vec<&Device> = std::iter::once(&alice).chain(peers.iter()).collect();
    settle(&all);
    let far = Header {
        dh: [9; 32],
        pn: 0,
        n: MAX_SKIP + 10,
    };
    let wire = [&far.to_bytes()[..], &[0u8; 40][..]].concat();
    for p in &peers {
        inject(&addr, &alice, message_from(p, wire.clone()));
    }
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.dropped, 6, "{r:?}");
    assert_eq!(alice.net.far_tries(), crate::network::FAR_TRIES_PER_ROUND as u32);
    assert_eq!(crate::network::FAR_TRIES_PER_ROUND, 4);
    relay.stop();
}

/// The relay loses the first `GAP` of Bob's texts. The last one is read
/// with a far skip, which keeps the keys of only the last `MAX_SKIP`
/// positions. A lost text sent again from before those can never be read:
/// Alice names it in a GONE message (R-21), and Bob's history shows it not
/// delivered, so he can send it again.
#[test]
fn a_text_lost_before_the_kept_keys_is_named_back() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    settle(&[&alice, &bob]);
    let (_, wires) = texts_in_one_chain(&alice, &bob);
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);

    // The relay loses everything stored for Alice but the last text.
    let key: [u8; 32] = alice.pk.as_slice().try_into().unwrap();
    let lost: Vec<u64> = relay
        .stored(&key)
        .into_iter()
        .filter(|(_, env)| *env != message_from(&bob, wires[GAP].clone()))
        .map(|(seq, _)| seq)
        .collect();
    assert_eq!(lost.len(), GAP);
    relay::client::Connection::connect(&addr, std::time::Duration::from_secs(2))
        .unwrap()
        .delete(key, lost)
        .unwrap();

    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.accepted, 1, "read with a far skip: {r:?}");

    // Text 0 arrives again, from before the kept keys; text GAP - 1 is kept.
    inject(&addr, &alice, message_from(&bob, wires[0].clone()));
    inject(&addr, &alice, message_from(&bob, wires[GAP - 1].clone()));
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.accepted, r.dropped), (1, 1), "{r:?}");

    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    let record = bob.core.prior_send(&alice.core.our_identity_pk().unwrap(), &client_id::text(b"f0"));
    assert!(
        matches!(record, Ok(Some(SendResult::Abandoned { .. }))),
        "text 0 is given up: {record:?}"
    );
    relay.stop();
}
