//! R-14: more than `MAX_SKIP` (1,000) of a contact's messages in a row that
//! never arrive used to stop that direction for good: every later message of
//! the chain lay too far ahead to decrypt. Such a message is now read with a
//! far skip (up to `MAX_FAR_SKIP` positions), once the session has seen far
//! messages of that chain for `FAR_SKIP_WAIT` without accepting one, at the
//! end of a message pass in which it accepted none: one try per session, at
//! most four per round. Most tests here set the wait to zero.

use std::time::Duration;

use super::net_harness::*;
use crate::network::far_hook::{self, Stage};
use crate::network::wire::{client_id, Envelope};
use crate::{ArciumCore, SendResult};
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

/// `d` tries a far skip as soon as a far message arrives.
fn far_at_once(d: &Device) {
    d.net.set_far_skip_wait(Duration::ZERO);
}

/// The far-skip record `d` stores for the session `handle`, if any.
fn far_record(d: &Device, handle: u64) -> Option<Vec<u8>> {
    match d.core.store.lock().unwrap().get(&crate::network::far_wait_key(handle)) {
        Ok(bytes) => Some(bytes.to_vec()),
        Err(core_storage::StorageError::NotFound) => None,
        Err(e) => panic!("{e}"),
    }
}

/// A far message "from" `peer` naming a key of its own: it needs a far
/// skip, and never decrypts.
fn forged_far(peer: &Device, k: u8) -> Vec<u8> {
    let far = Header {
        dh: [k; 32],
        pn: 0,
        n: MAX_SKIP + 10,
    };
    message_from(peer, [&far.to_bytes()[..], &[0u8; 40][..]].concat())
}

/// Gives up the session `handle` of `d` as a reset does, from inside a
/// round: its pending messages first, then the session.
fn retire(d: &ArciumCore, handle: u64) {
    for m in d.pending_outgoing(handle).unwrap() {
        d.abandon_outgoing(handle, m.message_id).unwrap();
    }
    assert!(d.retire_session(handle, &[]).unwrap());
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
    far_at_once(&alice);
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

/// The recipient dies in the far pass of a round: after the far skip
/// committed the message (`after_accept`), and after its receipt was
/// committed too (`after_settle`). The message was deleted from the relay in
/// the message pass, so on the recipient's side only its store holds it (the
/// sender still has it pending, and sends it again). Each time the restarted
/// device shows the text once, the next rounds commit or send the receipt,
/// and the sender ends with the text delivered.
#[cfg(unix)]
#[test]
fn a_recipient_killed_in_the_far_pass_keeps_the_message_and_confirms_it() {
    for point in ["after_accept", "after_settle"] {
        let relay = start_relay();
        let addr = relay.addr().to_string();
        let (alice, bob) = connected(&addr);
        settle(&[&alice, &bob]);
        let to_alice = crate::local_session_handle(alice.pk.clone()).unwrap();
        let to_bob = crate::local_session_handle(bob.pk.clone()).unwrap();
        let (ids, wires) = texts_in_one_chain(&alice, &bob);
        for id in &ids[..GAP] {
            bob.core.abandon_outgoing(to_alice, id.clone()).unwrap();
        }
        let id: [u8; 32] = ids[GAP].as_slice().try_into().unwrap();
        let text = format!("t{GAP}");
        inject(&addr, &alice, message_from(&bob, wires[GAP].clone()));

        super::network_crash::run_child(&alice, &addr, "far_sync", Some(point), &bob.pk);

        let alice = alice.restart(&addr);
        assert_eq!(
            alice.texts(&bob),
            vec![text.clone()],
            "{point}: the far skip committed the message before the death"
        );
        assert!(
            stored_messages(&relay, &alice).is_empty(),
            "{point}: and the relay no longer holds it"
        );
        assert_eq!(far_record(&alice, to_bob), None, "{point}: the wait was deleted");
        // A round that ended would have published the receipt: the child
        // died before that, so the crash point fired.
        assert!(
            stored_messages(&relay, &bob).is_empty(),
            "{point}: the round did not reach its last publish"
        );
        // The receipt tells the two points apart.
        let receipts = alice.core.pending_outgoing(to_bob).unwrap();
        if point == "after_accept" {
            assert!(receipts.is_empty(), "{point}: no receipt yet: {}", receipts.len());
        } else {
            assert_eq!(receipts.len(), 1, "{point}: the receipt is committed, not sent");
            assert_eq!(receipts[0].client_message_id, client_id::receipt(&id, 0), "{point}");
        }

        settle(&[&alice, &bob]);
        assert_eq!(alice.accepted_total(), 0, "{point}: nothing accepted twice");
        assert_eq!(alice.texts(&bob), vec![text], "{point}: shown once");
        assert_eq!(bob.undelivered(&alice), 0, "{point}: delivered");
        assert!(alice.core.pending_outgoing(to_bob).unwrap().is_empty(), "{point}");
        relay.stop();
    }
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
    far_at_once(&alice);
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
    far_at_once(&alice);
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
    // Two more far messages "from" the last contact, with keys of their own:
    // a session is judged once per pass, also when the round is full.
    for k in [10u8, 11] {
        let other = Header { dh: [k; 32], ..far };
        inject(&addr, &alice, message_from(&peers[5], [&other.to_bytes()[..], &[0u8; 40][..]].concat()));
    }
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.dropped, 8, "{r:?}");
    assert_eq!(alice.net.far_tries(), crate::network::FAR_TRIES_PER_ROUND as u32);
    assert_eq!(crate::network::FAR_TRIES_PER_ROUND, 4);
    let last = crate::local_session_handle(peers[5].pk.clone()).unwrap();
    assert_eq!(alice.net.far_waits(last), 1, "judged once in the pass");
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
    far_at_once(&alice);
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

/// Counts, for each of Bob's texts `f0`..`f{n-1}`, the outcome Bob reads
/// from its send record: (delivered, given up).
fn outcomes(alice: &Device, bob: &Device, n: usize) -> (usize, usize) {
    let alice_pk = alice.core.our_identity_pk().unwrap();
    let (mut delivered, mut abandoned) = (0, 0);
    for i in 0..n {
        match bob.core.prior_send(&alice_pk, &client_id::text(format!("f{i}").as_bytes())) {
            Ok(Some(SendResult::AlreadyAcknowledged { .. })) => delivered += 1,
            Ok(Some(SendResult::Abandoned { .. })) => abandoned += 1,
            other => panic!("f{i}: {other:?}"),
        }
    }
    (delivered, abandoned)
}

/// The relay lost (or expired) the first 1,200 of 1,501 texts, and Bob's
/// retransmission stored them again behind the later ones, which Alice now
/// reads first, more than `MAX_SKIP` ahead. With the wait, the far ones are
/// not skipped to: the older ones are read in the same round, and the later
/// ones when they come again. Every text is delivered, as before far skips;
/// skipping at once gave up 200 of them (review of PR #209).
#[test]
fn a_rotated_mailbox_delivers_every_text() {
    const N: usize = 1501;
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    settle(&[&alice, &bob]);
    for i in 0..N {
        bob.send(&alice, &format!("f{i}"), &format!("t{i}"));
    }
    assert!(bob.sync().errors.is_empty());
    let key: [u8; 32] = alice.pk.as_slice().try_into().unwrap();
    let lost: Vec<u64> = relay.stored(&key).iter().take(1200).map(|(s, _)| *s).collect();
    relay::client::Connection::connect(&addr, Duration::from_secs(2))
        .unwrap()
        .delete(key, lost)
        .unwrap();
    assert!(bob.sync().errors.is_empty(), "stores the lost ones again");
    assert_eq!(relay.stored(&key).len(), N);
    for _ in 0..8 {
        assert!(alice.sync().errors.is_empty());
        assert!(bob.sync().errors.is_empty());
        if bob.undelivered(&alice) == 0 {
            break;
        }
    }
    assert_eq!(alice.net.far_tries(), 0);
    assert_eq!(outcomes(&alice, &bob, N), (N, 0));
    relay.stop();
}

/// The relay lost the first 1,200 of 1,501 texts; Alice reads the rest
/// before Bob sends the lost ones again. As above, every text is delivered.
#[test]
fn a_lost_start_sent_again_later_delivers_every_text() {
    const N: usize = 1501;
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    settle(&[&alice, &bob]);
    for i in 0..N {
        bob.send(&alice, &format!("f{i}"), &format!("t{i}"));
    }
    assert!(bob.sync().errors.is_empty());
    let key: [u8; 32] = alice.pk.as_slice().try_into().unwrap();
    let lost: Vec<u64> = relay.stored(&key).iter().take(1200).map(|(s, _)| *s).collect();
    relay::client::Connection::connect(&addr, Duration::from_secs(2))
        .unwrap()
        .delete(key, lost)
        .unwrap();
    for _ in 0..8 {
        assert!(alice.sync().errors.is_empty());
        assert!(bob.sync().errors.is_empty());
        if bob.undelivered(&alice) == 0 {
            break;
        }
    }
    assert_eq!(alice.net.far_tries(), 0);
    assert_eq!(outcomes(&alice, &bob, N), (N, 0));
    relay.stop();
}

/// A far skip is tried only once the session has seen far messages for the
/// wait without accepting one.
#[test]
fn a_far_skip_waits_for_the_gap_to_stay_open() {
    let wait = Duration::from_millis(300);
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    settle(&[&alice, &bob]);
    alice.net.set_far_skip_wait(wait);
    let to_alice = crate::local_session_handle(alice.pk.clone()).unwrap();
    let (ids, wires) = texts_in_one_chain(&alice, &bob);
    for id in &ids[..GAP] {
        bob.core.abandon_outgoing(to_alice, id.clone()).unwrap();
    }
    inject(&addr, &alice, message_from(&bob, wires[GAP].clone()));
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.accepted, r.dropped, alice.net.far_tries()), (0, 1, 0), "{r:?}");

    std::thread::sleep(wait + Duration::from_millis(50));
    inject(&addr, &alice, message_from(&bob, wires[GAP].clone()));
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.accepted, alice.net.far_tries()), (1, 1), "{r:?}");
    relay.stop();
}

/// A message the session accepts starts the wait again, and a far message
/// seen in the same round, even before it, is not skipped to: the gap may be
/// filling.
#[test]
fn accepting_a_message_starts_the_wait_again() {
    let wait = Duration::from_millis(300);
    let pause = wait + Duration::from_millis(50);
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    settle(&[&alice, &bob]);
    alice.net.set_far_skip_wait(wait);
    let to_alice = crate::local_session_handle(alice.pk.clone()).unwrap();
    // One text Alice can read, a gap of GAP given up, one far text.
    let near = bob.send(&alice, "near", "near");
    let (ids, wires) = texts_in_one_chain(&alice, &bob);
    for id in &ids[..GAP] {
        bob.core.abandon_outgoing(to_alice, id.clone()).unwrap();
    }
    let near_wire = bob
        .core
        .pending_outgoing(to_alice)
        .unwrap()
        .into_iter()
        .find(|m| m.message_id == near)
        .unwrap()
        .wire;
    let far = || message_from(&bob, wires[GAP].clone());

    inject(&addr, &alice, far()); // first seen
    assert!(alice.sync().errors.is_empty());
    std::thread::sleep(pause);
    inject(&addr, &alice, far()); // the wait is over, but...
    inject(&addr, &alice, message_from(&bob, near_wire)); // ...this is accepted
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(
        (r.accepted, r.dropped, alice.net.far_tries()),
        (1, 1, 0),
        "not skipped to, and counted dropped: {r:?}"
    );

    inject(&addr, &alice, far()); // the wait starts again
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.accepted, alice.net.far_tries()), (0, 0), "{r:?}");
    std::thread::sleep(pause);
    inject(&addr, &alice, far());
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.accepted, alice.net.far_tries()), (1, 1), "{r:?}");
    relay.stop();
}

/// The wait is kept per chain: a forged far message naming a key of its own
/// (anyone who can write to the mailbox can make one) does not start the
/// wait of the genuine chain, which waits in full when it first shows.
#[test]
fn a_forged_far_message_does_not_start_a_genuine_chains_wait() {
    let wait = Duration::from_millis(300);
    let pause = wait + Duration::from_millis(50);
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    settle(&[&alice, &bob]);
    alice.net.set_far_skip_wait(wait);
    let to_alice = crate::local_session_handle(alice.pk.clone()).unwrap();
    let (ids, wires) = texts_in_one_chain(&alice, &bob);
    for id in &ids[..GAP] {
        bob.core.abandon_outgoing(to_alice, id.clone()).unwrap();
    }
    let forged = Header {
        dh: [9; 32],
        pn: 0,
        n: MAX_SKIP + 10,
    };
    inject(&addr, &alice, message_from(&bob, [&forged.to_bytes()[..], &[0u8; 40][..]].concat()));
    assert!(alice.sync().errors.is_empty());
    std::thread::sleep(pause);

    inject(&addr, &alice, message_from(&bob, wires[GAP].clone()));
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.accepted, alice.net.far_tries()), (0, 0), "its own wait: {r:?}");
    std::thread::sleep(pause);
    inject(&addr, &alice, message_from(&bob, wires[GAP].clone()));
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.accepted, alice.net.far_tries()), (1, 1), "{r:?}");
    relay.stop();
}

/// Deleting a contact forgets its far-skip waits: a new session with it has
/// the same handle.
#[test]
fn deleting_a_contact_forgets_its_far_waits() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    settle(&[&alice, &bob]);
    let to_bob = crate::local_session_handle(bob.pk.clone()).unwrap();
    let far = Header {
        dh: [9; 32],
        pn: 0,
        n: MAX_SKIP + 10,
    };
    inject(&addr, &alice, message_from(&bob, [&far.to_bytes()[..], &[0u8; 40][..]].concat()));
    assert!(alice.sync().errors.is_empty());
    assert_eq!(alice.net.far_waits(to_bob), 1);
    assert!(far_record(&alice, to_bob).is_some());
    alice.net.delete_contact(bob.pk.clone()).unwrap();
    assert_eq!(alice.net.far_waits(to_bob), 0);
    assert_eq!(far_record(&alice, to_bob), None, "deleted with the contact");
    relay.stop();
}

/// When a session holds `FAR_CHAINS_PER_SESSION` waits, a new key drops
/// the chain seen least recently. A genuine chain that keeps being judged
/// keeps its wait against forged keys, unless four of them are judged
/// between two passes in which it is.
#[test]
fn a_genuine_chain_that_keeps_arriving_keeps_its_wait() {
    let wait = Duration::from_millis(300);
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    settle(&[&alice, &bob]);
    alice.net.set_far_skip_wait(wait);
    let to_alice = crate::local_session_handle(alice.pk.clone()).unwrap();
    let to_bob = crate::local_session_handle(bob.pk.clone()).unwrap();
    let (ids, wires) = texts_in_one_chain(&alice, &bob);
    for id in &ids[..GAP] {
        bob.core.abandon_outgoing(to_alice, id.clone()).unwrap();
    }
    let genuine = || message_from(&bob, wires[GAP].clone());
    let forged = |k: u8| {
        let h = Header {
            dh: [k; 32],
            pn: 0,
            n: MAX_SKIP + 10,
        };
        message_from(&bob, [&h.to_bytes()[..], &[0u8; 40][..]].concat())
    };
    let round = |env: Vec<u8>| {
        inject(&addr, &alice, env);
        let r = alice.sync();
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        r
    };
    round(genuine()); // its wait starts
    round(forged(1));
    round(genuine()); // seen again
    round(forged(2));
    round(forged(3));
    round(forged(4)); // four chains held: the one seen least recently (1) goes
    assert_eq!(alice.net.far_waits(to_bob), 4);
    std::thread::sleep(wait + Duration::from_millis(50));
    let r = round(genuine());
    assert_eq!((r.accepted, alice.net.far_tries()), (1, 1), "its wait was kept: {r:?}");
    relay.stop();
}

/// The wait counts from a chain's first arrival, not its last: a chain that
/// arrives every two thirds of the wait is tried once the wait has passed
/// since it first came.
#[test]
fn the_wait_counts_from_the_first_arrival() {
    let wait = Duration::from_millis(300);
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    settle(&[&alice, &bob]);
    alice.net.set_far_skip_wait(wait);
    let to_alice = crate::local_session_handle(alice.pk.clone()).unwrap();
    let (ids, wires) = texts_in_one_chain(&alice, &bob);
    for id in &ids[..GAP] {
        bob.core.abandon_outgoing(to_alice, id.clone()).unwrap();
    }
    let round = || {
        inject(&addr, &alice, message_from(&bob, wires[GAP].clone()));
        let r = alice.sync();
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        r
    };
    round(); // first arrival
    std::thread::sleep(wait * 2 / 3);
    let r = round();
    assert_eq!((r.accepted, alice.net.far_tries()), (0, 0), "{r:?}");
    std::thread::sleep(wait * 2 / 3);
    let r = round(); // the wait has passed since the first arrival
    assert_eq!((r.accepted, alice.net.far_tries()), (1, 1), "{r:?}");
    relay.stop();
}

/// The wait goes on across a restart of the process (tracker R-14, R-20):
/// it is kept in the store. Before, the new process started it again, so a
/// gap healed only in a process that lived through the whole wait.
#[test]
fn the_wait_goes_on_across_a_restart() {
    let wait = Duration::from_millis(300);
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    settle(&[&alice, &bob]);
    alice.net.set_far_skip_wait(wait);
    let to_alice = crate::local_session_handle(alice.pk.clone()).unwrap();
    let to_bob = crate::local_session_handle(bob.pk.clone()).unwrap();
    let (ids, wires) = texts_in_one_chain(&alice, &bob);
    for id in &ids[..GAP] {
        bob.core.abandon_outgoing(to_alice, id.clone()).unwrap();
    }
    inject(&addr, &alice, message_from(&bob, wires[GAP].clone()));
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.accepted, alice.net.far_tries()), (0, 0), "{r:?}");
    assert!(far_record(&alice, to_bob).is_some(), "the wait is stored");
    std::thread::sleep(wait + Duration::from_millis(50));

    let alice = alice.restart(&addr);
    alice.net.set_far_skip_wait(wait);
    assert_eq!(alice.net.far_waits(to_bob), 0, "nothing read yet");
    inject(&addr, &alice, message_from(&bob, wires[GAP].clone()));
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.accepted, alice.net.far_tries()), (1, 1), "the wait was kept: {r:?}");
    assert_eq!(alice.texts(&bob).last().map(String::as_str), Some(format!("t{GAP}").as_str()));
    assert_eq!(far_record(&alice, to_bob), None, "deleted once a message is accepted");
    relay.stop();
}

/// A message the session accepts deletes the stored wait too: a new
/// process starts the wait again instead of reading the old one.
#[test]
fn an_accepted_message_deletes_the_stored_wait() {
    let wait = Duration::from_millis(300);
    let pause = wait + Duration::from_millis(50);
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    settle(&[&alice, &bob]);
    alice.net.set_far_skip_wait(wait);
    let to_alice = crate::local_session_handle(alice.pk.clone()).unwrap();
    let to_bob = crate::local_session_handle(bob.pk.clone()).unwrap();
    let near = bob.send(&alice, "near", "near");
    let (ids, wires) = texts_in_one_chain(&alice, &bob);
    for id in &ids[..GAP] {
        bob.core.abandon_outgoing(to_alice, id.clone()).unwrap();
    }
    let near_wire = bob
        .core
        .pending_outgoing(to_alice)
        .unwrap()
        .into_iter()
        .find(|m| m.message_id == near)
        .unwrap()
        .wire;
    let far = || message_from(&bob, wires[GAP].clone());

    inject(&addr, &alice, far());
    assert!(alice.sync().errors.is_empty());
    assert!(far_record(&alice, to_bob).is_some());
    inject(&addr, &alice, message_from(&bob, near_wire));
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.accepted, 1, "{r:?}");
    assert_eq!(far_record(&alice, to_bob), None);
    std::thread::sleep(pause);

    let alice = alice.restart(&addr);
    alice.net.set_far_skip_wait(wait);
    inject(&addr, &alice, far());
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.accepted, alice.net.far_tries()), (0, 0), "the wait starts again: {r:?}");
    relay.stop();
}

/// Giving the session up (a reset) forgets its far-skip waits, in memory
/// and in the store: the next session with the contact has the same
/// handle. (One of the three paths the review of PR #209 found untested.)
#[test]
fn resetting_the_session_forgets_its_far_waits() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    settle(&[&alice, &bob]);
    let to_bob = crate::local_session_handle(bob.pk.clone()).unwrap();
    inject(&addr, &alice, forged_far(&bob, 9));
    assert!(alice.sync().errors.is_empty());
    assert_eq!(alice.net.far_waits(to_bob), 1);
    assert!(far_record(&alice, to_bob).is_some());
    alice.net.reset_session(bob.pk.clone()).unwrap();
    assert_eq!(alice.net.far_waits(to_bob), 0);
    assert_eq!(far_record(&alice, to_bob), None);
    relay.stop();
}

/// A far try that fails other than by not decrypting (here the session was
/// given up between the message pass and the try) is counted dropped and
/// reported, and the pass goes on to the next session's try. (Untested
/// before, review of PR #209.)
#[test]
fn a_far_try_that_fails_otherwise_is_dropped_and_reported() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    let carol = Device::new(&addr, 3);
    alice.knows(&carol);
    carol.knows(&alice);
    carol.net.publish_prekeys().unwrap();
    alice.net.start_session(carol.pk.clone()).unwrap();
    settle(&[&alice, &bob, &carol]);
    far_at_once(&alice);
    let to_bob = crate::local_session_handle(bob.pk.clone()).unwrap();
    inject(&addr, &alice, forged_far(&bob, 9));
    inject(&addr, &alice, forged_far(&carol, 9));
    let core = alice.core.clone();
    far_hook::set(move |stage, handle| {
        if stage == Stage::BeforeTry && handle == to_bob {
            retire(&core, handle);
        }
    });
    let r = alice.sync();
    far_hook::clear();
    let failed: Vec<&String> = r
        .errors
        .iter()
        .filter(|e| e.starts_with("reading a message far ahead in its chain"))
        .collect();
    assert_eq!(failed.len(), 1, "{:?}", r.errors);
    assert_eq!((r.dropped, alice.net.far_tries()), (2, 2), "{r:?}");
    relay.stop();
}

/// A message read with a far skip that then fails to settle (here its
/// session was given up before the receipt) is reported, and the pass goes
/// on to the next session's try. (Untested before, review of PR #209.)
#[test]
fn a_failed_settle_leaves_the_far_pass_going() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    let carol = Device::new(&addr, 3);
    alice.knows(&carol);
    carol.knows(&alice);
    carol.net.publish_prekeys().unwrap();
    alice.net.start_session(carol.pk.clone()).unwrap();
    settle(&[&alice, &bob, &carol]);
    far_at_once(&alice);
    let to_alice = crate::local_session_handle(alice.pk.clone()).unwrap();
    for peer in [&bob, &carol] {
        let (ids, wires) = texts_in_one_chain(&alice, peer);
        for id in &ids[..GAP] {
            peer.core.abandon_outgoing(to_alice, id.clone()).unwrap();
        }
        inject(&addr, &alice, message_from(peer, wires[GAP].clone()));
    }
    let core = alice.core.clone();
    let mut first = None;
    far_hook::set(move |stage, handle| {
        if stage == Stage::BeforeSettle && first.is_none() {
            first = Some(handle);
            retire(&core, handle);
        }
    });
    let r = alice.sync();
    far_hook::clear();
    let failed: Vec<&String> = r
        .errors
        .iter()
        .filter(|e| e.starts_with("settling a message read with a far skip"))
        .collect();
    assert_eq!(failed.len(), 1, "{:?}", r.errors);
    assert_eq!((r.accepted, alice.net.far_tries()), (2, 2), "{r:?}");
    relay.stop();
}

/// A stored wait that does not parse is read as none: the wait starts at
/// the next far message, the record is replaced with a good one, and the
/// far skip comes once that wait is over (a damaged record holds nothing
/// back for good).
#[test]
fn a_damaged_stored_wait_is_read_as_none_and_replaced() {
    let wait = Duration::from_millis(300);
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    settle(&[&alice, &bob]);
    let to_alice = crate::local_session_handle(alice.pk.clone()).unwrap();
    let to_bob = crate::local_session_handle(bob.pk.clone()).unwrap();
    let (ids, wires) = texts_in_one_chain(&alice, &bob);
    for id in &ids[..GAP] {
        bob.core.abandon_outgoing(to_alice, id.clone()).unwrap();
    }
    alice
        .core
        .store
        .lock()
        .unwrap()
        .put(&crate::network::far_wait_key(to_bob), &[1, 9, 9])
        .unwrap();
    let alice = alice.restart(&addr);
    alice.net.set_far_skip_wait(wait);
    inject(&addr, &alice, message_from(&bob, wires[GAP].clone()));
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.accepted, alice.net.far_tries()), (0, 0), "{r:?}");
    let replaced = far_record(&alice, to_bob).expect("written again");
    assert_eq!((replaced.len(), &replaced[..2]), (2 + 48, &[1u8, 1][..]));
    std::thread::sleep(wait + Duration::from_millis(50));
    inject(&addr, &alice, message_from(&bob, wires[GAP].clone()));
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.accepted, alice.net.far_tries()), (1, 1), "{r:?}");
    relay.stop();
}

/// A chain's wait is stored when it starts, and a far message of the same
/// chain seen again within the minute writes nothing more: the last
/// sighting only orders the chains for dropping.
#[test]
fn a_chain_seen_again_within_a_minute_is_stored_once() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    settle(&[&alice, &bob]);
    let to_bob = crate::local_session_handle(bob.pk.clone()).unwrap();
    for _ in 0..3 {
        inject(&addr, &alice, forged_far(&bob, 9));
        let r = alice.sync();
        assert!(r.errors.is_empty(), "{:?}", r.errors);
    }
    assert_eq!(alice.net.far_waits(to_bob), 1);
    assert_eq!(alice.net.far_writes(), 1, "stored once");
    inject(&addr, &alice, forged_far(&bob, 10));
    assert!(alice.sync().errors.is_empty());
    assert_eq!(alice.net.far_writes(), 2, "a new chain is stored at once");
    relay.stop();
}

/// A far message whose wait is not over is not named back as late (R-21
/// beyond the remembered chains), however often it arrives: its key is not
/// gone, a far skip may read it later. Here a header of a key the session
/// never saw, far ahead.
#[test]
fn a_far_message_in_its_wait_draws_no_gone() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    settle(&[&alice, &bob]);
    alice.net.set_far_skip_wait(Duration::from_secs(600));
    for arrival in 1..=2 {
        inject(&addr, &alice, forged_far(&bob, 9));
        let r = alice.sync();
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert_eq!((r.dropped, r.published, alice.net.far_tries()), (1, 0, 0), "arrival {arrival}: {r:?}");
    }
    relay.stop();
}
