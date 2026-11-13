//! P-1 of the 2026-11-12 review: the relay refusing to store an envelope for
//! one recipient (a full mailbox) must not end the round for everyone
//! (docs/NET-MESSAGING.md, section 7). The relay here holds 8 envelopes per
//! mailbox, and a mailbox is filled directly, as anyone can on a relay
//! without sender authentication.

use std::net::TcpListener;
use std::time::Duration;

use super::net_harness::*;
use crate::network::NetworkMessenger;
use relay::server::{serve, RelayConfig, RelayHandle};

const LIMIT: usize = 8;

/// The report line of a round in which the relay refused one recipient.
const REFUSED: &str = "relay refused 1 recipient: Full";

fn small_relay() -> RelayHandle {
    serve(
        TcpListener::bind("127.0.0.1:0").unwrap(),
        RelayConfig {
            max_mailbox: LIMIT,
            canary: Some(CANARY.to_vec()),
            ..RelayConfig::default()
        },
    )
    .unwrap()
}

fn key(d: &Device) -> [u8; 32] {
    d.pk.as_slice().try_into().unwrap()
}

/// Fills `to`'s mailbox with envelopes its owner drops as malformed.
fn fill(relay: &str, to: &Device) {
    for i in 0..LIMIT {
        inject(relay, to, vec![i as u8; 10]);
    }
}

/// Bob has a session to start and two texts for Carol, whose mailbox is
/// full. Alice writes to Bob, and Bob writes to Alice. Before the fix the
/// first refused SEND ended every round of Bob's before his mailbox was read:
/// nothing arrived from Alice and nothing left for her, for as long as
/// Carol's mailbox stayed full. Now only Carol waits.
#[test]
fn a_full_mailbox_of_one_contact_does_not_stop_the_round() {
    let relay = small_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    let carol = Device::new(&addr, 3);
    bob.knows(&carol);
    carol.knows(&bob);
    carol.net.publish_prekeys().unwrap();
    fill(&addr, &carol);

    bob.net.start_session(carol.pk.clone()).unwrap();
    bob.send(&carol, "c1", "first for carol");
    bob.send(&carol, "c2", "second for carol");
    alice.send(&bob, "a1", "hello bob");
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    bob.send(&alice, "b1", "hello alice");

    for round in 1..=3 {
        let r = bob.sync();
        if round == 1 {
            assert_eq!(r.accepted, 1, "Alice's text, in the first round: {r:?}");
        }
        // The relay was reached: no line the application reads as offline.
        assert_eq!(r.errors, [REFUSED], "round {round}");
        assert!(!r.errors[0].starts_with("network:"));
        // One refused SEND per round: after it, the round sends Carol
        // nothing more, in either of its two sending steps.
        assert_eq!(bob.net.refusals_in_a_row(&key(&carol)), round);
    }
    assert_eq!(bob.texts(&alice), ["hello bob"]);
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(alice.texts(&bob), ["hello alice"]);
    // Nothing of Bob's is in Carol's mailbox, and nothing was given up.
    assert_eq!(relay.stored(&key(&carol)).len(), LIMIT);
    assert_eq!(bob.undelivered(&carol), 2);

    // Carol reads her mailbox, which empties it. Bob's next round stores
    // everything, in order, and each text arrives once.
    let r = carol.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.dropped as usize, LIMIT);
    settle(&[&bob, &carol, &alice]);
    assert_eq!(carol.texts(&bob), ["first for carol", "second for carol"]);
    assert_eq!(bob.undelivered(&carol), 0);
    assert_eq!(bob.undelivered(&alice), 0);
    relay.stop();
}

/// A refused recipient is not tried again before its wait is over, and the
/// wait doubles; meanwhile nothing is sent to it, so a text queued during
/// the wait cannot overtake the refused one. Waits here: 600 ms, then 1.2 s.
#[test]
fn a_refused_recipient_waits_and_its_texts_keep_their_order() {
    let relay = small_relay();
    let addr = relay.addr().to_string();
    let (_alice, bob) = connected(&addr);
    let carol = Device::new(&addr, 3);
    bob.knows(&carol);
    carol.knows(&bob);
    carol.net.publish_prekeys().unwrap();
    fill(&addr, &carol);
    bob.net.start_session(carol.pk.clone()).unwrap();
    bob.send(&carol, "c1", "first for carol");

    let net = NetworkMessenger::new(bob.core.clone(), addr.clone(), 600, 2000);
    assert_eq!(net.sync().errors, [REFUSED], "first refusal");
    // Carol's mailbox empties right away, and Bob queues another text.
    let r = carol.sync();
    assert_eq!(r.dropped as usize, LIMIT);
    bob.send(&carol, "c2", "second for carol");
    let r = net.sync();
    assert!(r.errors.is_empty(), "within the wait nothing is tried: {:?}", r.errors);
    assert!(relay.stored(&key(&carol)).is_empty(), "nothing overtakes the refused send");

    // The mailbox fills again before the wait is over: a second refusal,
    // and a wait twice as long.
    fill(&addr, &carol);
    std::thread::sleep(Duration::from_millis(700));
    assert_eq!(net.sync().errors, [REFUSED], "second refusal");
    let r = carol.sync();
    assert_eq!(r.dropped as usize, LIMIT);
    std::thread::sleep(Duration::from_millis(700));
    let r = net.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert!(relay.stored(&key(&carol)).is_empty(), "still within the doubled wait");

    std::thread::sleep(Duration::from_millis(700));
    let r = net.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert!(r.published >= 3, "handshake, first message and texts: {r:?}");
    settle(&[&bob, &carol]);
    assert_eq!(carol.texts(&bob), ["first for carol", "second for carol"]);
    relay.stop();
}

/// A receipt the relay refuses is not acknowledged: it stays pending and is
/// sent once the sender's mailbox has room.
#[test]
fn a_refused_receipt_stays_pending_and_is_sent_later() {
    let relay = small_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    alice.send(&bob, "a1", "hello bob");
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    fill(&addr, &alice);

    let r = bob.sync();
    assert_eq!(r.accepted, 1, "{r:?}");
    assert_eq!(r.errors, [REFUSED]);
    assert_eq!(relay.stored(&key(&alice)).len(), LIMIT, "no receipt stored");
    assert_eq!(alice.undelivered(&bob), 1);

    let r = alice.sync();
    assert_eq!(r.dropped as usize, LIMIT);
    assert_eq!(alice.undelivered(&bob), 1, "no receipt yet");
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    // The pending receipt, and one more for the copy of the text Alice sent
    // again in her round above (her text was still unconfirmed).
    assert!(r.published >= 1, "the receipt: {r:?}");
    assert_eq!(r.accepted, 0, "the text is not accepted twice: {r:?}");
    let r = alice.sync();
    assert_eq!(r.delivered, 1, "{r:?}");
    assert_eq!(alice.undelivered(&bob), 0);
    // Acknowledged once stored: not sent again.
    assert_eq!(bob.sync().published, 0);
    assert_eq!(bob.texts(&alice), ["hello bob"]);
    relay.stop();
}
