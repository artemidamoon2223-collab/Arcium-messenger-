//! Cancelling an outgoing text (`NetworkMessenger::cancel_text`, tracker
//! R-15) between independent devices over a real relay: from each state a
//! text can be cancelled in, what the peer then gets, a receipt that won the
//! race, the refusals, a restart, and sending the text again. A crash
//! between marking and abandoning is covered in `tests/network_crash.rs`.

use super::net_harness::*;
use super::*;
use crate::network::chat::{ChatEntry, ChatEntryState as S, ChatSessionState};

fn canary() -> String {
    String::from_utf8(CANARY.to_vec()).unwrap()
}

/// One `sync_conversations` per device, in order; none may report an error.
fn round(devices: &[&Device]) {
    for d in devices {
        let r = d.net.sync_conversations();
        assert!(r.errors.is_empty(), "{:?}", r.errors);
    }
}

fn rounds(devices: &[&Device], n: usize) {
    for _ in 0..n {
        round(devices);
    }
}

fn meet(a: &Device, b: &Device) {
    a.net
        .add_named_contact(b.core.contact_card().unwrap(), "peer".into())
        .unwrap();
    b.net
        .add_named_contact(a.core.contact_card().unwrap(), "peer".into())
        .unwrap();
}

fn say(from: &Device, to: &Device, app_id: &str, text: &str) -> ChatEntry {
    from.net
        .chat_send(
            to.pk.clone(),
            app_id.as_bytes().to_vec(),
            format!("{text}{}", canary()),
        )
        .unwrap()
}

fn cancel(from: &Device, to: &Device, app_id: &str) -> S {
    from.net
        .cancel_text(to.pk.clone(), app_id.as_bytes().to_vec())
        .unwrap()
        .state
}

/// `from`'s conversation with `with`: (outgoing, state, text without canary).
fn chat(from: &Device, with: &Device) -> Vec<(bool, S, String)> {
    from.net
        .chat_entries(with.pk.clone())
        .unwrap()
        .into_iter()
        .map(|e| (e.outgoing, e.state, e.text.0.replace(&canary(), "")))
        .collect()
}

/// Alice and Bob after one exchange started from the chat: both sessions
/// established, one delivered text each way.
fn talking(addr: &str) -> (Device, Device) {
    let (alice, bob) = (Device::new(addr, 1), Device::new(addr, 2));
    meet(&alice, &bob);
    round(&[&bob]);
    say(&alice, &bob, "a0", "hi");
    rounds(&[&alice, &bob], 2);
    say(&bob, &alice, "b0", "hi back");
    rounds(&[&bob, &alice], 2);
    assert_eq!(
        alice.net.conversation(bob.pk.clone()).unwrap().session,
        ChatSessionState::Established
    );
    (alice, bob)
}

/// A text committed to the outbox and never published is cancelled: it
/// leaves the outbox, no later round sends it, and the peer never gets it.
/// Repeating the cancel changes nothing.
#[test]
fn a_cancelled_pending_text_is_never_sent() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    assert_eq!(say(&alice, &bob, "a1", "never sent").state, S::Pending);
    assert_eq!(alice.undelivered(&bob), 1);

    assert_eq!(cancel(&alice, &bob, "a1"), S::Cancelled);
    assert_eq!(alice.undelivered(&bob), 0, "out of the outbox");
    assert_eq!(cancel(&alice, &bob, "a1"), S::Cancelled, "repeatable");
    rounds(&[&alice, &bob], 3);
    assert!(stored_messages(&relay, &bob).is_empty());
    assert_eq!(
        chat(&bob, &alice),
        vec![
            (false, S::Received, "hi".into()),
            (true, S::Delivered, "hi back".into()),
        ]
    );
    assert_eq!(chat(&alice, &bob)[2], (true, S::Cancelled, "never sent".into()));
    // `send` with its logical id reports the abandonment: nothing is
    // encrypted again under it.
    assert!(matches!(
        alice
            .core
            .prior_send(&bob.pk.as_slice().try_into().unwrap(), b"ta1")
            .unwrap(),
        Some(SendResult::Abandoned { .. })
    ));
    assert_eq!(relay.canary_hits(), 0);
    relay.stop();
}

/// A queued text (no session yet) is cancelled: it never starts a session
/// and never leaves the device.
#[test]
fn a_cancelled_queued_text_starts_no_session() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    meet(&alice, &bob);
    round(&[&bob]);
    assert_eq!(say(&alice, &bob, "a1", "queued").state, S::Queued);
    assert_eq!(cancel(&alice, &bob, "a1"), S::Cancelled);
    rounds(&[&alice, &bob], 3);
    assert_eq!(
        alice.net.conversation(bob.pk.clone()).unwrap().session,
        ChatSessionState::None
    );
    assert!(relay.stored(&bob.pk.as_slice().try_into().unwrap()).is_empty());
    assert_eq!(chat(&bob, &alice), vec![]);
    assert_eq!(chat(&alice, &bob), vec![(true, S::Cancelled, "queued".into())]);
    relay.stop();
}

/// A text the relay already accepted is cancelled while the peer is
/// offline. It is not sent again, but the copy on the relay still reaches
/// the peer, which accepts it: `Cancelled` claims nothing about the peer.
/// The peer's receipt then finds the message abandoned, and the entry stays
/// `Cancelled`.
#[test]
fn a_cancelled_transmitted_text_may_still_arrive() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    say(&alice, &bob, "a1", "already on the relay");
    round(&[&alice]);
    assert_eq!(chat(&alice, &bob)[2].1, S::Transmitted);
    // The text, and the receipt for Bob's last text.
    let on_relay = stored_messages(&relay, &bob).len();
    assert_eq!(on_relay, 2);

    assert_eq!(cancel(&alice, &bob, "a1"), S::Cancelled);
    let published = alice.net.sync_conversations().published;
    assert_eq!(published, 0, "nothing is sent again");
    assert_eq!(stored_messages(&relay, &bob).len(), on_relay);
    rounds(&[&bob, &alice], 2);
    assert_eq!(
        chat(&bob, &alice)[2],
        (false, S::Received, "already on the relay".into())
    );
    // Alice fetched Bob's receipt and deleted it from the relay.
    assert!(stored_messages(&relay, &alice).is_empty());
    assert_eq!(
        chat(&alice, &bob)[2],
        (true, S::Cancelled, "already on the relay".into())
    );
    relay.stop();
}

/// The peer's receipt was taken (by `sync` alone, which leaves the history
/// as it was) before the cancel: the entry reads `Delivered`, the fact the
/// receipt proves. A text already delivered is returned as it stands.
#[test]
fn a_receipt_that_won_the_race_reads_delivered() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    say(&alice, &bob, "a1", "delivered first");
    round(&[&alice, &bob]);
    let r = alice.net.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.delivered, 1, "the receipt was taken");
    assert_eq!(cancel(&alice, &bob, "a1"), S::Delivered);
    assert_eq!(chat(&alice, &bob)[2].1, S::Delivered);
    assert_eq!(cancel(&alice, &bob, "a0"), S::Delivered, "final: unchanged");
    relay.stop();
}

/// The refusals: an app id with no outgoing text, an unpinned or malformed
/// contact. Nothing is changed by any of them.
#[test]
fn cancel_refuses_what_it_cannot_cancel() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    let stranger = Device::new(&addr, 3);
    let before = chat(&alice, &bob);
    assert!(matches!(
        alice.net.cancel_text(bob.pk.clone(), b"nope".to_vec()),
        Err(CoreError::InvalidArgument { .. })
    ));
    assert!(matches!(
        alice.net.cancel_text(stranger.pk.clone(), b"a0".to_vec()),
        Err(CoreError::UnknownContact)
    ));
    assert!(matches!(
        alice.net.cancel_text(vec![1; 31], b"a0".to_vec()),
        Err(CoreError::InvalidKey { .. })
    ));
    assert_eq!(chat(&alice, &bob), before);
    say(&alice, &bob, "a1", "kept");
    alice.net.delete_contact(bob.pk.clone()).unwrap();
    assert!(matches!(
        alice.net.cancel_text(bob.pk.clone(), b"a1".to_vec()),
        Err(CoreError::UnknownContact)
    ));
    relay.stop();
}

/// `Cancelled` is stored: a restarted device reads it, sends nothing for
/// it, and "send again" (a new app id with the same text) is delivered.
#[test]
fn a_cancelled_text_survives_a_restart_and_can_be_sent_again() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    say(&alice, &bob, "a1", "try again");
    assert_eq!(cancel(&alice, &bob, "a1"), S::Cancelled);

    let alice = alice.restart(&addr);
    assert_eq!(chat(&alice, &bob)[2], (true, S::Cancelled, "try again".into()));
    let (record, scan) = alice.net.open_record_and_scan(&bob.pk);
    assert_eq!(record, scan, "not an open entry");
    assert!(record.is_empty());
    say(&alice, &bob, "a2", "try again");
    rounds(&[&alice, &bob, &alice], 2);
    assert_eq!(
        chat(&alice, &bob)[2..],
        [
            (true, S::Cancelled, "try again".into()),
            (true, S::Delivered, "try again".into()),
        ]
    );
    assert_eq!(
        chat(&bob, &alice)[2..],
        [(false, S::Received, "try again".into())],
        "only the second copy was ever sent"
    );
    assert_eq!(relay.canary_hits(), 0);
    relay.stop();
}
