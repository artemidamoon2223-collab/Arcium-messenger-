//! Who may take an outgoing text out of the outbox, and what the chat history
//! then shows. `network/chat.rs` reads a text missing from the outbox as
//! delivered ("absence is a receipt"), which holds only while nothing but an
//! authenticated receipt (or an abandonment, marked first) removes it. The
//! exported `ArciumCore::acknowledge_outgoing` removes it unconditionally:
//! `core_protocol::messaging` leaves confirming delivery to its caller. These
//! tests pin both sides of that contract; the first one documents the hazard.

use super::net_harness::*;
use crate::network::chat::ChatEntryState as S;
use core_crypto::session_handle::local_session_handle;

fn round(devices: &[&Device]) {
    for d in devices {
        let r = d.net.sync_conversations();
        assert!(r.errors.is_empty(), "{:?}", r.errors);
    }
}

/// Alice and Bob with a session, Alice's text to Bob on the relay, and Bob
/// never syncing again: no receipt can exist.
fn unreceipted_text(addr: &str) -> (Device, Device, Vec<u8>) {
    let (alice, bob) = (Device::new(addr, 1), Device::new(addr, 2));
    alice.net.add_named_contact(bob.core.contact_card().unwrap(), "bob".into()).unwrap();
    bob.net.add_named_contact(alice.core.contact_card().unwrap(), "alice".into()).unwrap();
    round(&[&bob]); // Bob's bundle reaches the relay.
    let text = format!("hello{}", String::from_utf8(CANARY.to_vec()).unwrap());
    alice.net.chat_send(bob.pk.clone(), b"t1".to_vec(), text).unwrap();
    round(&[&alice]); // session started, text committed and published
    round(&[&alice]);
    let pending = alice.net.undelivered(bob.pk.clone()).unwrap();
    assert_eq!(pending.len(), 1, "the text waits for Bob's receipt");
    (alice, bob, pending[0].clone())
}

fn state_of_text(alice: &Device, bob: &Device) -> S {
    let e = alice.net.chat_entries(bob.pk.clone()).unwrap();
    assert_eq!(e.len(), 1);
    e[0].state
}

#[test]
fn exported_acknowledge_outgoing_marks_an_unreceipted_text_delivered() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob, id) = unreceipted_text(&addr);
    assert_eq!(state_of_text(&alice, &bob), S::Transmitted);
    let waiting = stored_messages(&relay, &bob);
    assert!(!waiting.is_empty(), "the text is on the relay, unfetched");

    // The trigger: the exported call, as Kotlin's MessageRepository.confirmDelivered makes it.
    let handle = local_session_handle(bob.pk.as_slice().try_into().unwrap());
    assert!(alice.core.acknowledge_outgoing(handle, id).unwrap());

    assert_eq!(state_of_text(&alice, &bob), S::Delivered, "shown delivered without a receipt");
    assert!(alice.net.undelivered(bob.pk.clone()).unwrap().is_empty(), "nothing left to retransmit");
    assert!(bob.net.chat_entries(alice.pk.clone()).unwrap().is_empty(), "Bob has received nothing");
    round(&[&alice]);
    assert_eq!(stored_messages(&relay, &bob), waiting, "still unfetched by Bob");
}

/// Negative control: the same state without the exported call stays undelivered.
#[test]
fn without_a_receipt_the_network_path_never_shows_delivered() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob, _) = unreceipted_text(&addr);
    for _ in 0..3 {
        round(&[&alice]);
        assert_eq!(state_of_text(&alice, &bob), S::Transmitted);
    }
    assert_eq!(alice.net.undelivered(bob.pk.clone()).unwrap().len(), 1);
}

/// Positive control: Bob's authenticated receipt is what delivers it.
#[test]
fn bobs_receipt_delivers_the_text() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob, _) = unreceipted_text(&addr);
    round(&[&bob, &alice]);
    assert_eq!(state_of_text(&alice, &bob), S::Delivered);
    assert!(alice.net.undelivered(bob.pk.clone()).unwrap().is_empty());
    let got = bob.net.chat_entries(alice.pk.clone()).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].state, S::Received);
}
