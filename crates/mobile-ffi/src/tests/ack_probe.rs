//! Who may take an outgoing text out of the outbox, and what the chat history
//! then shows. `network/chat.rs` reads a text missing from the outbox as
//! delivered ("absence is a receipt"), which holds only while nothing but an
//! authenticated receipt (or an abandonment, marked not delivered first)
//! removes it. `core_protocol::messaging` leaves confirming delivery to its
//! caller, so `ArciumCore::acknowledge_outgoing` and `abandon_outgoing` are
//! crate-private: only the network layer calls them, and they are not
//! exported through UniFFI. Abandonment through `resolve_session_conflict`
//! (marked `NotDelivered`) is covered in `tests/chat.rs`.

use std::path::Path;

use super::net_harness::*;
use crate::network::chat::ChatEntryState as S;

fn round(devices: &[&Device]) {
    for d in devices {
        let r = d.net.sync_conversations();
        assert!(r.errors.is_empty(), "{:?}", r.errors);
    }
}

/// Alice and Bob with a session, Alice's text to Bob on the relay, and Bob
/// not syncing since: no receipt can exist.
fn unreceipted_text(addr: &str) -> (Device, Device) {
    let (alice, bob) = (Device::new(addr, 1), Device::new(addr, 2));
    alice.net.add_named_contact(bob.core.contact_card().unwrap(), "bob".into()).unwrap();
    bob.net.add_named_contact(alice.core.contact_card().unwrap(), "alice".into()).unwrap();
    round(&[&bob]); // Bob's bundle reaches the relay.
    let text = format!("hello{}", String::from_utf8(CANARY.to_vec()).unwrap());
    alice.net.chat_send(bob.pk.clone(), b"t1".to_vec(), text).unwrap();
    round(&[&alice]); // session started, text committed and published
    round(&[&alice]);
    assert_eq!(alice.net.undelivered(bob.pk.clone()).unwrap().len(), 1, "the text waits for Bob's receipt");
    (alice, bob)
}

fn state_of_text(alice: &Device, bob: &Device) -> S {
    let e = alice.net.chat_entries(bob.pk.clone()).unwrap();
    assert_eq!(e.len(), 1);
    e[0].state
}

/// Negative control: without a receipt the text is never shown delivered and
/// stays in the outbox.
#[test]
fn without_a_receipt_the_network_path_never_shows_delivered() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = unreceipted_text(&addr);
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
    let (alice, bob) = unreceipted_text(&addr);
    round(&[&bob, &alice]);
    assert_eq!(state_of_text(&alice, &bob), S::Delivered);
    assert!(alice.net.undelivered(bob.pk.clone()).unwrap().is_empty());
    let got = bob.net.chat_entries(alice.pk.clone()).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].state, S::Received);
}

/// Without a receipt the text survives a restart in the outbox, the new
/// process publishes it again, byte for byte, and Bob's later receipt still
/// delivers it once. (The harness retransmits on every sync, so this shows
/// the outbox surviving, not the in-memory retransmission clock.)
#[test]
fn an_unreceipted_text_is_resent_after_a_restart_and_then_delivered_once() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = unreceipted_text(&addr);
    let before = stored_messages(&relay, &bob);
    let (path, byte) = (alice.path.clone(), alice.byte);
    drop(alice);

    let alice = Device::reopen(&path, byte, &addr);
    assert_eq!(state_of_text(&alice, &bob), S::Transmitted, "a restart is not a receipt");
    assert_eq!(alice.net.undelivered(bob.pk.clone()).unwrap().len(), 1);
    let r = alice.net.sync_conversations();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert!(r.published >= 1, "published again: {}", r.published);
    // The relay drops an identical envelope, so an unchanged mailbox means
    // the resend was the stored bytes, not a new ciphertext.
    assert_eq!(stored_messages(&relay, &bob), before);
    assert_eq!(state_of_text(&alice, &bob), S::Transmitted);

    round(&[&bob, &alice]);
    assert_eq!(state_of_text(&alice, &bob), S::Delivered);
    assert!(alice.net.undelivered(bob.pk.clone()).unwrap().is_empty());
    assert_eq!(bob.net.chat_entries(alice.pk.clone()).unwrap().len(), 1, "received once");
}

/// The bodies of every `#[uniffi::export]` item in `src`, with their file.
fn exported_items(dir: &Path, out: &mut Vec<(String, String)>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n != "tests") {
                exported_items(&path, out);
            }
            continue;
        }
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let src = std::fs::read_to_string(&path).unwrap();
        let code: String = src
            .lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n");
        for (at, _) in code.match_indices("#[uniffi::export") {
            let open = at + code[at..].find('{').expect("an exported item has a body");
            let mut depth = 0usize;
            let mut end = open;
            for (i, c) in code[open..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = open + i;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            assert!(end > open, "unbalanced braces in {}", path.display());
            out.push((path.display().to_string(), code[at..=end].to_string()));
        }
    }
}

/// The trust boundary itself: no exported method lets Kotlin remove an
/// outgoing message from the outbox. Generated bindings are checked
/// separately; this keeps the source from re-exporting either call.
#[test]
fn neither_outbox_removal_is_exported_through_uniffi() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut items = Vec::new();
    exported_items(&src, &mut items);
    let names: Vec<_> = items.iter().map(|(f, _)| f.as_str()).collect();
    assert!(
        names.iter().any(|f| f.ends_with("messaging_api.rs")),
        "the scan must see the exported messaging block: {names:?}"
    );
    for (file, body) in &items {
        for name in ["fn acknowledge_outgoing", "fn abandon_outgoing"] {
            assert!(!body.contains(name), "{name} is exported in {file}");
        }
    }
    // The scan is not vacuous: it does find exported methods.
    assert!(items.iter().any(|(_, b)| b.contains("fn pending_outgoing")));
    assert!(items.iter().any(|(_, b)| b.contains("fn acknowledge_incoming")));
}
