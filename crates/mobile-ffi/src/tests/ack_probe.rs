//! Who may take an outgoing text out of the outbox, and what the chat history
//! then shows. `network/chat.rs` shows a text Delivered when its send record
//! reads acknowledged (the outbox emptied without an abandonment), which is
//! a receipt only while nothing but an authenticated receipt acknowledges
//! it. `core_protocol::messaging` leaves confirming delivery to its
//! caller, so `ArciumCore::acknowledge_outgoing` and `abandon_outgoing` are
//! crate-private: only the network layer calls them, and they are not
//! exported through UniFFI. Abandonment through `resolve_session_conflict`
//! (marked `NotDelivered`) is covered in `tests/chat.rs`, and through
//! `delete_contact` (`Messenger::forget_peer`, which marks every pending text
//! abandoned and deletes the history with it) in `tests/delete_contact.rs`,
//! and through `cancel_text` (marked `Cancelled` first) in
//! `tests/cancel_text.rs`.

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
/// delivers it once. Both restart against an empty second relay, so what it
/// holds afterwards was sent after the restart (the relay drops identical
/// envelopes, so resending to the first one would leave no trace).
#[test]
fn an_unreceipted_text_is_resent_after_a_restart_and_then_delivered_once() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = unreceipted_text(&addr);
    let sent = stored_messages(&relay, &bob);
    assert_eq!(sent.len(), 2, "the session opener and the text");
    let (alice_at, bob_at) = ((alice.path.clone(), alice.byte), (bob.path.clone(), bob.byte));
    drop((alice, bob));

    let relay2 = start_relay();
    let addr2 = relay2.addr().to_string();
    let alice = Device::reopen(&alice_at.0, alice_at.1, &addr2);
    let bob = Device::reopen(&bob_at.0, bob_at.1, &addr2);
    assert_eq!(state_of_text(&alice, &bob), S::Transmitted, "a restart is not a receipt");
    assert_eq!(alice.net.undelivered(bob.pk.clone()).unwrap().len(), 1);
    round(&[&alice]);
    assert_eq!(stored_messages(&relay2, &bob), sent, "both sent again, byte for byte");
    assert_eq!(state_of_text(&alice, &bob), S::Transmitted);

    round(&[&bob, &alice]);
    assert_eq!(state_of_text(&alice, &bob), S::Delivered);
    assert!(alice.net.undelivered(bob.pk.clone()).unwrap().is_empty());
    assert_eq!(bob.net.chat_entries(alice.pk.clone()).unwrap().len(), 1, "received once");
}

/// A raw `send_message` cannot take a chat text's client id: otherwise its
/// own message would be committed under the text's id, the text would be
/// linked to it, and the peer's receipt for it would show the text delivered
/// although the peer never received it.
#[test]
fn a_raw_send_cannot_take_the_network_layers_client_ids() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = unreceipted_text(&addr);
    let handle = core_crypto::session_handle::local_session_handle(bob.pk.as_slice().try_into().unwrap());
    for id in [&b"tfoo"[..], b"t", b"r", b"rX", b"o", b"o12345678"] {
        assert!(
            matches!(
                alice.core.send_message(handle, id.to_vec(), b"\x01substituted".to_vec()),
                Err(crate::CoreError::InvalidClientMessageId)
            ),
            "{id:?} must be refused"
        );
    }
    // Control: other ids, including ones merely starting with `o`, still work.
    for id in [&b"orphan"[..], b"foo", b"x"] {
        assert!(alice.core.send_message(handle, id.to_vec(), b"\x01raw".to_vec()).is_ok());
    }
    alice.net.chat_send(bob.pk.clone(), b"foo".to_vec(), "real".into()).unwrap();
    round(&[&alice, &bob, &alice]);
    let texts: Vec<_> = bob.net.chat_entries(alice.pk.clone()).unwrap().into_iter().map(|e| e.text.0.clone()).collect();
    assert!(texts.iter().any(|t| t == "real"), "{texts:?}");
    let ours = alice.net.chat_entries(bob.pk.clone()).unwrap();
    let real = ours.iter().find(|e| e.app_id == b"foo").unwrap();
    assert_eq!((real.text.0.as_str(), real.state), ("real", S::Delivered));
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

/// The `fn` items of an exported body (an exported `impl` exports every
/// method, `pub` or not), each with its name, up to the next one. Direct
/// calls only: a helper that calls either method on an exported method's
/// behalf is not seen here (the network layer's own helpers do, on a receipt).
fn exported_methods(body: &str) -> Vec<(&str, &str)> {
    let starts: Vec<usize> = body
        .match_indices("fn ")
        .map(|(i, _)| i)
        .filter(|&i| i == 0 || !body.as_bytes()[i - 1].is_ascii_alphanumeric() && body.as_bytes()[i - 1] != b'_')
        .collect();
    (0..starts.len())
        .map(|k| {
            let item = &body[starts[k]..starts.get(k + 1).copied().unwrap_or(body.len())];
            let name = item[3..].split(|c: char| !(c.is_alphanumeric() || c == '_')).next().unwrap_or("");
            (name, item)
        })
        .collect()
}

/// The trust boundary itself: no exported method lets Kotlin remove an
/// outgoing message from the outbox, except the three that never let it
/// read as delivered. A source check: it keeps `acknowledge_outgoing`,
/// `abandon_outgoing` and `forget_peer` from being exported, and from being
/// called directly by any exported method other than
/// `resolve_session_conflict` (marks the texts `NotDelivered`, then abandons
/// them), `delete_contact` (`forget_peer` marks every pending text
/// abandoned in the transaction that deletes it) and `cancel_text` (marks
/// the one entry `Cancelled`, then abandons its message; the record then
/// reads abandoned, never acknowledged). Paths that abandon through a
/// crate-private helper are not seen by this scan: the restart after a
/// refusal (`sync` → `restart_after_refusal` →
/// `retire_unconfirmed_session`, which marks the texts `NotDelivered`
/// first) and `publish_pending` (`sync` abandons, instead of sending, a text
/// whose entry already reads `Cancelled`; covered in `tests/cancel_text.rs`
/// and `tests/network_crash.rs`). The generated bindings
/// themselves are not checked by any test.
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
    const ALLOWED: [&str; 3] = ["resolve_session_conflict", "delete_contact", "cancel_text"];
    const CALLS: [&str; 3] = ["acknowledge_outgoing", "abandon_outgoing", "forget_peer"];
    let mut allowed_seen = Vec::new();
    for (file, body) in &items {
        for call in CALLS {
            let name = format!("fn {call}");
            assert!(!body.contains(&name), "{name} is exported in {file}");
        }
        for (name, method) in exported_methods(body) {
            if ALLOWED.contains(&name) {
                allowed_seen.push(name);
                continue;
            }
            for call in CALLS {
                assert!(!method.contains(call), "exported {name} in {file} refers to {call}");
            }
        }
    }
    // The scan is not vacuous: it does find exported methods, the allowed
    // ones among them.
    assert!(items.iter().any(|(_, b)| b.contains("fn pending_outgoing")));
    assert!(items.iter().any(|(_, b)| b.contains("fn acknowledge_incoming")));
    allowed_seen.sort_unstable();
    assert_eq!(allowed_seen, ["cancel_text", "delete_contact", "resolve_session_conflict"]);
}

/// The identity key's DH stays inside Rust. `ArciumCore::identity_dh` gives
/// the X25519 of the identity secret with any public key, for the relay's
/// mailbox authentication; exported, it would hand Kotlin (and anything that
/// reaches the bindings) a DH oracle on the identity key. A source check:
/// no exported item defines it or calls it directly; the messenger reaches
/// it only through its own non-exported `authenticate`.
#[test]
fn identity_dh_is_not_exported_through_uniffi() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let lib = std::fs::read_to_string(src.join("lib.rs")).unwrap();
    assert!(lib.contains("fn identity_dh("), "the guarded method exists under this name");
    let mut items = Vec::new();
    exported_items(&src, &mut items);
    // Not vacuous: the scan sees `ArciumCore`'s exported block in lib.rs.
    assert!(
        items.iter().any(|(f, b)| f.ends_with("lib.rs") && b.contains("fn export_prekey_bundle")),
        "the scan must see ArciumCore's exported block"
    );
    // The name as a whole word: `identity_dh_pk` and the like are other items.
    let names_it = |body: &str| {
        body.match_indices("identity_dh").any(|(i, m)| {
            let next = body[i + m.len()..].chars().next();
            let prev = body[..i].chars().next_back();
            !next.is_some_and(|c| c.is_alphanumeric() || c == '_') && !prev.is_some_and(|c| c.is_alphanumeric() || c == '_')
        })
    };
    assert!(names_it("self.core.identity_dh(pk, out)") && !names_it("identity_dh_pk"));
    for (file, body) in &items {
        assert!(!names_it(body), "identity_dh is exported or called by an export in {file}");
    }
}
