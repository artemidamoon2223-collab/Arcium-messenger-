//! Delivered in the chat history must mean the peer's receipt, whatever runs
//! concurrently and whichever exported call committed a text:
//!
//! - MAJOR-1: a text committed while `resolve_session_conflict` runs, after
//!   its NotDelivered pass and before its abandon pass, is abandoned
//!   unmarked. The history used to read its absence from the outbox as a
//!   receipt. It now asks the durable send record, which tells an
//!   acknowledgement from an abandonment.
//! - MAJOR-A: `send_text` and `chat_send` commit under the same client id
//!   (`t` + app id). A `send_text` under an app id the chat then used linked
//!   the history entry to the `send_text` message, and the receipt for that
//!   message showed the chat text as delivered. Each now refuses an app id
//!   the other holds.

use std::sync::Arc;

use super::net_harness::*;
use crate::network::chat::{test_hooks, ChatEntryState as S, ChatSessionState};
use crate::network::wire::{client_id, Payload};
use crate::CoreError;
use zeroize::Zeroizing;

fn canary() -> String {
    String::from_utf8(CANARY.to_vec()).unwrap()
}

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
    a.net.add_named_contact(b.core.contact_card().unwrap(), "peer".into()).unwrap();
    b.net.add_named_contact(a.core.contact_card().unwrap(), "peer".into()).unwrap();
}

fn say(from: &Device, to: &Device, app_id: &str, text: &str) {
    from.net
        .chat_send(to.pk.clone(), app_id.as_bytes().to_vec(), format!("{text}{}", canary()))
        .unwrap();
}

/// `from`'s history with `with`: (outgoing, state, text without canary).
fn chat(from: &Device, with: &Device) -> Vec<(bool, S, String)> {
    from.net
        .chat_entries(with.pk.clone())
        .unwrap()
        .into_iter()
        .map(|e| (e.outgoing, e.state, e.text.0.replace(&canary(), "")))
        .collect()
}

fn state_of(d: &Device, with: &Device, text: &str) -> Option<S> {
    chat(d, with).into_iter().find(|e| e.0 && e.2 == text).map(|e| e.1)
}

fn received(d: &Device, from: &Device) -> Vec<String> {
    chat(d, from).into_iter().filter(|e| !e.0).map(|e| e.2).collect()
}

/// Repeats `f` while it fails transiently: two connections committing on
/// one session see each other's commits as a conflict, and an IMMEDIATE
/// transaction can find the store busy. Both are documented as retryable
/// with the same arguments.
fn retrying<T>(mut f: impl FnMut() -> Result<T, CoreError>) -> Result<T, CoreError> {
    for _ in 0..100 {
        match f() {
            Err(CoreError::SessionConflict { .. } | CoreError::Storage { .. }) => {
                std::thread::sleep(std::time::Duration::from_millis(2))
            }
            other => return other,
        }
    }
    f()
}

fn invalid<T: std::fmt::Debug>(r: Result<T, CoreError>) -> bool {
    matches!(r, Err(CoreError::InvalidArgument { .. }))
}

/// Two devices in a session conflict: both started a session before seeing
/// the other's handshake. Returns (the one that resolves, the other).
fn conflict(addr: &str) -> (Device, Device) {
    let (alice, bob) = (Device::new(addr, 1), Device::new(addr, 2));
    meet(&alice, &bob);
    rounds(&[&alice, &bob], 1);
    say(&alice, &bob, "a", "from alice");
    say(&bob, &alice, "b", "from bob");
    alice.net.start_session(bob.pk.clone()).unwrap();
    bob.net.start_session(alice.pk.clone()).unwrap();
    rounds(&[&alice, &bob], 2);
    let (g, s) = if alice.pk > bob.pk { (alice, bob) } else { (bob, alice) };
    assert_eq!(
        g.net.conversation(s.pk.clone()).unwrap().session,
        ChatSessionState::Conflict { can_resolve: true }
    );
    (g, s)
}

/// After the conflict is resolved and both sides talked: every outgoing text
/// shown Delivered was received by the peer, and none was lost.
fn assert_consistent(g: &Device, s: &Device, sent: &[String]) {
    let got = received(s, g);
    let ours = chat(g, s);
    for t in sent {
        let n = ours.iter().filter(|e| e.0 && &e.2 == t).count();
        assert_eq!(n, 1, "{t}: recorded once, never lost");
    }
    for (outgoing, state, text) in &ours {
        if *outgoing && *state == S::Delivered {
            assert!(got.contains(text), "{text} shown Delivered but never received");
        }
        if *outgoing && *state == S::NotDelivered {
            assert!(!got.contains(text), "{text} abandoned but received");
        }
    }
}

// ── MAJOR-1 ─────────────────────────────────────────────────────────────────

/// The race, made deterministic: a `chat_send` lands between the two passes
/// of `resolve_session_conflict` (a test hook runs it there). Its text is
/// committed in the session about to be removed, then abandoned unmarked.
/// It must end NotDelivered, not Delivered, and stay in the history.
#[test]
fn a_text_committed_between_the_resolve_passes_is_never_shown_delivered() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (g, s) = conflict(&addr);
    let net = g.net.clone();
    let peer = s.pk.clone();
    test_hooks::set_between_resolve_passes(move || {
        net.chat_send(peer, b"late".to_vec(), format!("late{}", canary())).unwrap();
    });
    g.net.resolve_session_conflict(s.pk.clone()).unwrap();
    assert_eq!(state_of(&g, &s, "late"), Some(S::NotDelivered));

    rounds(&[&g, &s, &g, &s], 2);
    assert_eq!(g.net.conversation(s.pk.clone()).unwrap().session, ChatSessionState::Established);
    assert!(!received(&s, &g).contains(&"late".to_string()), "the peer never got it");
    assert_eq!(state_of(&g, &s, "late"), Some(S::NotDelivered), "after the peer's session too");
    assert_consistent(&g, &s, &["late".into()]);
    relay.stop();
}

/// Crash and retry: the resolving process dies between the passes, or after
/// abandoning and before removing the session. After the restart a text is
/// committed in the still-present session; the repeated call completes the
/// resolution exactly once, and the text ends NotDelivered, never Delivered
/// and never lost. (The repeated call marks it before abandoning it, so this
/// does not reproduce the race; it checks the crash and retry paths.)
#[cfg(unix)]
#[test]
fn a_resolution_killed_between_its_passes_and_repeated_never_shows_delivered() {
    for point in ["resolve_after_mark", "resolve_after_abandon"] {
        let relay = start_relay();
        let addr = relay.addr().to_string();
        let (g, s) = conflict(&addr);
        super::network_crash::run_child(&g, &addr, "resolve", Some(point), &s.pk);
        let g = g.restart(&addr);
        say(&g, &s, "after-crash", "after crash");
        g.net.resolve_session_conflict(s.pk.clone()).unwrap();
        assert!(g.net.resolve_session_conflict(s.pk.clone()).is_err(), "{point}: resolved once");
        assert_eq!(
            g.net.conversation(s.pk.clone()).unwrap().session,
            ChatSessionState::AwaitingPeerSession,
            "{point}"
        );
        let shown = state_of(&g, &s, "after crash");
        rounds(&[&g, &s, &g, &s], 2);
        assert_eq!(g.net.conversation(s.pk.clone()).unwrap().session, ChatSessionState::Established);
        let after = state_of(&g, &s, "after crash");
        match shown {
            Some(S::NotDelivered) => assert_eq!(after, Some(S::NotDelivered), "{point}"),
            other => panic!("{point}: expected NotDelivered right after the resolution, got {other:?}"),
        }
        assert_consistent(&g, &s, &["after crash".into()]);
        relay.stop();
    }
}

/// Real threads: one keeps sending from the chat while the other resolves
/// the conflict, repeated. Whatever the interleaving, nothing sent is lost,
/// nothing abandoned is shown Delivered, and everything shown Delivered was
/// received. The run also reports how many texts landed in the abandoned
/// session, so a run that never hit the window is visible.
#[test]
fn concurrent_sends_and_a_resolution_never_show_delivered_without_a_receipt() {
    let mut abandoned = 0;
    for iteration in 0..6 {
        let relay = start_relay();
        let addr = relay.addr().to_string();
        let (g, s) = conflict(&addr);
        let net = g.net.clone();
        let peer = s.pk.clone();
        let sender = std::thread::spawn(move || {
            let mut sent = Vec::new();
            for k in 0..25 {
                let text = format!("c{iteration}-{k}");
                // The entry is recorded first; committing it can then find the
                // session removed under it (NoSession). Nothing is lost: the
                // call is repeated with the same id, as documented.
                let mut tries = 0;
                loop {
                    match net.chat_send(peer.clone(), text.clone().into_bytes(), format!("{text}{}", canary())) {
                        Ok(_) => break,
                        Err(CoreError::NoSession { .. } | CoreError::SessionConflict { .. })
                            if tries < 50 =>
                        {
                            tries += 1
                        }
                        Err(e) => panic!("{text}: {e:?}"),
                    }
                }
                sent.push(text);
            }
            sent
        });
        // A text committed after the abandon pass makes the removal refuse
        // (PendingOutgoing), changing nothing; repeating completes it.
        let mut refused = 0;
        loop {
            match g.net.resolve_session_conflict(s.pk.clone()) {
                Ok(()) => break,
                Err(CoreError::PendingOutgoing { .. }) if refused < 50 => refused += 1,
                Err(e) => panic!("{e:?}"),
            }
        }
        let sent = sender.join().unwrap();
        abandoned += sent
            .iter()
            .filter(|t| state_of(&g, &s, t) == Some(S::NotDelivered))
            .count();
        rounds(&[&g, &s, &g, &s, &g], 3);
        assert_consistent(&g, &s, &sent);
        relay.stop();
    }
    eprintln!("texts committed in the abandoned session across runs: {abandoned}");
}

// ── MAJOR-A ─────────────────────────────────────────────────────────────────

/// Alice and Bob with an established chat session.
fn talking(addr: &str) -> (Device, Device) {
    let (alice, bob) = (Device::new(addr, 1), Device::new(addr, 2));
    meet(&alice, &bob);
    round(&[&bob]);
    say(&alice, &bob, "a0", "hi");
    rounds(&[&alice, &bob, &alice], 2);
    assert_eq!(state_of(&alice, &bob, "hi"), Some(S::Delivered));
    (alice, bob)
}

/// The reported collision, both orders, and the repeats that must still work.
#[test]
fn send_text_and_chat_send_never_share_an_app_id() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    let pk = bob.pk.clone();

    // send_text first: the chat refuses the app id, so its text can never be
    // linked to the send_text message.
    let raw = alice.net.send_text(pk.clone(), b"foo".to_vec(), b"substituted".to_vec()).unwrap();
    assert!(invalid(alice.net.chat_send(pk.clone(), b"foo".to_vec(), "real".into())));
    let again = alice.net.send_text(pk.clone(), b"foo".to_vec(), b"ignored".to_vec()).unwrap();
    assert_eq!(again.message_id, raw.message_id, "a repeated send_text is the same message");

    // chat_send first: send_text refuses the app id.
    say(&alice, &bob, "bar", "chat bar");
    assert!(invalid(alice.net.send_text(pk.clone(), b"bar".to_vec(), b"raw bar".to_vec())));
    say(&alice, &bob, "bar", "ignored on a repeat");

    // Control: other ids still work on both paths.
    alice.net.send_text(pk.clone(), b"raw-only".to_vec(), b"raw only".to_vec()).unwrap();
    say(&alice, &bob, "chat-only", "chat only");

    rounds(&[&alice, &bob, &alice], 2);
    let got = received(&bob, &alice);
    for t in ["substituted", "chat bar", "raw only", "chat only"] {
        assert_eq!(got.iter().filter(|g| g.as_str() == t).count(), 1, "{t} received once: {got:?}");
    }
    assert!(!got.contains(&"real".to_string()) && !got.contains(&"raw bar".to_string()));
    assert_eq!(state_of(&alice, &bob, "chat bar"), Some(S::Delivered));
    assert_eq!(state_of(&alice, &bob, "chat only"), Some(S::Delivered));
    assert_eq!(state_of(&alice, &bob, "real"), None, "the refused text is not in the history");
    relay.stop();
}

/// The race inside `chat_send`, made deterministic: a `send_text` under the
/// same app id lands after the chat's check for a committed text and before
/// it records its entry. The claim, checked in the recording transaction,
/// makes the chat refuse instead of adopting the `send_text` message.
#[test]
fn a_send_text_landing_inside_chat_send_makes_it_refuse() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    let (net, pk) = (alice.net.clone(), bob.pk.clone());
    test_hooks::set_chat_send_before_record(move || {
        net.send_text(pk, b"mid".to_vec(), b"substituted mid".to_vec()).unwrap();
    });
    assert!(invalid(alice.net.chat_send(bob.pk.clone(), b"mid".to_vec(), "real mid".into())));
    rounds(&[&alice, &bob, &alice], 2);
    assert_eq!(state_of(&alice, &bob, "real mid"), None);
    assert_eq!(received(&bob, &alice).iter().filter(|t| *t == "substituted mid").count(), 1);
    relay.stop();
}

/// A `send_text` that took its app id and then failed (no session yet) keeps
/// it: the chat refuses that app id, and the repeated `send_text` sends it
/// once the session exists.
#[test]
fn a_failed_send_text_still_holds_its_app_id() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    meet(&alice, &bob);
    let r = alice.net.send_text(bob.pk.clone(), b"early".to_vec(), b"early raw".to_vec());
    assert!(matches!(r, Err(CoreError::NoSession { .. })), "{r:?}");
    assert!(invalid(alice.net.chat_send(bob.pk.clone(), b"early".to_vec(), "early chat".into())));
    round(&[&bob]);
    alice.net.start_session(bob.pk.clone()).unwrap();
    alice.net.send_text(bob.pk.clone(), b"early".to_vec(), b"early raw".to_vec()).unwrap();
    rounds(&[&alice, &bob, &alice], 2);
    assert_eq!(received(&bob, &alice), vec!["early raw".to_string()]);
    assert_eq!(state_of(&alice, &bob, "early chat"), None);
    relay.stop();
}

/// A text committed under `t` + app id before this change carries no claim
/// record. The chat still refuses that app id, from the send record itself.
#[test]
fn a_text_sent_before_the_claim_record_existed_still_blocks_its_app_id() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    let handle = core_crypto::session_handle::local_session_handle(bob.pk.as_slice().try_into().unwrap());
    // What `send_text` committed in a build without the claim: the message
    // alone.
    let payload = Payload::Text(Zeroizing::new(b"old raw".to_vec())).encode();
    alice.core.send_committed(handle, &client_id::text(b"old"), &payload).unwrap();
    assert!(invalid(alice.net.chat_send(bob.pk.clone(), b"old".to_vec(), "chat old".into())));
    rounds(&[&alice, &bob, &alice], 2);
    assert_eq!(received(&bob, &alice).iter().filter(|t| *t == "old raw").count(), 1);
    assert_eq!(state_of(&alice, &bob, "chat old"), None);
    relay.stop();
}

/// The two calls racing on the same app ids from two connections to one
/// store (two cores on the same file): for each id at most one wins, and the
/// history only ever follows its own message.
#[test]
fn racing_send_text_and_chat_send_from_two_connections_never_collide() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    let other = Arc::new(Device::reopen(&alice.path, alice.byte, &addr));
    let n = 40;
    let (raw_net, pk) = (other.net.clone(), bob.pk.clone());
    let raw = std::thread::spawn(move || {
        (0..n)
            .map(|k| {
                retrying(|| {
                    raw_net.send_text(
                        pk.clone(),
                        format!("id{k}").into_bytes(),
                        format!("raw{k}{}", canary()).into_bytes(),
                    )
                })
                .map(|_| ())
            })
            .collect::<Vec<_>>()
    });
    let chat_results: Vec<_> = (0..n)
        .map(|k| {
            retrying(|| {
                alice
                    .net
                    .chat_send(bob.pk.clone(), format!("id{k}").into_bytes(), format!("chat{k}{}", canary()))
            })
            .map(|_| ())
        })
        .collect();
    let raw_results = raw.join().unwrap();
    for k in 0..n {
        let (c, r) = (&chat_results[k], &raw_results[k]);
        assert!(!(c.is_ok() && r.is_ok()), "id{k}: both calls took the app id");
        for e in [c, r] {
            if let Err(e) = e {
                assert!(matches!(e, CoreError::InvalidArgument { .. }), "id{k}: {e:?}");
            }
        }
        assert!(c.is_ok() || r.is_ok(), "id{k}: one of them must win");
    }
    drop(other);
    rounds(&[&alice, &bob, &alice], 3);
    let got = received(&bob, &alice);
    for k in 0..n {
        let (c, r) = (format!("chat{k}"), format!("raw{k}"));
        assert!(!(got.contains(&c) && got.contains(&r)), "id{k}: two texts under one id");
        match state_of(&alice, &bob, &c) {
            Some(S::Delivered) => assert!(got.contains(&c), "id{k}: Delivered without its text"),
            Some(other) => panic!("id{k}: chat text left {other:?}"),
            None => assert!(got.contains(&r), "id{k}: the send_text one won"),
        }
    }
    relay.stop();
}
