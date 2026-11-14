//! Deleting a contact (`NetworkMessenger::delete_contact`, option C of
//! `docs/SESSION-RECOVERY-OPTIONS.md`) between independent devices over a
//! real relay: the dead end a false conflict leads to (tracker R-13) and the
//! way out of it, repeated and session-less deletes, and a text that had no
//! receipt when its contact was deleted.

use super::net_harness::*;
use super::*;
use crate::network::chat::{ChatEntry, ChatEntryState as S, ChatSessionState};
use crate::network::TextState;
use crate::network::wire::{client_id, Envelope};

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

/// Both pin each other's card under a name, as after an out-of-band exchange.
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

/// `from`'s conversation with `with`: (outgoing, state, text without canary).
fn chat(from: &Device, with: &Device) -> Vec<(bool, S, String)> {
    from.net
        .chat_entries(with.pk.clone())
        .unwrap()
        .into_iter()
        .map(|e| (e.outgoing, e.state, e.text.0.replace(&canary(), "")))
        .collect()
}

fn session(from: &Device, with: &Device) -> ChatSessionState {
    from.net.conversation(with.pk.clone()).unwrap().session
}

fn key(d: &Device) -> [u8; 32] {
    d.pk.as_slice().try_into().unwrap()
}

/// Every record `d` holds for `other`, except the `seen:` and `sendid:`
/// records a deletion keeps.
fn remaining(d: &Device, other: &Device) -> Vec<String> {
    let hex: String = other.pk.iter().map(|b| format!("{b:02x}")).collect();
    let handle = format!(
        "{:016x}",
        core_crypto::session_handle::local_session_handle(&key(other))
    );
    let entries = format!("chat-e.v1.{hex}:");
    let store = d.core.store.lock().unwrap();
    let mut out = Vec::new();
    for ns in [
        "contact:", "session:", "handle:", "hsout:", "hsin:", "outbox:", "inbox:", "chat-meta:",
        "chat-open:", "chat-o:", "chat-r:", "chat-i:", &entries,
    ] {
        out.extend(
            store
                .list_keys_with_prefix(ns)
                .unwrap()
                .into_iter()
                .filter(|k| k.contains(&hex) || k.contains(&handle)),
        );
    }
    out
}

/// The `seen:` and `sendid:` records `d` holds for `other`.
fn kept(d: &Device, other: &Device) -> usize {
    let hex: String = other.pk.iter().map(|b| format!("{b:02x}")).collect();
    let store = d.core.store.lock().unwrap();
    ["seen:", "sendid:"]
        .iter()
        .flat_map(|ns| store.list_keys_with_prefix(ns).unwrap())
        .filter(|k| k.contains(&hex))
        .count()
}

/// After `d` deleted `other`: no record of it but the kept ones, and the
/// contact is gone from every list.
fn assert_forgotten(d: &Device, other: &Device) {
    assert_eq!(remaining(d, other), Vec::<String>::new());
    assert!(!d.core.contacts().unwrap().contains(&other.pk));
    assert!(d.net.conversations().unwrap().iter().all(|c| c.peer != other.pk));
    assert!(matches!(
        d.net.chat_entries(other.pk.clone()),
        Err(CoreError::UnknownContact)
    ));
}

/// Alice and Bob after one exchange started from the chat: a session exists
/// and both have one delivered text.
fn talking(addr: &str) -> (Device, Device) {
    let (alice, bob) = (Device::new(addr, 1), Device::new(addr, 2));
    meet(&alice, &bob);
    round(&[&bob]);
    say(&alice, &bob, "a0", "hi");
    rounds(&[&alice, &bob], 2);
    say(&bob, &alice, "b0", "hi back");
    rounds(&[&bob, &alice], 2);
    assert_eq!(session(&alice, &bob), ChatSessionState::Established);
    assert_eq!(session(&bob, &alice), ChatSessionState::Established);
    (alice, bob)
}

/// R-13, reproduced and then left: a forged handshake "from" the contact
/// raises a false conflict on the device that may resolve it; resolving it
/// removes that device's session while the contact goes on to accept it.
/// One side then waits for a handshake that never comes, the other holds an
/// established session whose messages the first cannot read. Both delete
/// each other and exchange cards again: the next texts start a new session
/// and are delivered both ways.
#[test]
fn deleting_each_other_ends_the_dead_end_of_a_false_conflict() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    let (g, s) = if alice.pk > bob.pk {
        (&alice, &bob)
    } else {
        (&bob, &alice)
    };
    meet(g, s);
    round(&[s]); // s's bundle reaches the relay.
    say(g, s, "g1", "lost in the dead end");
    round(&[g]); // g starts a session; s is offline.
    assert_eq!(session(g, s), ChatSessionState::AwaitingPeer);

    // Anyone can store this "from s": its bytes are public.
    let mut forged = vec![0u8; crate::INITIATOR_HANDSHAKE_V1_LEN];
    forged[4..36].copy_from_slice(&s.pk);
    inject(
        &addr,
        g,
        Envelope::Handshake {
            sender: key(s),
            handshake: forged,
        }
        .encode(),
    );
    round(&[g]);
    assert_eq!(
        session(g, s),
        ChatSessionState::Conflict { can_resolve: true }
    );
    g.net.resolve_session_conflict(s.pk.clone()).unwrap();

    // s comes online and accepts g's original handshake. g never gets one
    // from s, and cannot read what s sends: the dead end.
    rounds(&[s, g], 3);
    say(s, g, "s1", "unreadable for g");
    rounds(&[s, g], 3);
    assert_eq!(session(s, g), ChatSessionState::Established);
    assert_eq!(session(g, s), ChatSessionState::AwaitingPeerSession);
    assert_eq!(
        chat(g, s),
        vec![(true, S::NotDelivered, "lost in the dead end".into())]
    );
    assert_eq!(
        chat(s, g),
        vec![
            (false, S::Received, "lost in the dead end".into()),
            (true, S::Transmitted, "unreadable for g".into()),
        ]
    );

    for (d, other) in [(g, s), (s, g)] {
        d.net.delete_contact(other.pk.clone()).unwrap();
        assert_forgotten(d, other);
        assert!(kept(d, other) > 0, "seen and send-id records stay");
    }

    meet(g, s);
    say(g, s, "g2", "after deleting");
    say(s, g, "s2", "after deleting too");
    rounds(&[g, s], 3);
    assert_eq!(session(g, s), ChatSessionState::Established);
    assert_eq!(session(s, g), ChatSessionState::Established);
    assert_eq!(
        chat(g, s),
        vec![
            (true, S::Delivered, "after deleting".into()),
            (false, S::Received, "after deleting too".into()),
        ]
    );
    assert_eq!(
        chat(s, g),
        vec![
            (true, S::Delivered, "after deleting too".into()),
            (false, S::Received, "after deleting".into()),
        ]
    );
    assert_eq!(relay.canary_hits(), 0);
    relay.stop();
}

/// Deleting needs no session and no pinned card, and a second delete is
/// harmless. A text that was only queued never left the device, so its app
/// id is free again for the contact once re-added.
#[test]
fn deleting_a_contact_is_idempotent_and_needs_no_session() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob, stranger) = (
        Device::new(&addr, 1),
        Device::new(&addr, 2),
        Device::new(&addr, 3),
    );
    meet(&alice, &bob);
    assert_eq!(say(&alice, &bob, "a1", "queued").state, S::Queued);
    for _ in 0..2 {
        alice.net.delete_contact(bob.pk.clone()).unwrap();
        assert_forgotten(&alice, &bob);
    }
    assert!(alice.net.conversations().unwrap().is_empty());
    alice.net.delete_contact(stranger.pk.clone()).unwrap();
    assert!(matches!(
        alice.net.delete_contact(vec![1; 31]),
        Err(CoreError::InvalidKey { .. })
    ));

    meet(&alice, &bob);
    assert_eq!(alice.net.chat_entries(bob.pk.clone()).unwrap(), vec![]);
    assert_eq!(say(&alice, &bob, "a1", "queued again").state, S::Queued);
    rounds(&[&bob, &alice, &bob, &alice], 1);
    assert_eq!(
        chat(&bob, &alice),
        vec![(false, S::Received, "queued again".into())]
    );
    assert_eq!(
        chat(&alice, &bob),
        vec![(true, S::Delivered, "queued again".into())]
    );
    relay.stop();
}

/// A text the relay accepted but the contact never receipted is abandoned
/// by the delete, never taken as delivered: the outbox is empty right after,
/// its send record reads abandoned, and under the new session its app id
/// commits nothing (`send_text` reports it abandoned with its old message
/// id, `chat_send` refuses it). The contact never receives it.
#[test]
fn a_text_without_a_receipt_is_abandoned_by_the_delete_not_delivered() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    say(&alice, &bob, "p1", "never receipted");
    round(&[&alice]);
    assert_eq!(
        chat(&alice, &bob).last().unwrap(),
        &(true, S::Transmitted, "never receipted".into())
    );
    let old_id = alice.net.undelivered(bob.pk.clone()).unwrap();
    assert_eq!(old_id.len(), 1);

    alice.net.delete_contact(bob.pk.clone()).unwrap();
    assert_forgotten(&alice, &bob);
    assert_eq!(
        alice
            .core
            .prior_send(&key(&bob), &client_id::text(b"p1"))
            .unwrap(),
        Some(SendResult::Abandoned {
            message_id: old_id[0].clone()
        })
    );

    bob.net.delete_contact(alice.pk.clone()).unwrap();
    meet(&alice, &bob);
    say(&alice, &bob, "p2", "fresh");
    rounds(&[&alice, &bob, &alice], 1);
    assert_eq!(session(&alice, &bob), ChatSessionState::Established);
    assert!(matches!(
        alice.net.chat_send(
            bob.pk.clone(),
            b"p1".to_vec(),
            format!("again{}", canary())
        ),
        Err(CoreError::InvalidArgument { .. })
    ));
    let again = alice
        .net
        .send_text(bob.pk.clone(), b"p1".to_vec(), format!("again{}", canary()).into_bytes())
        .unwrap();
    assert_eq!(again.state, TextState::Abandoned);
    assert_eq!(again.message_id, old_id[0]);
    assert!(alice.net.undelivered(bob.pk.clone()).unwrap().is_empty());
    rounds(&[&alice, &bob], 2);
    assert_eq!(chat(&bob, &alice), vec![(false, S::Received, "fresh".into())]);
    assert_eq!(chat(&alice, &bob), vec![(true, S::Delivered, "fresh".into())]);
    relay.stop();
}

/// A call that checked the contact before a delete and writes after it
/// writes nothing (review probe): here `chat_send`, with the delete landing
/// between its contact check and the transaction that records the entry,
/// and the open-entry build of a background refresh run after the delete.
/// The send fails as for any non-contact, and a re-added contact starts with
/// an empty history and no flags.
#[test]
fn a_write_racing_a_delete_leaves_nothing_for_the_contact() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    meet(&alice, &bob);
    let (net, peer) = (alice.net.clone(), bob.pk.clone());
    crate::network::chat::test_hooks::set_chat_send_before_record(move || {
        net.delete_contact(peer).unwrap()
    });
    assert!(matches!(
        alice
            .net
            .chat_send(bob.pk.clone(), b"r1".to_vec(), format!("x{}", canary())),
        Err(CoreError::UnknownContact)
    ));
    assert_forgotten(&alice, &bob);
    let (record, scan) = alice.net.open_record_and_scan(&bob.pk);
    assert!(record.is_empty() && scan.is_empty());
    assert_eq!(remaining(&alice, &bob), Vec::<String>::new());

    meet(&alice, &bob);
    assert_eq!(alice.net.chat_entries(bob.pk.clone()).unwrap(), vec![]);
    let c = alice.net.conversation(bob.pk.clone()).unwrap();
    assert_eq!(
        (c.session, c.identity_mismatch, c.handshake_refused, c.unread),
        (ChatSessionState::None, false, false, 0)
    );
    relay.stop();
}
