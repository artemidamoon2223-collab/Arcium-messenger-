//! Conversations (`network/chat.rs`) between independent devices over a real
//! relay: what an application shows, across restarts, offline peers, repeats,
//! duplicates, a forged bundle and a session conflict. Process deaths are in
//! `network_crash.rs`.

use super::net_harness::*;
use super::*;
use crate::network::chat::{ChatEntry, ChatEntryState as S, ChatSessionState};
use crate::network::wire::Envelope;

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
        .map(|e| (e.outgoing, e.state, e.text.replace(&canary(), "")))
        .collect()
}

fn invalid<T>(r: Result<T, CoreError>) -> bool {
    matches!(r, Err(CoreError::InvalidArgument { .. }))
}

fn session(from: &Device, with: &Device) -> ChatSessionState {
    from.net.conversation(with.pk.clone()).unwrap().session
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

#[test]
fn the_first_text_starts_a_session_and_both_histories_survive_restarts() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    meet(&alice, &bob);
    round(&[&bob]); // Bob's bundle reaches the relay.

    let first = say(&alice, &bob, "a1", "hello bob");
    assert_eq!(first.state, S::Queued, "no session yet: nothing encrypted");
    assert_eq!(session(&alice, &bob), ChatSessionState::None);

    round(&[&alice]);
    assert_eq!(
        chat(&alice, &bob),
        vec![(true, S::Transmitted, "hello bob".into())]
    );
    assert_eq!(session(&alice, &bob), ChatSessionState::AwaitingPeer);

    round(&[&bob]);
    assert_eq!(
        chat(&bob, &alice),
        vec![(false, S::Received, "hello bob".into())]
    );
    assert_eq!(bob.net.conversation(alice.pk.clone()).unwrap().unread, 1);
    bob.net.mark_seen(alice.pk.clone()).unwrap();
    assert_eq!(bob.net.conversation(alice.pk.clone()).unwrap().unread, 0);

    round(&[&alice]);
    assert_eq!(
        chat(&alice, &bob)[0].1,
        S::Delivered,
        "Bob's receipt arrived"
    );
    assert_eq!(session(&alice, &bob), ChatSessionState::Established);

    say(&bob, &alice, "b1", "hi alice");
    rounds(&[&bob, &alice, &bob], 1);
    let alice_before = chat(&alice, &bob);
    let bob_before = chat(&bob, &alice);
    assert_eq!(
        alice_before,
        vec![
            (true, S::Delivered, "hello bob".into()),
            (false, S::Received, "hi alice".into()),
        ]
    );
    assert_eq!(bob_before[1], (true, S::Delivered, "hi alice".into()));

    let (alice, bob) = (alice.restart(&addr), bob.restart(&addr));
    assert_eq!(chat(&alice, &bob), alice_before);
    assert_eq!(chat(&bob, &alice), bob_before);
    assert_eq!(session(&alice, &bob), ChatSessionState::Established);
    assert_eq!(alice.net.conversation(bob.pk.clone()).unwrap().name, "peer");

    say(&bob, &alice, "b2", "after restart");
    rounds(&[&bob, &alice, &bob], 1);
    assert_eq!(
        chat(&alice, &bob)[2],
        (false, S::Received, "after restart".into())
    );
    assert_eq!(
        chat(&bob, &alice)[2],
        (true, S::Delivered, "after restart".into())
    );
    assert_eq!(relay.canary_hits(), 0, "no plaintext reached the relay");
    relay.stop();
}

#[test]
fn repeating_a_send_never_records_or_encrypts_it_twice() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    let before = chat(&alice, &bob).len();

    let first = say(&alice, &bob, "x", "once");
    let again = say(&alice, &bob, "x", "a different text under the same id");
    assert_eq!(again.seq, first.seq);
    assert_eq!(again.text, first.text, "the first text stands");
    assert_eq!(chat(&alice, &bob).len(), before + 1);
    assert_eq!(
        alice.undelivered(&bob),
        1,
        "one ciphertext for the logical message"
    );

    // State left by a crash between the outbox commit and the history update:
    // the outbox holds the text, the history only the queued record.
    alice
        .net
        .send_text(bob.pk.clone(), b"y".to_vec(), b"committed".to_vec())
        .unwrap();
    say(&alice, &bob, "y", "committed");
    assert_eq!(
        alice.undelivered(&bob),
        2,
        "the committed message was reused"
    );

    rounds(&[&alice, &bob, &alice], 1);
    let texts: Vec<_> = chat(&bob, &alice).into_iter().map(|e| e.2).collect();
    assert_eq!(texts.iter().filter(|t| *t == "once").count(), 1);
    assert_eq!(
        texts.iter().filter(|t| t.starts_with("committed")).count(),
        1
    );
    assert_eq!(chat(&alice, &bob)[before].1, S::Delivered);
    relay.stop();
}

#[test]
fn an_offline_contact_gets_every_text_once_and_delivered_waits_for_its_receipt() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    for i in 1..=3 {
        say(&alice, &bob, &format!("q{i}"), &format!("queued {i}"));
    }
    rounds(&[&alice], 3); // Bob stays offline.
    let states: Vec<_> = chat(&alice, &bob)[2..].iter().map(|e| e.1).collect();
    assert_eq!(
        states,
        vec![S::Transmitted; 3],
        "the relay's acceptance is not a receipt"
    );

    round(&[&bob]);
    let received: Vec<_> = chat(&bob, &alice)[2..]
        .iter()
        .map(|e| e.2.clone())
        .collect();
    assert_eq!(received, vec!["queued 1", "queued 2", "queued 3"]);

    rounds(&[&alice, &bob], 2);
    let states: Vec<_> = chat(&alice, &bob)[2..].iter().map(|e| e.1).collect();
    assert_eq!(states, vec![S::Delivered; 3]);
    assert_eq!(chat(&bob, &alice).len(), 5, "each text appears once");
    relay.stop();
}

#[test]
fn a_replayed_message_does_not_repeat_in_the_history() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    say(&alice, &bob, "d", "only once");
    round(&[&alice]);
    let wires = stored_messages(&relay, &bob);
    round(&[&bob]);
    for wire in wires {
        inject(
            &addr,
            &bob,
            Envelope::Message {
                sender: alice.pk.as_slice().try_into().unwrap(),
                wire,
            }
            .encode(),
        );
    }
    let r = bob.net.sync_conversations();
    assert!(r.duplicates > 0, "{r:?}");
    let texts: Vec<_> = chat(&bob, &alice).into_iter().map(|e| e.2).collect();
    assert_eq!(texts.iter().filter(|t| *t == "only once").count(), 1);
    relay.stop();
}

#[test]
fn a_bundle_that_does_not_match_the_verified_card_is_refused_and_shown() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, carol, mallory) = (
        Device::new(&addr, 1),
        Device::new(&addr, 3),
        Device::new(&addr, 4),
    );
    alice
        .net
        .add_named_contact(carol.core.contact_card().unwrap(), "carol".into())
        .unwrap();
    // Carol has never been online; Mallory publishes her bundle under
    // Carol's key.
    mallory.core.establish_prekeys().unwrap();
    relay::client::Connection::connect(&addr, std::time::Duration::from_secs(2))
        .unwrap()
        .put_bundle(
            carol.pk.as_slice().try_into().unwrap(),
            mallory.core.export_prekey_bundle().unwrap(),
        )
        .unwrap();

    say(&alice, &carol, "m", "for carol only");
    rounds(&[&alice], 2);
    let conversation = alice.net.conversation(carol.pk.clone()).unwrap();
    assert!(conversation.identity_mismatch);
    assert_eq!(conversation.session, ChatSessionState::None);
    assert_eq!(
        chat(&alice, &carol)[0].1,
        S::Queued,
        "nothing was encrypted"
    );
    assert!(stored_messages(&relay, &carol).is_empty());
    assert_eq!(relay.canary_hits(), 0);
    relay.stop();
}

#[test]
fn a_contact_that_never_came_online_keeps_the_text_queued_until_it_does() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    meet(&alice, &bob);
    say(&alice, &bob, "w", "waiting");
    round(&[&alice]);
    let conversation = alice.net.conversation(bob.pk.clone()).unwrap();
    assert_eq!(conversation.session, ChatSessionState::None);
    assert!(!conversation.note.is_empty(), "the reason is shown");
    assert_eq!(chat(&alice, &bob)[0].1, S::Queued);

    rounds(&[&bob, &alice, &bob, &alice], 1);
    assert_eq!(
        chat(&bob, &alice),
        vec![(false, S::Received, "waiting".into())]
    );
    assert_eq!(chat(&alice, &bob)[0].1, S::Delivered);
    assert!(alice
        .net
        .conversation(bob.pk.clone())
        .unwrap()
        .note
        .is_empty());
    relay.stop();
}

#[test]
fn a_session_conflict_is_shown_and_resolved_on_one_device_without_losing_texts() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    meet(&alice, &bob);
    rounds(&[&alice, &bob], 1); // Both bundles on the relay.
    say(&alice, &bob, "a", "from alice");
    say(&bob, &alice, "b", "from bob");
    // Both start before either sees the other's handshake.
    alice.net.start_session(bob.pk.clone()).unwrap();
    bob.net.start_session(alice.pk.clone()).unwrap();
    rounds(&[&alice, &bob], 2);

    let (g, s) = if alice.pk > bob.pk {
        (&alice, &bob)
    } else {
        (&bob, &alice)
    };
    assert_eq!(
        session(g, s),
        ChatSessionState::Conflict { can_resolve: true }
    );
    assert_eq!(
        session(s, g),
        ChatSessionState::Conflict { can_resolve: false }
    );
    assert!(
        chat(g, s).iter().all(|e| e.0),
        "nothing decrypts across the two sessions"
    );
    assert!(matches!(
        s.net.resolve_session_conflict(g.pk.clone()),
        Err(CoreError::InvalidArgument { .. })
    ));

    g.net.resolve_session_conflict(s.pk.clone()).unwrap();
    g.net.resolve_session_conflict(s.pk.clone()).unwrap_err(); // Already resolved.
    assert_eq!(session(g, s), ChatSessionState::AwaitingPeerSession);
    assert_eq!(
        chat(g, s)[0].1,
        S::NotDelivered,
        "its session's texts were given up"
    );

    rounds(&[g, s, g, s], 2);
    assert_eq!(session(g, s), ChatSessionState::Established);
    assert_eq!(session(s, g), ChatSessionState::Established);
    let g_text = chat(g, s)[0].2.clone();
    let s_text = chat(s, g)[0].2.clone();
    assert!(chat(g, s).contains(&(false, S::Received, s_text.clone())));
    assert_eq!(chat(s, g)[0], (true, S::Delivered, s_text));

    // The user resends the text given up on, as a new message.
    g.net
        .chat_send(
            s.pk.clone(),
            b"again".to_vec(),
            format!("{g_text}{}", canary()),
        )
        .unwrap();
    rounds(&[g, s, g], 1);
    assert!(chat(s, g).contains(&(false, S::Received, g_text.clone())));
    assert_eq!(chat(g, s).last().unwrap(), &(true, S::Delivered, g_text));
    assert_eq!(relay.canary_hits(), 0);
    relay.stop();
}

#[test]
fn names_texts_and_ids_are_checked_and_unknown_contacts_refused() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob, stranger) = (
        Device::new(&addr, 1),
        Device::new(&addr, 2),
        Device::new(&addr, 3),
    );
    let card = bob.core.contact_card().unwrap();
    assert!(invalid(
        alice.net.add_named_contact(card.clone(), "  ".into())
    ));
    assert!(invalid(
        alice.net.add_named_contact(card.clone(), "x".repeat(129))
    ));
    alice
        .net
        .add_named_contact(card.clone(), " Bob ".into())
        .unwrap();
    assert_eq!(alice.net.conversation(bob.pk.clone()).unwrap().name, "Bob");

    let mut changed = card.clone();
    changed[40] ^= 1; // Same X25519 key, another signing key.
    assert!(matches!(
        alice.net.add_named_contact(changed, "Bob".into()),
        Err(CoreError::ContactIdentityChanged)
    ));
    assert_eq!(
        alice.net.conversation(bob.pk.clone()).unwrap().fingerprint,
        crate::contacts::contact_card_fingerprint(card).unwrap(),
        "the pinned card is unchanged"
    );

    let send = |id: &[u8], text: &str| {
        alice
            .net
            .chat_send(bob.pk.clone(), id.to_vec(), text.into())
    };
    assert!(invalid(send(b"", "x")));
    assert!(invalid(send(&[1; 64], "x")));
    assert!(invalid(send(b"i", "")));
    assert!(invalid(send(b"i", &"x".repeat(16 * 1024 + 1))));
    assert!(matches!(
        alice
            .net
            .chat_send(stranger.pk.clone(), b"i".to_vec(), "x".into()),
        Err(CoreError::UnknownContact)
    ));
    assert!(invalid(alice.net.resolve_session_conflict(bob.pk.clone())));
    assert_eq!(alice.net.chat_entries(bob.pk.clone()).unwrap(), vec![]);
    relay.stop();
}
