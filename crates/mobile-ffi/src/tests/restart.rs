//! Option B of `docs/SESSION-RECOVERY-OPTIONS.md`: the user restarts the
//! secure session with a contact (`reset_session`), and the contact's device
//! replaces its own copy of the old session once the first message under
//! the new handshake authenticates beside it (`docs/NET-MESSAGING.md`
//! section 10, "Reset"; `docs/S2-B2-DURABLE-MESSAGING.md` sections 4c, 6a).
//!
//! A handshake alone replaces nothing; neither does a replay of one older
//! than the session, nor anything a writer to the mailbox can make without
//! the contact's identity secret. When both users reset at once, the
//! existing conflict is shown and resolved (Owner decision, 2026-11-18).

use super::net_harness::*;
use super::*;
use crate::network::chat::{ChatEntryState as S, ChatSessionState};
use crate::network::wire::{Envelope, Payload};

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

fn say(from: &Device, to: &Device, app_id: &str, text: &str) {
    from.net
        .chat_send(
            to.pk.clone(),
            app_id.as_bytes().to_vec(),
            format!("{text}{}", canary()),
        )
        .unwrap();
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

fn peer_reset(from: &Device, with: &Device) -> bool {
    from.net.conversation(with.pk.clone()).unwrap().peer_reset
}

fn key(d: &Device) -> [u8; 32] {
    d.pk.as_slice().try_into().unwrap()
}

fn handle(of: &Device) -> u64 {
    core_crypto::session_handle::local_session_handle(&key(of))
}

/// The provisional handshake record `d` holds under `other`'s handle, raw.
fn hsin(d: &Device, other: &Device) -> Option<Vec<u8>> {
    let store = d.core.store.lock().unwrap();
    match store.get(&format!("hsin:v1/{:016x}", handle(other))) {
        Ok(bytes) => Some(bytes),
        Err(StorageError::NotFound) => None,
        Err(e) => panic!("{e}"),
    }
}

/// Alice and Bob, contacts of each other, with an established session that
/// Alice started, and one text delivered each way.
fn talking(addr: &str) -> (Device, Device) {
    let (alice, bob) = (Device::new(addr, 1), Device::new(addr, 2));
    meet(&alice, &bob);
    round(&[&alice, &bob]); // Both bundles on the relay.
    say(&alice, &bob, "a1", "hello bob");
    rounds(&[&alice, &bob], 3);
    say(&bob, &alice, "b1", "hello alice");
    rounds(&[&bob, &alice], 3);
    assert_eq!(session(&alice, &bob), ChatSessionState::Established);
    assert_eq!(session(&bob, &alice), ChatSessionState::Established);
    (alice, bob)
}

/// Alice resets the session while a text waits in each direction. Hers is
/// given up at once (`NotDelivered`); Bob's is given up when his device
/// replaces the session on Alice's first message under the new one, and
/// Bob is told the contact restarted it. New texts then go both ways, and
/// Bob's next text clears the notice.
#[test]
fn a_reset_replaces_the_session_on_both_devices() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);

    say(&bob, &alice, "b2", "pending from bob");
    round(&[&bob]); // On the relay; Alice is offline.
    say(&alice, &bob, "a2", "pending from alice");
    alice.net.reset_session(bob.pk.clone()).unwrap();
    assert_eq!(session(&alice, &bob), ChatSessionState::None);
    assert_eq!(
        chat(&alice, &bob).last().unwrap(),
        &(true, S::NotDelivered, "pending from alice".into()),
        "given up with the old session"
    );

    rounds(&[&alice, &bob, &alice, &bob], 3);
    assert_eq!(session(&alice, &bob), ChatSessionState::Established);
    assert_eq!(session(&bob, &alice), ChatSessionState::Established);
    assert!(peer_reset(&bob, &alice), "Bob is told");
    assert!(!peer_reset(&alice, &bob));
    assert_eq!(
        chat(&bob, &alice).last().unwrap(),
        &(true, S::NotDelivered, "pending from bob".into()),
        "Alice could no longer read it"
    );
    assert!(
        !chat(&alice, &bob).iter().any(|e| e.2 == "pending from bob"),
        "it never reached Alice"
    );

    say(&alice, &bob, "a3", "after the reset");
    say(&bob, &alice, "b3", "after the reset too");
    assert!(!peer_reset(&bob, &alice), "Bob writing again clears the notice");
    rounds(&[&alice, &bob, &alice, &bob], 2);
    assert!(chat(&alice, &bob).contains(&(true, S::Delivered, "after the reset".into())));
    assert!(chat(&alice, &bob).contains(&(false, S::Received, "after the reset too".into())));
    assert!(chat(&bob, &alice).contains(&(true, S::Delivered, "after the reset too".into())));
    assert!(chat(&bob, &alice).contains(&(false, S::Received, "after the reset".into())));
    assert_eq!(relay.canary_hits(), 0);
    relay.stop();
}

/// A text Alice sent on the old session just before resetting arrives at
/// Bob in the same round as her new handshake and first message. Bob reads
/// it on the old session, which keeps the handshake recorded beside it, and
/// replaces the session in that same round. (Alice gave her text up at the
/// reset, so it reads `NotDelivered` there although Bob read it.)
#[test]
fn an_old_session_message_arriving_with_the_restart_does_not_stop_it() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    say(&alice, &bob, "a2", "sent just before the reset");
    round(&[&alice]);
    alice.net.reset_session(bob.pk.clone()).unwrap();
    round(&[&alice]); // The new handshake and first message.
    round(&[&bob]);
    assert!(peer_reset(&bob, &alice), "replaced in this round");
    assert!(chat(&bob, &alice).contains(&(false, S::Received, "sent just before the reset".into())));
    assert_eq!(hsin(&bob, &alice), None, "the new session came from it");
    rounds(&[&alice, &bob], 2);
    assert_eq!(session(&alice, &bob), ChatSessionState::Established);
    assert_eq!(session(&bob, &alice), ChatSessionState::Established);
    assert!(chat(&alice, &bob).contains(&(true, S::NotDelivered, "sent just before the reset".into())));
    relay.stop();
}

/// Situation 1 of `docs/SESSION-RECOVERY-OPTIONS.md`: after resolving a
/// false conflict, one device waits for a handshake that never comes while
/// the other holds an established session the first cannot read. Before
/// option B only deleting the contact on both devices ended it. A reset on
/// the waiting device does: the other replaces its session on the first
/// message of the new one.
#[test]
fn a_reset_ends_the_dead_end_of_a_false_conflict() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    let (g, s) = if alice.pk > bob.pk {
        (&alice, &bob)
    } else {
        (&bob, &alice)
    };
    meet(g, s);
    round(&[g, s]);

    // s starts a session while g is offline; its handshake and first
    // messages are captured on the relay and deleted, and s deletes and
    // re-adds g, so that session is gone and g never saw it.
    say(s, g, "s0", "never seen by g");
    round(&[s]);
    let captured = relay.stored(&key(g));
    relay::client::Connection::connect(&addr, std::time::Duration::from_secs(2))
        .unwrap()
        .delete(key(g), captured.iter().map(|(seq, _)| *seq).collect())
        .unwrap();
    s.net.delete_contact(g.pk.clone()).unwrap();
    s.net
        .add_named_contact(g.core.contact_card().unwrap(), "peer".into())
        .unwrap();
    say(g, s, "g1", "lost in the dead end");
    round(&[g]);
    for (_, env) in captured {
        inject(&addr, g, env);
    }
    round(&[g]);
    assert_eq!(session(g, s), ChatSessionState::Conflict { can_resolve: true });
    g.net.resolve_session_conflict(s.pk.clone()).unwrap();
    rounds(&[s, g], 3);
    assert_eq!(session(s, g), ChatSessionState::Established);
    assert_eq!(session(g, s), ChatSessionState::AwaitingPeerSession, "the dead end");

    g.net.reset_session(s.pk.clone()).unwrap();
    say(g, s, "g2", "after the reset");
    rounds(&[g, s, g, s], 3);
    assert_eq!(session(g, s), ChatSessionState::Established);
    assert_eq!(session(s, g), ChatSessionState::Established);
    assert!(peer_reset(s, g));
    assert!(chat(g, s).contains(&(true, S::Delivered, "after the reset".into())));
    assert!(chat(s, g).contains(&(false, S::Received, "after the reset".into())));
    say(s, g, "s2", "and back");
    rounds(&[s, g, s], 2);
    assert!(chat(g, s).contains(&(false, S::Received, "and back".into())));
    assert_eq!(relay.canary_hits(), 0);
    relay.stop();
}

/// A handshake of the contact this device never accepted, built from a
/// bundle published before this device's own session was established, and
/// its first message, replayed after that, replace nothing: confirming the
/// session replaced the one-time prekey it names (`ArciumCore::new`), so it
/// is not even recorded. Before option B such a replay could raise a
/// conflict at most; with it, it would have replaced the session.
#[test]
fn a_replayed_handshake_older_than_the_session_never_replaces_it() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    meet(&alice, &bob);
    round(&[&alice, &bob]);

    // Bob's keys on a second, empty database build a handshake and a first
    // message against Alice's bundle as it is now: what a relay could have
    // withheld from Alice and kept.
    let second = ArciumCore::new(
        tempfile::tempdir().unwrap().keep().join("db").to_str().unwrap().to_string(),
        vec![9; 32],
    )
    .unwrap();
    second.save_identity(bob.core.load_identity().unwrap().unwrap()).unwrap();
    let h = handle(&alice);
    let old_handshake = second
        .establish_session_initiator(h, alice.core.export_prekey_bundle().unwrap())
        .unwrap();
    let old_first = match second
        .send_message(h, b"old".to_vec(), Payload::Text(b"replayed".to_vec().into()).encode().to_vec())
        .unwrap()
    {
        crate::SendResult::Sent { message } => message.wire,
        other => panic!("{other:?}"),
    };

    // Alice starts the session, Bob accepts it, and it is established.
    say(&alice, &bob, "a1", "hello bob");
    rounds(&[&alice, &bob], 3);
    say(&bob, &alice, "b1", "hello alice");
    rounds(&[&bob, &alice], 3);
    assert_eq!(session(&alice, &bob), ChatSessionState::Established);
    let history = chat(&alice, &bob);

    for env in [
        Envelope::Handshake {
            sender: key(&bob),
            handshake: old_handshake,
        },
        Envelope::Message {
            sender: key(&bob),
            wire: old_first,
        },
    ] {
        inject(&addr, &alice, env.encode());
    }
    round(&[&alice]);
    assert_eq!(hsin(&alice, &bob), None, "not answerable, so not recorded");
    assert_eq!(session(&alice, &bob), ChatSessionState::Established);
    assert!(!peer_reset(&alice, &bob));
    assert_eq!(chat(&alice, &bob), history);
    say(&bob, &alice, "b2", "the session goes on");
    rounds(&[&bob, &alice], 2);
    assert!(chat(&alice, &bob).contains(&(false, S::Received, "the session goes on".into())));
    relay.stop();
}

/// A handshake "from" the contact anyone can make from public bytes (it
/// even passes the prekey rules) is recorded beside the established
/// session, and a forged first message under it replaces nothing.
#[test]
fn a_forged_restart_replaces_nothing() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    let bundle = relay::client::Connection::connect(&addr, std::time::Duration::from_secs(2))
        .unwrap()
        .get_bundle(key(&alice))
        .unwrap()
        .unwrap();
    let bundle = unpack_prekey_bundle(&bundle).unwrap();
    let forged = pack_initiator_handshake(
        &PublicKey::from(key(&bob)),
        &PublicKey::from(&StaticSecret::random_from_rng(OsRng)),
        &spk_id(bundle.signed_prekey_pk.as_bytes()),
        bundle.one_time_prekey_id,
    );
    let mut wire = vec![0u8; 40 + 48];
    OsRng.fill_bytes(&mut wire);
    wire[32..40].fill(0);
    inject(
        &addr,
        &alice,
        Envelope::Handshake {
            sender: key(&bob),
            handshake: forged,
        }
        .encode(),
    );
    inject(&addr, &alice, Envelope::Message { sender: key(&bob), wire }.encode());
    round(&[&alice]);
    assert!(hsin(&alice, &bob).is_some(), "recorded: it has no authority");
    assert_eq!(session(&alice, &bob), ChatSessionState::Established);
    assert!(!peer_reset(&alice, &bob));
    say(&bob, &alice, "b2", "still our session");
    say(&alice, &bob, "a2", "still ours");
    rounds(&[&bob, &alice, &bob], 2);
    assert!(chat(&alice, &bob).contains(&(false, S::Received, "still our session".into())));
    assert!(chat(&alice, &bob).contains(&(true, S::Delivered, "still ours".into())));
    relay.stop();
}

/// Both users reset at once: each starts a new session before the other's
/// handshake arrives, so each holds a new unconfirmed session and the
/// other's handshake beside it, which is the conflict of a simultaneous
/// start (Owner decision). The device with the greater key resolves it, and
/// the session is established on both. (A reset whose handshake arrives
/// before the other device starts its own is accepted there instead.)
#[test]
fn both_resetting_at_once_is_a_conflict_the_greater_key_resolves() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    alice.net.reset_session(bob.pk.clone()).unwrap();
    bob.net.reset_session(alice.pk.clone()).unwrap();
    // The new sessions start before either round reads the other's.
    alice.net.start_session(bob.pk.clone()).unwrap();
    bob.net.start_session(alice.pk.clone()).unwrap();
    rounds(&[&alice, &bob], 3);
    let (g, s) = if alice.pk > bob.pk {
        (&alice, &bob)
    } else {
        (&bob, &alice)
    };
    assert_eq!(session(g, s), ChatSessionState::Conflict { can_resolve: true });
    assert_eq!(session(s, g), ChatSessionState::Conflict { can_resolve: false });
    assert!(matches!(
        g.net.reset_session(s.pk.clone()),
        Err(CoreError::InvalidArgument { .. })
    ), "a conflict is resolved, not reset");
    g.net.resolve_session_conflict(s.pk.clone()).unwrap();
    rounds(&[g, s, g, s], 3);
    assert_eq!(session(g, s), ChatSessionState::Established);
    assert_eq!(session(s, g), ChatSessionState::Established);
    say(g, s, "g1", "after both resets");
    say(s, g, "s1", "after both resets too");
    rounds(&[g, s, g], 2);
    assert!(chat(s, g).contains(&(false, S::Received, "after both resets".into())));
    assert!(chat(g, s).contains(&(false, S::Received, "after both resets too".into())));
    relay.stop();
}

/// `reset_session` works without a connection and with no session (it then
/// only asks the next round to start one, also with no text queued),
/// repeats harmlessly, and is refused for a stranger.
#[test]
fn reset_session_rules() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    let stranger = Device::new(&addr, 3);
    meet(&alice, &bob);
    round(&[&alice, &bob]);
    assert!(matches!(
        alice.net.reset_session(stranger.pk.clone()),
        Err(CoreError::UnknownContact)
    ));
    alice.net.reset_session(bob.pk.clone()).unwrap();
    alice.net.reset_session(bob.pk.clone()).unwrap();
    assert_eq!(session(&alice, &bob), ChatSessionState::None);
    round(&[&alice]);
    assert_eq!(session(&alice, &bob), ChatSessionState::AwaitingPeer, "started with nothing queued");
    rounds(&[&bob, &alice], 2);
    assert_eq!(session(&alice, &bob), ChatSessionState::Established);
    assert_eq!(session(&bob, &alice), ChatSessionState::Established);
    assert!(!peer_reset(&bob, &alice), "a first contact, not a restart");
    relay.stop();
}

/// Process death at each new step of a reset, on the device that resets
/// (`reset_*`) and on the one that replaces its session (`restart_*`): each
/// repeats safely, and the session is established on both afterwards.
#[cfg(unix)]
#[test]
fn process_death_at_each_restart_step_repeats_safely() {
    for point in [
        "reset_after_mark",
        "reset_after_abandon",
        "reset_after_retire",
        "restart_after_record",
        "restart_after_flag",
        "restart_after_mark",
        "restart_after_abandon",
    ] {
        let relay = start_relay();
        let addr = relay.addr().to_string();
        let (alice, bob) = talking(&addr);
        say(&alice, &bob, "a2", "pending from alice");
        say(&bob, &alice, "b2", "pending from bob");
        round(&[&bob]);
        let (alice, bob) = if point.starts_with("reset_") {
            super::network_crash::run_child(&alice, &addr, "reset", Some(point), &bob.pk);
            let alice = alice.restart(&addr);
            // Calling it again completes it.
            alice.net.reset_session(bob.pk.clone()).unwrap();
            (alice, bob)
        } else {
            alice.net.reset_session(bob.pk.clone()).unwrap();
            round(&[&alice]);
            super::network_crash::run_child(&bob, &addr, "chat_sync", Some(point), &alice.pk);
            let bob = bob.restart(&addr);
            (alice, bob)
        };
        rounds(&[&alice, &bob, &alice, &bob], 3);
        assert_eq!(session(&alice, &bob), ChatSessionState::Established, "{point}");
        assert_eq!(session(&bob, &alice), ChatSessionState::Established, "{point}");
        assert!(
            chat(&alice, &bob).contains(&(true, S::NotDelivered, "pending from alice".into())),
            "{point}"
        );
        assert!(
            chat(&bob, &alice).contains(&(true, S::NotDelivered, "pending from bob".into())),
            "{point}"
        );
        assert!(peer_reset(&bob, &alice), "{point}");
        say(&alice, &bob, "a3", "after");
        rounds(&[&alice, &bob, &alice], 2);
        assert!(chat(&bob, &alice).contains(&(false, S::Received, "after".into())), "{point}");
        relay.stop();
    }
}
