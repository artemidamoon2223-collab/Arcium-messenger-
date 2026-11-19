//! Option B of `docs/SESSION-RECOVERY-OPTIONS.md`: the user restarts the
//! secure session with a contact (`reset_session`), and the contact's device
//! replaces its own copy of the old session once the first message under
//! the new handshake authenticates beside it (`docs/NET-MESSAGING.md`
//! section 10, "Reset"; `docs/S2-B2-DURABLE-MESSAGING.md` sections 4c, 6a).
//!
//! A handshake alone replaces nothing; neither does a replay of one older
//! than the session, nor anything a writer to the mailbox can make without
//! the contact's identity secret (or this device's signed-prekey secret:
//! `docs/NET-MESSAGING.md` section 8). When both users reset at once, the
//! existing conflict is shown and resolved (Owner decision, 2026-11-18).

use super::net_harness::*;
use super::*;
use crate::network::chat::{test_hooks, ChatEntryState as S, ChatSessionState};
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

/// How many envelopes of each kind wait in `to`'s mailbox:
/// (handshakes, refusals).
fn waiting(relay: &relay::server::RelayHandle, to: &Device) -> (usize, usize) {
    let kinds: Vec<_> = relay
        .stored(&key(to))
        .into_iter()
        .filter_map(|(_, e)| Envelope::decode(e.as_slice()))
        .collect();
    (
        kinds.iter().filter(|e| matches!(e, Envelope::Handshake { .. })).count(),
        kinds.iter().filter(|e| matches!(e, Envelope::Refusal { .. })).count(),
    )
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

/// Alice's restart names the one-time prekey of Bob's bundle, and Carol's
/// first contact, ahead of it in Bob's mailbox, consumes that prekey first.
/// Bob can no longer answer the restart: he refuses it, and Alice makes it
/// again from his current bundle, so the session is replaced on both
/// devices. Without the refusal both would wait for good: Alice for an
/// answer, Bob on the old session (review of option B).
#[test]
fn a_restart_the_contact_can_no_longer_answer_is_refused_and_made_again() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    let carol = Device::new(&addr, 3);
    meet(&carol, &bob);
    say(&carol, &bob, "c1", "hello bob");
    round(&[&carol]);
    alice.net.reset_session(bob.pk.clone()).unwrap();
    round(&[&alice]);
    // Bob records the restart beside the session (handshakes are read
    // first), then Carol's first message consumes the prekey it names, so
    // Alice's first message no longer authenticates there.
    round(&[&bob]);
    assert_eq!(session(&bob, &carol), ChatSessionState::Established);
    assert_eq!(waiting(&relay, &alice).1, 0);
    // Alice sends both again; Bob can no longer answer the handshake.
    rounds(&[&alice, &bob], 1);
    assert_eq!(session(&bob, &alice), ChatSessionState::Established, "the old one");
    assert!(waiting(&relay, &alice).1 >= 1, "the restart is refused");

    rounds(&[&alice, &bob], 4);
    assert_eq!(session(&alice, &bob), ChatSessionState::Established);
    assert_eq!(session(&bob, &alice), ChatSessionState::Established);
    assert!(peer_reset(&bob, &alice), "replaced on Bob's device too");
    say(&alice, &bob, "a3", "after");
    rounds(&[&alice, &bob, &alice], 2);
    assert!(chat(&bob, &alice).contains(&(false, S::Received, "after".into())));
    assert!(chat(&alice, &bob).contains(&(true, S::Delivered, "after".into())));
    relay.stop();
}

/// Bob accepts Alice's first handshake, and a copy of it arrives again
/// before his receipt reaches Alice (she retransmits until then). The copy
/// can no longer be answered, but is not refused: it is the handshake
/// Bob's session came from, and a refusal naming it would end Alice's.
/// Also when the relay put another encoding of Alice's ephemeral key in
/// place of hers before Bob read it, one that derives the same keys, so
/// the session Bob made is Alice's though the bytes Bob recorded differ
/// from the copy's (second review of option B).
#[test]
fn a_late_copy_of_the_handshake_the_session_came_from_is_never_refused() {
    for substitute in [None, Some(0), Some(1)] {
        let relay = start_relay();
        let addr = relay.addr().to_string();
        let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
        meet(&alice, &bob);
        round(&[&bob]); // Bob's bundle on the relay.
        say(&alice, &bob, "a1", "hello bob");
        round(&[&alice]);
        let (seq, copy, handshake) = relay
            .stored(&key(&bob))
            .into_iter()
            .find_map(|(seq, e)| match Envelope::decode(&e) {
                Some(Envelope::Handshake { handshake, .. }) => Some((seq, e, handshake)),
                _ => None,
            })
            .expect("Alice's handshake");
        if let Some(which) = substitute {
            let ephemeral: [u8; 32] = handshake[36..68].try_into().unwrap();
            let mut changed = handshake.clone();
            changed[36..68].copy_from_slice(&same_keys_other_encodings(ephemeral)[which]);
            relay::client::Connection::connect(&addr, std::time::Duration::from_secs(2))
                .unwrap()
                .delete(key(&bob), vec![seq])
                .unwrap();
            let env = Envelope::Handshake {
                sender: key(&alice),
                handshake: changed,
            };
            inject(&addr, &bob, env.encode());
        }
        round(&[&bob]);
        assert_eq!(session(&bob, &alice), ChatSessionState::Established, "{substitute:?}");
        assert!(
            chat(&bob, &alice).contains(&(false, S::Received, "hello bob".into())),
            "Alice's first message authenticated: {substitute:?}"
        );
        inject(&addr, &bob, copy);
        round(&[&bob]);
        assert_eq!(waiting(&relay, &bob).0, 0, "the copy was read: {substitute:?}");
        assert_eq!(waiting(&relay, &alice).1, 0, "and not refused: {substitute:?}");

        rounds(&[&alice, &bob, &alice], 2);
        assert_eq!(session(&alice, &bob), ChatSessionState::Established, "{substitute:?}");
        assert!(
            chat(&alice, &bob).contains(&(true, S::Delivered, "hello bob".into())),
            "{substitute:?}"
        );
        assert!(!peer_reset(&bob, &alice), "{substitute:?}");
        relay.stop();
    }
}

/// As when another first contact consumes the prekey, but here Bob's own
/// session with Carol is confirmed after Alice fetched his bundle, which
/// replaces his one-time prekey (`replace_prekey_on_confirm`): Bob refuses
/// Alice's restart, and she makes it again from his current bundle.
#[test]
fn a_restart_whose_prekey_a_confirmation_replaced_is_refused_and_made_again() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    let carol = Device::new(&addr, 3);
    meet(&carol, &bob);
    round(&[&carol]); // Carol's bundle on the relay.
    say(&bob, &carol, "b1", "hello carol");
    round(&[&bob]); // Bob starts his own session with Carol.
    round(&[&carol]); // Carol accepts it; her receipt waits for Bob.
    alice.net.reset_session(bob.pk.clone()).unwrap();
    round(&[&alice]);
    // Bob records the restart, then Carol's receipt confirms his session
    // and replaces the prekey the restart names.
    round(&[&bob]);
    assert_eq!(session(&bob, &carol), ChatSessionState::Established);
    assert_eq!(session(&bob, &alice), ChatSessionState::Established, "the old one");
    rounds(&[&alice, &bob], 1);
    assert!(waiting(&relay, &alice).1 >= 1, "the restart is refused");

    rounds(&[&alice, &bob], 4);
    assert_eq!(session(&alice, &bob), ChatSessionState::Established);
    assert_eq!(session(&bob, &alice), ChatSessionState::Established);
    assert!(peer_reset(&bob, &alice));
    say(&alice, &bob, "a3", "after");
    rounds(&[&alice, &bob, &alice], 2);
    assert!(chat(&alice, &bob).contains(&(true, S::Delivered, "after".into())));
    relay.stop();
}

/// Flips one ciphertext byte of `d`'s `hsacc:` record for `peer`, so it no
/// longer decrypts. The row is found as the only one whose value changes
/// when that record is written twice.
fn corrupt_accepted_handshake(d: &Device, peer: &Device) {
    let rows = || -> Vec<(Vec<u8>, Vec<u8>)> {
        let conn = rusqlite::Connection::open(&d.path).unwrap();
        let mut stmt = conn.prepare("SELECT k, v FROM kv ORDER BY k").unwrap();
        let all = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        all
    };
    let record = crate::accepted_handshake_key(&key(peer));
    d.core.store.lock().unwrap().put(&record, &[1; 32]).unwrap();
    let before = rows();
    d.core.store.lock().unwrap().put(&record, &[2; 32]).unwrap();
    let after = rows();
    let changed: Vec<_> = before
        .iter()
        .zip(&after)
        .filter(|(b, a)| b != a)
        .map(|(_, a)| a.clone())
        .collect();
    assert_eq!(changed.len(), 1, "exactly the record's row");
    let (k, mut v) = changed.into_iter().next().unwrap();
    v[30] ^= 0x01; // past the 24-byte nonce
    let conn = rusqlite::Connection::open(&d.path).unwrap();
    assert_eq!(conn.execute("UPDATE kv SET v = ?1 WHERE k = ?2", (v, k)).unwrap(), 1);
    assert!(matches!(
        d.core.store.lock().unwrap().get(&record),
        Err(StorageError::Decryption)
    ));
}

/// An `hsacc:` record that no longer decrypts (damage, or tampering with
/// the store) stops no round: a late copy of the handshake is then refused,
/// as for a session an older build stored. The next restart still replaces
/// the session and writes the record again.
#[test]
fn an_unreadable_accepted_handshake_record_stops_nothing() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    let original = alice.core.initiator_handshake(handle(&bob)).unwrap().unwrap();
    corrupt_accepted_handshake(&bob, &alice);

    let env = Envelope::Handshake {
        sender: key(&alice),
        handshake: original,
    };
    inject(&addr, &bob, env.encode());
    say(&alice, &bob, "a2", "still here");
    rounds(&[&alice, &bob], 1);
    assert!(chat(&bob, &alice).contains(&(false, S::Received, "still here".into())));
    assert_eq!(waiting(&relay, &alice).1, 1, "the copy is refused");
    rounds(&[&alice, &bob], 2);
    assert_eq!(session(&alice, &bob), ChatSessionState::Established, "confirmed: ignored");
    assert!(chat(&alice, &bob).contains(&(true, S::Delivered, "still here".into())));

    alice.net.reset_session(bob.pk.clone()).unwrap();
    rounds(&[&alice, &bob, &alice, &bob], 3);
    assert_eq!(session(&alice, &bob), ChatSessionState::Established);
    assert_eq!(session(&bob, &alice), ChatSessionState::Established);
    assert!(peer_reset(&bob, &alice));
    let record = crate::accepted_handshake_key(&key(&alice));
    assert!(bob.core.store.lock().unwrap().get(&record).is_ok(), "repaired");
    relay.stop();
}

/// Alice reads Bob's text and sends her receipt under the old session, then
/// resets. Bob reads the receipt and the restart in one round: the text is
/// Delivered, not given up with the session (third review of option B).
#[test]
fn a_receipt_read_in_the_round_of_a_restart_still_counts() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    say(&bob, &alice, "b2", "read before the reset");
    round(&[&bob]);
    round(&[&alice]); // Alice accepts it and sends her receipt.
    alice.net.reset_session(bob.pk.clone()).unwrap();
    round(&[&alice]); // Her restart follows the receipt on the relay.
    round(&[&bob]);
    assert!(peer_reset(&bob, &alice), "the restart was accepted");
    assert!(chat(&bob, &alice).contains(&(true, S::Delivered, "read before the reset".into())));
    relay.stop();
}

/// A write to the contact's meta between reading it and the removal (here
/// a rename, as from another thread) fails the removal's precondition with
/// nothing written; the reset reads the meta again and completes, and the
/// rename stays (fourth review of option B).
#[test]
fn a_meta_write_racing_a_reset_does_not_stop_it() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    say(&alice, &bob, "a2", "pending");
    let (net, to) = (alice.net.clone(), bob.pk.clone());
    test_hooks::set_between_meta_and_retire(move || {
        net.rename_contact(to, "renamed".into()).unwrap();
    });
    alice.net.reset_session(bob.pk.clone()).unwrap();
    assert_eq!(session(&alice, &bob), ChatSessionState::None);
    assert_eq!(alice.net.conversation(bob.pk.clone()).unwrap().name, "renamed");
    assert_eq!(chat(&alice, &bob).last().unwrap(), &(true, S::NotDelivered, "pending".into()));
    rounds(&[&alice, &bob, &alice, &bob], 3);
    assert_eq!(session(&alice, &bob), ChatSessionState::Established);
    assert!(peer_reset(&bob, &alice));
    relay.stop();
}

/// On a store an earlier build wrote, the first round replaces the one-time
/// prekey before it reads the mailbox. A genuine handshake made from the
/// bundle published before (one this device never saw, replayed) is then
/// refused in that round, not recorded beside the session.
#[test]
fn a_handshake_from_before_the_upgrade_is_refused_in_the_first_upgraded_round() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    bob.core.store.lock().unwrap().delete("prekeys/renewed-b0").unwrap();
    // Alice's keys on a second database, against Bob's bundle of now.
    let second = ArciumCore::new(
        tempdir().unwrap().keep().join("db").to_str().unwrap().to_string(),
        key32(9),
    )
    .unwrap();
    second.save_identity(alice.core.load_identity().unwrap().unwrap()).unwrap();
    let handshake = second
        .establish_session_initiator(handle(&bob), bob.core.export_prekey_bundle().unwrap())
        .unwrap();
    let env = Envelope::Handshake {
        sender: key(&alice),
        handshake,
    };
    inject(&addr, &bob, env.encode());
    round(&[&bob]);
    assert!(hsin(&bob, &alice).is_none(), "not recorded beside the session");
    assert!(waiting(&relay, &alice).1 >= 1, "refused");
    assert_eq!(session(&bob, &alice), ChatSessionState::Established);
    relay.stop();
}

/// A session record that cannot be read is refused by `reset_session`
/// before anything changes: the texts committed to it are not given up.
#[test]
fn a_reset_of_an_unreadable_session_changes_nothing() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    say(&alice, &bob, "a2", "pending");
    let hex: String = key(&bob).iter().map(|b| format!("{b:02x}")).collect();
    alice
        .core
        .store
        .lock()
        .unwrap()
        .put(&format!("session:v1/{hex}"), b"not a session checkpoint")
        .unwrap();
    assert!(alice.net.reset_session(bob.pk.clone()).is_err());
    let last = chat(&alice, &bob).last().unwrap().clone();
    assert_eq!((last.0, last.2.as_str()), (true, "pending"));
    assert_ne!(last.1, S::NotDelivered, "nothing was given up");
    assert!(alice.core.has_session(handle(&bob)).unwrap());
    relay.stop();
}

/// The first time this build publishes from a store an earlier build wrote
/// (no mark yet), it replaces the one-time prekey once; later rounds keep
/// it, as does a new store's first round.
#[test]
fn a_store_from_before_option_b_replaces_its_one_time_prekey_once() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let d = Device::new(&addr, 1);
    d.net.publish_prekeys().unwrap();
    let first = d.core.export_prekey_bundle().unwrap();
    d.net.publish_prekeys().unwrap();
    assert_eq!(d.core.export_prekey_bundle().unwrap(), first, "a new store keeps it");
    // As a store an earlier build wrote: no mark.
    d.core.store.lock().unwrap().delete("prekeys/renewed-b0").unwrap();
    d.net.publish_prekeys().unwrap();
    let renewed = d.core.export_prekey_bundle().unwrap();
    assert_ne!(renewed, first, "replaced once");
    d.net.publish_prekeys().unwrap();
    assert_eq!(d.core.export_prekey_bundle().unwrap(), renewed, "and only once");
    relay.stop();
}

/// A text `chat_send` commits on the old session while a reset is giving
/// it up (the app runs a send on another thread than a reset): the reset
/// still completes, and that text is given up with the session.
#[test]
fn a_text_sent_while_a_reset_gives_the_session_up_is_given_up_with_it() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr);
    let (net, to) = (alice.net.clone(), bob.pk.clone());
    test_hooks::set_before_retire(move || {
        net.chat_send(to, b"a2".to_vec(), "sent meanwhile".into()).unwrap();
    });
    alice.net.reset_session(bob.pk.clone()).unwrap();
    assert_eq!(session(&alice, &bob), ChatSessionState::None);
    assert_eq!(
        chat(&alice, &bob).last().unwrap(),
        &(true, S::NotDelivered, "sent meanwhile".into())
    );
    rounds(&[&alice, &bob, &alice, &bob], 3);
    assert_eq!(session(&alice, &bob), ChatSessionState::Established);
    assert!(peer_reset(&bob, &alice));
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
/// repeats safely, and the session is established on both afterwards. Once
/// the session is removed, the reset needs no second call.
#[cfg(unix)]
#[test]
fn process_death_at_each_restart_step_repeats_safely() {
    for point in [
        "reset_after_mark",
        "reset_after_abandon",
        "reset_after_retire",
        "restart_after_record",
        "restart_after_mark",
        "restart_after_abandon",
        "restart_after_retire",
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
            // Before the removal, calling it again completes it; after it,
            // the request to start again was committed with the removal and
            // the next round acts on it alone.
            if point != "reset_after_retire" {
                alice.net.reset_session(bob.pk.clone()).unwrap();
            }
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
