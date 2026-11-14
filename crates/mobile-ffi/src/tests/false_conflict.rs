//! R-13, option A of `docs/SESSION-RECOVERY-OPTIONS.md`: a session conflict
//! is raised only by evidence that needs the contact's identity secret.
//!
//! A handshake "from" a pinned contact that arrives while this device holds
//! an unconfirmed session of its own is public bytes: anyone who reaches the
//! relay can make one. It is recorded beside that session and raises
//! nothing. The conflict is raised when a message from the contact, which
//! does not decrypt under our session, authenticates as the first message
//! under that recorded handshake (`docs/NET-MESSAGING.md` section 10,
//! `docs/S2-B2-DURABLE-MESSAGING.md` section 4c).

use super::net_harness::*;
use super::*;
use crate::network::chat::{ChatEntryState as S, ChatSessionState};
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

fn key(d: &Device) -> [u8; 32] {
    d.pk.as_slice().try_into().unwrap()
}

fn handle(of: &Device) -> u64 {
    core_crypto::session_handle::local_session_handle(&key(of))
}

/// Two fresh devices, the first with the greater identity key if `greater`.
fn two(addr: &str, greater: bool) -> (Device, Device) {
    let (x, y) = (Device::new(addr, 1), Device::new(addr, 2));
    if (x.pk > y.pk) == greater {
        (x, y)
    } else {
        (y, x)
    }
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

/// A handshake "from" `from` to `to` built from public bytes only: `from`'s
/// identity key, a fresh ephemeral key, and the prekey ids of `to`'s bundle
/// as the relay serves it to anyone. It passes `to`'s prekey rules, but no
/// one can make a message that authenticates under it without `from`'s
/// identity secret.
fn forged_handshake(addr: &str, from: &Device, to: &Device) -> Vec<u8> {
    let bundle = relay::client::Connection::connect(addr, std::time::Duration::from_secs(2))
        .unwrap()
        .get_bundle(key(to))
        .unwrap()
        .expect("to's bundle is on the relay");
    let bundle = unpack_prekey_bundle(&bundle).unwrap();
    let ephemeral = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
    pack_initiator_handshake(
        &PublicKey::from(key(from)),
        &ephemeral,
        &spk_id(bundle.signed_prekey_pk.as_bytes()),
        bundle.one_time_prekey_id,
    )
}

/// A "first message" from `from` anyone can make: a well-formed header
/// (a random ratchet key, message number 0) and random ciphertext.
fn forged_message(from: &Device) -> Vec<u8> {
    let mut wire = vec![0u8; 40 + 48];
    OsRng.fill_bytes(&mut wire);
    wire[32..40].fill(0);
    Envelope::Message {
        sender: key(from),
        wire,
    }
    .encode()
}

/// Removes from `to`'s mailbox, and returns, the envelopes `pick` selects:
/// what anyone can do on the relay (no authentication, R-9).
fn take(
    relay: &relay::server::RelayHandle,
    addr: &str,
    to: &Device,
    pick: impl Fn(&Envelope) -> bool,
) -> Vec<Vec<u8>> {
    let (seqs, taken): (Vec<u64>, Vec<Vec<u8>>) = relay
        .stored(&key(to))
        .into_iter()
        .filter(|(_, e)| Envelope::decode(e).is_some_and(|e| pick(&e)))
        .unzip();
    relay::client::Connection::connect(addr, std::time::Duration::from_secs(2))
        .unwrap()
        .delete(key(to), seqs)
        .unwrap();
    taken
}

fn is_message(e: &Envelope) -> bool {
    matches!(e, Envelope::Message { .. })
}

/// The device and the contact, each after one round so both bundles are on
/// the relay, and the device's own unconfirmed session with the contact
/// (its text committed), while the contact stays offline.
fn own_session(addr: &str, device_greater: bool) -> (Device, Device) {
    let (v, c) = two(addr, device_greater);
    meet(&v, &c);
    round(&[&c, &v]);
    say(&v, &c, "v1", "hello");
    round(&[&v]);
    assert_eq!(session(&v, &c), ChatSessionState::AwaitingPeer);
    (v, c)
}

/// The tracker's R-13 trigger, in both key orders: a handshake anyone can
/// forge (here one that even passes the prekey rules) and a forged first
/// message reach a device that holds its own unconfirmed session. Neither
/// raises a conflict, so there is nothing to resolve into the dead end. The
/// contact then accepts the device's own handshake, the session is
/// established as it would have been without the forgery, and the record
/// beside it is gone.
#[test]
fn a_forged_handshake_beside_our_own_session_raises_no_conflict() {
    for device_greater in [true, false] {
        let relay = start_relay();
        let addr = relay.addr().to_string();
        let (v, c) = own_session(&addr, device_greater);

        let forged = forged_handshake(&addr, &c, &v);
        inject(
            &addr,
            &v,
            Envelope::Handshake {
                sender: key(&c),
                handshake: forged.clone(),
            }
            .encode(),
        );
        inject(&addr, &v, forged_message(&c));
        round(&[&v]);
        assert_eq!(
            session(&v, &c),
            ChatSessionState::AwaitingPeer,
            "device_greater={device_greater}: nothing authenticated, nothing raised"
        );
        let beside = hsin(&v, &c).expect("the handshake is recorded beside our session");
        assert!(beside.ends_with(&forged));
        assert!(matches!(
            v.net.resolve_session_conflict(c.pk.clone()),
            Err(CoreError::InvalidArgument { .. })
        ));

        rounds(&[&c, &v], 2);
        assert_eq!(session(&v, &c), ChatSessionState::Established);
        assert_eq!(session(&c, &v), ChatSessionState::Established);
        assert_eq!(hsin(&v, &c), None, "confirming our session discarded it");
        assert_eq!(chat(&c, &v), vec![(false, S::Received, "hello".into())]);
        assert_eq!(chat(&v, &c), vec![(true, S::Delivered, "hello".into())]);

        say(&c, &v, "c1", "hi");
        rounds(&[&c, &v, &c], 1);
        assert_eq!(chat(&c, &v)[1], (true, S::Delivered, "hi".into()));
        assert_eq!(relay.canary_hits(), 0);
        relay.stop();
    }
}

/// A handshake beside our own session that this device can never answer
/// (here a forged one naming a one-time prekey it does not hold) raises no
/// conflict either. It is refused as a responder refuses one, and the
/// refusal changes nothing at the named contact, which holds no session
/// with that handshake: the contact drops it and accepts our session.
#[test]
fn an_unanswerable_handshake_beside_our_session_is_refused_and_raises_nothing() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (v, c) = own_session(&addr, true);
    let mut forged = forged_handshake(&addr, &c, &v);
    forged[83] ^= 1; // another one-time prekey id
    inject(
        &addr,
        &v,
        Envelope::Handshake {
            sender: key(&c),
            handshake: forged,
        }
        .encode(),
    );
    let r = v.net.sync_conversations();
    assert!(r.errors.iter().any(|e| e.starts_with("handshake refused")), "{:?}", r.errors);
    assert_eq!(session(&v, &c), ChatSessionState::AwaitingPeer);
    assert_eq!(hsin(&v, &c), None, "nothing recorded");
    let refusals = relay
        .stored(&key(&c))
        .iter()
        .filter(|(_, e)| matches!(Envelope::decode(e), Some(Envelope::Refusal { .. })))
        .count();
    assert_eq!(refusals, 1, "refused as a responder refuses");

    let r = c.net.sync_conversations();
    assert!(r.dropped >= 1, "the refusal names no handshake of c's: {r:?}");
    rounds(&[&v, &c], 2);
    assert_eq!(session(&v, &c), ChatSessionState::Established);
    assert_eq!(session(&c, &v), ChatSessionState::Established);
    assert_eq!(chat(&v, &c), vec![(true, S::Delivered, "hello".into())]);
    relay.stop();
}

/// A genuine simultaneous start, in both key orders. While only the
/// handshakes travel, each is recorded beside the other side's own session
/// and nothing is raised. Once each side's first message arrives and
/// authenticates, the conflict shows on both, only the greater key may
/// resolve it, and both end established with the smaller key's text
/// delivered; the greater key's given-up text is sent again as a new one.
#[test]
fn a_genuine_simultaneous_start_is_flagged_only_when_its_first_message_authenticates() {
    for alice_greater in [true, false] {
        let relay = start_relay();
        let addr = relay.addr().to_string();
        let (alice, bob) = two(&addr, alice_greater);
        meet(&alice, &bob);
        round(&[&alice, &bob]);
        say(&alice, &bob, "a", "from alice");
        say(&bob, &alice, "b", "from bob");
        alice.net.start_session(bob.pk.clone()).unwrap();
        bob.net.start_session(alice.pk.clone()).unwrap();

        // Only the handshakes arrive at first (a relay may withhold the rest).
        round(&[&alice]);
        take(&relay, &addr, &bob, is_message);
        round(&[&bob]);
        take(&relay, &addr, &alice, is_message);
        round(&[&alice]);
        take(&relay, &addr, &bob, is_message);
        for (d, other) in [(&alice, &bob), (&bob, &alice)] {
            assert_eq!(
                session(d, other),
                ChatSessionState::AwaitingPeer,
                "alice_greater={alice_greater}: a handshake alone raises nothing"
            );
            assert!(hsin(d, other).is_some(), "recorded beside the own session");
        }

        // The first messages arrive (retransmitted) and authenticate.
        round(&[&alice, &bob, &alice]);
        let (g, s) = if alice_greater { (&alice, &bob) } else { (&bob, &alice) };
        assert_eq!(session(g, s), ChatSessionState::Conflict { can_resolve: true });
        assert_eq!(session(s, g), ChatSessionState::Conflict { can_resolve: false });
        assert!(matches!(
            s.net.resolve_session_conflict(g.pk.clone()),
            Err(CoreError::InvalidArgument { .. })
        ));

        g.net.resolve_session_conflict(s.pk.clone()).unwrap();
        assert_eq!(session(g, s), ChatSessionState::AwaitingPeerSession);
        assert_eq!(hsin(g, s), None, "removed with the session it was beside");
        rounds(&[g, s, g, s], 2);
        assert_eq!(session(g, s), ChatSessionState::Established);
        assert_eq!(session(s, g), ChatSessionState::Established);
        assert_eq!(hsin(g, s), None);
        assert_eq!(hsin(s, g), None, "discarded once the peer confirmed ours");
        let (g_text, s_text) = if alice_greater {
            ("from alice", "from bob")
        } else {
            ("from bob", "from alice")
        };
        assert_eq!(chat(s, g)[0], (true, S::Delivered, s_text.into()));
        assert!(chat(g, s).contains(&(false, S::Received, s_text.into())));
        assert_eq!(chat(g, s)[0], (true, S::NotDelivered, g_text.into()));
        assert!(!chat(s, g).contains(&(false, S::Received, g_text.into())));

        say(g, s, "again", g_text);
        rounds(&[g, s, g], 1);
        assert!(chat(s, g).contains(&(false, S::Received, g_text.into())));
        assert_eq!(chat(g, s).last().unwrap(), &(true, S::Delivered, g_text.into()));
        assert_eq!(relay.canary_hits(), 0);
        relay.stop();
    }
}

/// A handshake recorded beside our own session goes when that session is
/// removed, and when the contact is deleted. Here it is the contact's
/// genuine handshake, recorded before this device started its own session
/// (a store written before this change can hold the same). After the
/// removal the contact's retransmitted handshake and first message create
/// the session as usual.
#[test]
fn a_record_beside_our_session_goes_with_the_session_and_with_the_contact() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = two(&addr, true);
    meet(&alice, &bob);
    round(&[&alice, &bob]);
    alice.net.start_session(bob.pk.clone()).unwrap();
    alice.sync();
    take(&relay, &addr, &bob, is_message);
    bob.sync();
    assert!(!bob.core.has_session(handle(&alice)).unwrap());
    assert!(hsin(&bob, &alice).is_some(), "recorded as provisional");
    bob.net.start_session(alice.pk.clone()).unwrap();
    assert!(hsin(&bob, &alice).is_some(), "now beside Bob's own session");

    // Removal needs nothing pending: Bob's opener is given up first.
    let h = handle(&alice);
    for m in bob.core.pending_outgoing(h).unwrap() {
        bob.core.abandon_outgoing(h, m.message_id).unwrap();
    }
    bob.core.remove_session(h).unwrap();
    assert_eq!(hsin(&bob, &alice), None, "removed with the session");
    settle(&[&alice, &bob]);
    assert_eq!(session(&bob, &alice), ChatSessionState::Established);
    assert_eq!(session(&alice, &bob), ChatSessionState::Established);

    // Deleting a contact takes a record beside an unconfirmed session too.
    let carol = Device::new(&addr, 3);
    meet(&alice, &carol);
    round(&[&carol]);
    say(&alice, &carol, "x", "to carol");
    round(&[&alice]);
    inject(
        &addr,
        &alice,
        Envelope::Handshake {
            sender: key(&carol),
            handshake: forged_handshake(&addr, &carol, &alice),
        }
        .encode(),
    );
    round(&[&alice]);
    assert!(hsin(&alice, &carol).is_some());
    alice.net.delete_contact(carol.pk.clone()).unwrap();
    assert_eq!(hsin(&alice, &carol), None);
    relay.stop();
}

/// Overwrites `d`'s stored flags for `with` (chat meta byte 17), as a store
/// written by an earlier build may hold them.
fn put_flags(d: &Device, with: &Device, flags: u8) {
    let hex: String = with.pk.iter().map(|b| format!("{b:02x}")).collect();
    let key = format!("chat-meta:v1/{hex}");
    let store = d.core.store.lock().unwrap();
    let mut meta = store.get(&key).unwrap();
    meta[17] = flags;
    store.put(&key, &meta).unwrap();
}

/// A `PROVISIONAL_HANDSHAKE_RECORD_V1` for `peer` holding `handshake`, as
/// any build since provisional records exist writes it.
fn provisional_record(peer: &Device, handshake: &[u8]) -> Vec<u8> {
    let mut out = b"ARCHSIN\x01".to_vec();
    out.extend_from_slice(&peer.pk);
    out.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    out.extend_from_slice(handshake);
    out
}

/// Migration: an earlier build raised the conflict flag on a handshake
/// alone, so a store it wrote may hold a false conflict. That flag (bit 1)
/// is not read any more: the device shows its session as awaiting the peer,
/// a resolution is refused, and the session goes on to be established. A
/// genuine conflict is raised again from its first message, which the
/// contact keeps retransmitting.
#[test]
fn a_conflict_flag_an_earlier_build_raised_on_a_handshake_alone_is_not_read() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (v, c) = own_session(&addr, true);
    put_flags(&v, &c, 1);
    assert_eq!(session(&v, &c), ChatSessionState::AwaitingPeer);
    assert!(matches!(
        v.net.resolve_session_conflict(c.pk.clone()),
        Err(CoreError::InvalidArgument { .. })
    ));
    rounds(&[&c, &v], 2);
    assert_eq!(session(&v, &c), ChatSessionState::Established);
    assert_eq!(session(&c, &v), ChatSessionState::Established);
    relay.stop();

    // A genuine one: both started, nothing delivered yet, both stores
    // carrying the old flag.
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = two(&addr, true);
    meet(&alice, &bob);
    round(&[&alice, &bob]);
    say(&alice, &bob, "a", "from alice");
    say(&bob, &alice, "b", "from bob");
    alice.net.start_session(bob.pk.clone()).unwrap();
    bob.net.start_session(alice.pk.clone()).unwrap();
    put_flags(&alice, &bob, 1);
    put_flags(&bob, &alice, 1);
    assert_eq!(session(&alice, &bob), ChatSessionState::AwaitingPeer);
    assert_eq!(session(&bob, &alice), ChatSessionState::AwaitingPeer);
    rounds(&[&alice, &bob], 2);
    assert_eq!(session(&alice, &bob), ChatSessionState::Conflict { can_resolve: true });
    alice.net.resolve_session_conflict(bob.pk.clone()).unwrap();
    rounds(&[&alice, &bob, &alice, &bob], 2);
    assert_eq!(session(&alice, &bob), ChatSessionState::Established);
    assert_eq!(session(&bob, &alice), ChatSessionState::Established);
    relay.stop();
}

/// Migration: a build before this change never deleted a provisional
/// record when its own session was confirmed, so a store it wrote may hold
/// one beside an established session. It is never read there (a message
/// that does not decrypt raises nothing), the next message from the peer
/// deletes it, and nothing else changes.
#[test]
fn a_stale_record_beside_an_established_session_is_ignored_and_then_deleted() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (v, c) = own_session(&addr, true);
    rounds(&[&c, &v], 2);
    assert_eq!(session(&v, &c), ChatSessionState::Established);
    let stale = provisional_record(&c, &forged_handshake(&addr, &c, &v));
    v.core
        .store
        .lock()
        .unwrap()
        .put(&format!("hsin:v1/{:016x}", handle(&c)), &stale)
        .unwrap();

    inject(&addr, &v, forged_message(&c));
    round(&[&v]);
    assert_eq!(session(&v, &c), ChatSessionState::Established);
    assert_eq!(hsin(&v, &c), Some(stale), "a message that does not decrypt changes nothing");

    say(&c, &v, "c1", "after the upgrade");
    rounds(&[&c, &v, &c], 1);
    assert_eq!(hsin(&v, &c), None, "the next message from the peer deleted it");
    assert_eq!(chat(&c, &v)[1], (true, S::Delivered, "after the upgrade".into()));
    assert_eq!(session(&v, &c), ChatSessionState::Established);
    relay.stop();
}

/// A record beside our own session that cannot be decoded (a damaged store)
/// must not let a message anyone can store "from" the contact stall every
/// round: the check is reported once for that message, the message is
/// deleted like any that does not decrypt, later rounds are clean, and the
/// session is established once the contact comes online.
#[test]
fn an_undecodable_record_beside_our_session_does_not_stall_rounds() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (v, c) = own_session(&addr, true);
    v.core
        .store
        .lock()
        .unwrap()
        .put(&format!("hsin:v1/{:016x}", handle(&c)), b"not a provisional record")
        .unwrap();

    inject(&addr, &v, forged_message(&c));
    let r = v.net.sync_conversations();
    assert_eq!(r.errors.len(), 1, "{:?}", r.errors);
    assert!(r.errors[0].starts_with("checking a first message beside our session"), "{:?}", r.errors);
    assert!(
        relay.stored(&key(&v)).is_empty(),
        "the message left the relay: nothing is retried every round"
    );
    round(&[&v]);
    assert_eq!(session(&v, &c), ChatSessionState::AwaitingPeer);

    rounds(&[&c, &v], 2);
    assert_eq!(session(&v, &c), ChatSessionState::Established);
    assert_eq!(chat(&v, &c), vec![(true, S::Delivered, "hello".into())]);
    relay.stop();
}

/// Process death right after a handshake was recorded beside our own
/// session, before its envelope left the relay, and right after the
/// conflict was raised, before the first message left the relay. After the
/// restart the same envelopes are processed again with the same outcome,
/// and the conflict resolves as usual.
#[cfg(unix)]
#[test]
fn process_death_at_each_new_step_repeats_safely() {
    for point in ["beside_after_record", "conflict_after_flag"] {
        let relay = start_relay();
        let addr = relay.addr().to_string();
        let (alice, bob) = two(&addr, true);
        meet(&alice, &bob);
        round(&[&alice, &bob]);
        say(&alice, &bob, "a", "from alice");
        say(&bob, &alice, "b", "from bob");
        alice.net.start_session(bob.pk.clone()).unwrap();
        bob.net.start_session(alice.pk.clone()).unwrap();
        round(&[&bob]);
        round(&[&alice]);
        if point == "beside_after_record" {
            take(&relay, &addr, &bob, is_message);
        }
        super::network_crash::run_child(&bob, &addr, "sync", Some(point), &alice.pk);
        let bob = bob.restart(&addr);
        let handshakes_left = relay
            .stored(&key(&bob))
            .iter()
            .filter(|(_, e)| matches!(Envelope::decode(e), Some(Envelope::Handshake { .. })))
            .count();
        if point == "beside_after_record" {
            assert!(hsin(&bob, &alice).is_some(), "{point}: committed before the death");
            assert_eq!(handshakes_left, 1, "{point}: not yet deleted from the relay");
            assert_eq!(session(&bob, &alice), ChatSessionState::AwaitingPeer, "{point}");
        } else {
            assert_eq!(
                session(&bob, &alice),
                ChatSessionState::Conflict { can_resolve: false },
                "{point}"
            );
            assert!(!stored_messages(&relay, &bob).is_empty(), "{point}: not yet deleted");
        }
        rounds(&[&bob, &alice], 2);
        assert_eq!(session(&alice, &bob), ChatSessionState::Conflict { can_resolve: true }, "{point}");
        assert_eq!(session(&bob, &alice), ChatSessionState::Conflict { can_resolve: false }, "{point}");
        alice.net.resolve_session_conflict(bob.pk.clone()).unwrap();
        rounds(&[&alice, &bob, &alice, &bob], 2);
        assert_eq!(session(&alice, &bob), ChatSessionState::Established, "{point}");
        assert_eq!(session(&bob, &alice), ChatSessionState::Established, "{point}");
        assert_eq!(chat(&alice, &bob)[1], (false, S::Received, "from bob".into()), "{point}");
        relay.stop();
    }
}
