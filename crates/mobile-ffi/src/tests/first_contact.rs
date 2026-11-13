//! R-1: first contact to a recipient whose app was closed.
//!
//! The recipient's bundle carries one one-time prekey, so when two contacts
//! write to it for the first time while it is away, both handshakes name the
//! same prekey and only the first can be answered. Before refusals the second
//! initiator never learned that: its text stayed "sent" for good, and with the
//! recipient's identity key the greater, a session conflict between the two
//! could not be resolved by either side. Now the recipient sends a refusal
//! (`HANDSHAKE_REFUSAL_V1`, authenticated by a MAC only the two parties can
//! make or check), and the initiator gives up its dead session and starts a
//! new one (docs/NET-MESSAGING.md, section 6).

use std::time::Duration;

use super::net_harness::*;
use crate::network::chat::{ChatEntryState as S, ChatSessionState};
use crate::network::wire::Envelope;

fn canary() -> String {
    String::from_utf8(CANARY.to_vec()).unwrap()
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

/// One `sync_conversations` per device. A refused handshake is reported as
/// an error by the device that refuses it, so errors are not asserted here.
fn rounds(devices: &[&Device], n: usize) {
    for _ in 0..n {
        for d in devices {
            d.net.sync_conversations();
        }
    }
}

fn session(d: &Device, with: &Device) -> ChatSessionState {
    d.net.conversation(with.pk.clone()).unwrap().session
}

fn state_of(d: &Device, with: &Device, text: &str) -> Option<S> {
    d.net
        .chat_entries(with.pk.clone())
        .unwrap()
        .into_iter()
        .find(|e| e.outgoing && e.text.0.replace(&canary(), "") == text)
        .map(|e| e.state)
}

fn received(d: &Device, from: &Device) -> Vec<String> {
    d.net
        .chat_entries(from.pk.clone())
        .unwrap()
        .into_iter()
        .filter(|e| !e.outgoing)
        .map(|e| e.text.0.replace(&canary(), ""))
        .collect()
}

fn key(d: &Device) -> [u8; 32] {
    d.pk.as_slice().try_into().unwrap()
}

fn handle(with: &Device) -> u64 {
    core_crypto::session_handle::local_session_handle(&key(with))
}

/// The handshake of `d`'s own session with `with`, if it has one.
fn handshake_of(d: &Device, with: &Device) -> Option<Vec<u8>> {
    d.core.initiator_handshake(handle(with)).unwrap()
}

/// Refusal envelopes stored for `to`, from anyone.
fn refusals_for(relay: &relay::server::RelayHandle, to: &Device) -> usize {
    relay
        .stored(&key(to))
        .into_iter()
        .filter(|(_, e)| matches!(Envelope::decode(e), Some(Envelope::Refusal { .. })))
        .count()
}

/// Bob (2), with `n` contacts that each write to him for the first time
/// while his app is closed, then Bob's first round back: he accepts one
/// first message and refuses the others' (their handshakes all named the
/// one one-time prekey his bundle carried). `greater` picks whether the
/// writers' identity keys are greater than Bob's.
fn offline_recipient(addr: &str, n: usize, writers_greater: bool) -> (Device, Vec<Device>) {
    // Bob's key must be below (or above) every writer's. All n + 1 devices
    // are made first, and Bob is the one with the least (or greatest) key:
    // one always exists, whatever keys were drawn. (Drawing Bob against
    // writers already made can fail: with a writer's key near an end of the
    // range almost no key lies beyond it. With 150 draws that fails in
    // n / (n + 151) of the calls: 1.3% for two writers, 3.2% for five.)
    let mut writers: Vec<Device> = (0..=n as u8).map(|i| Device::new(addr, 10 + i)).collect();
    let at = (0..writers.len())
        .reduce(|a, b| if (writers[b].pk < writers[a].pk) == writers_greater { b } else { a })
        .expect("n + 1 devices");
    let bob = writers.remove(at);
    for w in &writers {
        meet(w, &bob);
    }
    // Bob opens the app once, so his bundle is on the relay, then closes it.
    assert!(bob.net.sync_conversations().errors.is_empty());
    for (i, w) in writers.iter().enumerate() {
        say(w, &bob, &format!("first-{i}"), &format!("first {i}"));
        assert!(w.net.sync_conversations().errors.is_empty());
    }
    bob.net.sync_conversations();
    (bob, writers)
}

/// Rounds until every writer has an established session with Bob, at most
/// `max` rounds. Returns how many it took.
fn until_established(bob: &Device, writers: &[Device], max: usize) -> usize {
    for i in 1..=max {
        let mut all: Vec<&Device> = vec![bob];
        all.extend(writers.iter());
        rounds(&all, 1);
        if writers.iter().all(|w| {
            session(w, bob) == ChatSessionState::Established
                && session(bob, w) == ChatSessionState::Established
        }) {
            return i;
        }
    }
    panic!("not every first contact was established within {max} rounds");
}

/// The regression: two contacts write to an offline recipient for the first
/// time, in both key orders. Both sessions become established without any
/// user action. The refused contact's first text, which went into the
/// session that could never be accepted, ends NotDelivered and never
/// reaches Bob; its next text is delivered.
#[test]
fn two_first_contacts_to_an_offline_recipient_both_establish_in_either_key_order() {
    for writers_greater in [true, false] {
        let relay = start_relay();
        let addr = relay.addr().to_string();
        let (bob, writers) = offline_recipient(&addr, 2, writers_greater);
        until_established(&bob, &writers, 12);

        let mut first_delivered = 0;
        for (i, w) in writers.iter().enumerate() {
            match state_of(w, &bob, &format!("first {i}")) {
                Some(S::Delivered) => first_delivered += 1,
                Some(S::NotDelivered) => {
                    assert!(!received(&bob, w).contains(&format!("first {i}")))
                }
                other => panic!("first text of writer {i}: {other:?}"),
            }
        }
        assert_eq!(first_delivered, 1, "one first message was accepted");

        for (i, w) in writers.iter().enumerate() {
            say(w, &bob, &format!("again-{i}"), &format!("again {i}"));
        }
        let mut all: Vec<&Device> = vec![&bob];
        all.extend(writers.iter());
        rounds(&all, 4);
        for (i, w) in writers.iter().enumerate() {
            assert_eq!(state_of(w, &bob, &format!("again {i}")), Some(S::Delivered), "writer {i}");
            let got = received(&bob, w);
            assert_eq!(
                got.iter().filter(|t| **t == format!("again {i}")).count(),
                1,
                "writer {i}: each text once: {got:?}"
            );
        }
        relay.stop();
    }
}

/// Bob, back online, writes to the refused contact before the refusal
/// reaches it, so both hold an unconfirmed session of their own: a
/// conflict. Whoever may resolve it does, and in both key orders the two
/// end up with one established session. Before refusals, with Bob's key
/// the greater, this was a dead end.
#[test]
fn a_conflict_after_a_refused_first_contact_resolves_in_either_key_order() {
    for carol_greater in [true, false] {
        let relay = start_relay();
        let addr = relay.addr().to_string();
        let (bob, writers) = offline_recipient(&addr, 2, carol_greater);
        // The writer whose first message Bob refused.
        let carol = writers
            .iter()
            .find(|w| session(&bob, w) != ChatSessionState::Established)
            .expect("one first message was refused");
        let alice = writers.iter().find(|w| !std::ptr::eq(*w, carol)).unwrap();

        say(&bob, carol, "b0", "hi, it's bob");
        bob.net.sync_conversations(); // Bob's own session with Carol.
        rounds(&[carol, &bob], 2);
        let resolver = [(&bob, carol), (carol, &bob)]
            .into_iter()
            .find(|(d, w)| matches!(session(d, w), ChatSessionState::Conflict { can_resolve: true }));
        if let Some((d, w)) = resolver {
            d.net.resolve_session_conflict(w.pk.clone()).unwrap();
        }
        rounds(&[&bob, carol, alice], 10);
        assert_eq!(session(&bob, carol), ChatSessionState::Established, "carol_greater={carol_greater}");
        assert_eq!(session(carol, &bob), ChatSessionState::Established, "carol_greater={carol_greater}");

        say(carol, &bob, "c1", "after the conflict");
        say(&bob, carol, "b1", "after the conflict too");
        rounds(&[&bob, carol], 4);
        assert_eq!(state_of(carol, &bob, "after the conflict"), Some(S::Delivered));
        assert_eq!(state_of(&bob, carol, "after the conflict too"), Some(S::Delivered));
        relay.stop();
    }
}

/// N first contacts (2, 3, 5) to an offline recipient, with no wait between
/// refusals: each round of refusals lets one more through, and every
/// session ends established with no user action.
#[test]
fn n_first_contacts_to_an_offline_recipient_all_establish() {
    for n in [2, 3, 5] {
        let relay = start_relay();
        let addr = relay.addr().to_string();
        let (bob, writers) = offline_recipient(&addr, n, n % 2 == 0);
        bob.net.set_refusal_interval(Duration::ZERO);
        let took = until_established(&bob, &writers, 8 * n);
        println!("{n} first contacts established in {took} rounds");
        for (i, w) in writers.iter().enumerate() {
            say(w, &bob, &format!("again-{i}"), &format!("again {i}"));
        }
        let mut all: Vec<&Device> = vec![&bob];
        all.extend(writers.iter());
        rounds(&all, 4);
        for (i, w) in writers.iter().enumerate() {
            assert_eq!(state_of(w, &bob, &format!("again {i}")), Some(S::Delivered), "n={n} writer {i}");
        }
        relay.stop();
    }
}

/// D3: at most one refusal per contact per REFUSAL_INTERVAL. With three
/// contenders, the one refused a second time within the interval is not
/// told again, and waits; once the interval passes (here: shortened), it is
/// told and gets through.
#[test]
fn a_second_refusal_to_one_contact_waits_for_the_interval() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (bob, writers) = offline_recipient(&addr, 3, true);
    let mut all: Vec<&Device> = vec![&bob];
    all.extend(writers.iter());
    rounds(&all, 12);
    let waiting: Vec<&Device> = writers
        .iter()
        .filter(|w| session(&bob, w) != ChatSessionState::Established)
        .collect();
    assert_eq!(waiting.len(), 1, "two got through, the third was refused twice");
    let carol = waiting[0];
    assert!(handshake_of(carol, &bob).is_some(), "it still waits on its second session");

    bob.net.set_refusal_interval(Duration::ZERO);
    until_established(&bob, &writers, 12);
    relay.stop();
}

/// D3: one refusal per refused handshake, however often it is retransmitted.
#[test]
fn a_retransmitted_handshake_is_refused_once() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (bob, writers) = offline_recipient(&addr, 2, true);
    bob.net.set_refusal_interval(Duration::ZERO);
    let carol = writers
        .iter()
        .find(|w| session(&bob, w) != ChatSessionState::Established)
        .unwrap();
    let hs = handshake_of(carol, &bob).unwrap();
    let env = Envelope::Handshake {
        sender: key(carol),
        handshake: hs,
    }
    .encode();
    for _ in 0..4 {
        inject(&addr, &bob, env.clone());
        bob.sync();
    }
    assert_eq!(refusals_for(&relay, carol), 1);
    relay.stop();
}

/// The refusal fields of `refuser` for `initiator`'s `handshake`.
fn fields(refuser: &Device, initiator: &Device, handshake: &[u8], reason: u8) -> Vec<u8> {
    [&key(refuser)[..], &key(initiator)[..], &crate::handshake_hash(handshake)[..], &[reason]].concat()
}

/// `fields` with the tag `holder` computes, with `other` as the other party,
/// for a refusal by `refuser_pk` of a handshake from `initiator_pk`.
fn tagged(holder: &Device, other: &Device, refuser_pk: [u8; 32], initiator_pk: [u8; 32], fields: &[u8]) -> Vec<u8> {
    let identity = holder.core.load_identity().unwrap().unwrap();
    let tag = core_crypto::refusal_mac::refusal_tag(&identity.dh_key, &key(other), &refuser_pk, &initiator_pk, fields)
        .expect("not a low-order key");
    [fields, &tag[..]].concat()
}

fn refusal_env(sender: &Device, refusal: Vec<u8>) -> Vec<u8> {
    Envelope::Refusal {
        sender: key(sender),
        refusal,
    }
    .encode()
}

/// Every refusal that does not prove Bob refused Carol's current handshake
/// is dropped and changes nothing; the genuine one restarts the session;
/// replaying it afterwards, or refusing a confirmed session, changes nothing.
#[test]
fn only_a_genuine_refusal_of_the_current_handshake_restarts_the_session() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (bob, writers) = offline_recipient(&addr, 2, true);
    let carol = writers
        .iter()
        .find(|w| session(&bob, w) != ChatSessionState::Established)
        .unwrap();
    let alice = writers.iter().find(|w| !std::ptr::eq(*w, carol)).unwrap();
    // As at the start of Bob's next round: his bundle names the prekey that
    // replaced the consumed one, so a restarted session can be answered.
    bob.net.publish_prekeys().unwrap();
    // Carol also knows Alice, and Dave is a stranger to her.
    meet(carol, alice);
    let dave = Device::new(&addr, 99);
    meet(&dave, &bob);
    let hs = handshake_of(carol, &bob).unwrap();
    let valid = bob
        .core
        .make_handshake_refusal(key(carol), &hs, crate::RefusalReason::OneTimePrekeyUnavailable)
        .unwrap()
        .unwrap();

    let mut forged = valid.clone();
    forged[crate::HANDSHAKE_REFUSAL_V1_LEN - 1] ^= 1;
    let mut other_fields = valid.clone();
    other_fields[96] = 2;
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("forged tag", refusal_env(&bob, forged)),
        ("a field changed under Bob's tag", refusal_env(&bob, other_fields)),
        (
            "from a stranger",
            refusal_env(
                &dave,
                dave.core
                    .make_handshake_refusal(key(carol), &hs, crate::RefusalReason::OneTimePrekeyUnavailable)
                    .unwrap()
                    .unwrap(),
            ),
        ),
        (
            "made by another contact, sent as Bob",
            refusal_env(
                &bob,
                alice
                    .core
                    .make_handshake_refusal(key(carol), &hs, crate::RefusalReason::OneTimePrekeyUnavailable)
                    .unwrap()
                    .unwrap(),
            ),
        ),
        (
            "another contact's own refusal",
            refusal_env(
                alice,
                alice
                    .core
                    .make_handshake_refusal(key(carol), &hs, crate::RefusalReason::OneTimePrekeyUnavailable)
                    .unwrap()
                    .unwrap(),
            ),
        ),
        (
            "another handshake",
            refusal_env(
                &bob,
                bob.core
                    .make_handshake_refusal(key(carol), &[0u8; 84], crate::RefusalReason::OneTimePrekeyUnavailable)
                    .unwrap()
                    .unwrap(),
            ),
        ),
        (
            "another initiator",
            refusal_env(
                &bob,
                bob.core
                    .make_handshake_refusal(key(alice), &hs, crate::RefusalReason::OneTimePrekeyUnavailable)
                    .unwrap()
                    .unwrap(),
            ),
        ),
        (
            "unknown reason, with a valid tag",
            refusal_env(&bob, tagged(&bob, carol, key(&bob), key(carol), &fields(&bob, carol, &hs, 9))),
        ),
        (
            "tag keyed for the roles swapped",
            refusal_env(&bob, tagged(&bob, carol, key(carol), key(&bob), &fields(&bob, carol, &hs, 1))),
        ),
        (
            "tag made by a stranger for Bob's fields",
            refusal_env(&bob, tagged(&dave, carol, key(&bob), key(carol), &fields(&bob, carol, &hs, 1))),
        ),
        (
            "wrong length",
            [b"ARN1".as_slice(), &[3], &key(&bob), &valid[..crate::HANDSHAKE_REFUSAL_V1_LEN - 1]].concat(),
        ),
    ];
    for (what, env) in cases {
        inject(&addr, carol, env);
        let r = carol.sync();
        assert!(r.dropped >= 1, "{what}: dropped");
        assert_eq!(handshake_of(carol, &bob).as_deref(), Some(hs.as_slice()), "{what}: session kept");
        assert!(relay.stored(&key(carol)).iter().all(|(_, e)| !matches!(Envelope::decode(e), Some(Envelope::Refusal { .. }))), "{what}: deleted");
    }

    // The genuine refusal: the dead session goes, a new one starts.
    inject(&addr, carol, refusal_env(&bob, valid.clone()));
    carol.sync();
    let restarted = handshake_of(carol, &bob).expect("a new session");
    assert_ne!(restarted, hs);
    assert_eq!(state_of(carol, &bob, "first 1").or(state_of(carol, &bob, "first 0")), Some(S::NotDelivered));

    // Replayed after the restart: names the old handshake.
    inject(&addr, carol, refusal_env(&bob, valid));
    assert!(carol.sync().dropped >= 1);
    assert_eq!(handshake_of(carol, &bob), Some(restarted.clone()));

    // A refusal of a session Bob confirmed changes nothing.
    rounds(&[&bob, carol], 4);
    assert_eq!(session(carol, &bob), ChatSessionState::Established);
    let late = bob
        .core
        .make_handshake_refusal(key(carol), &restarted, crate::RefusalReason::OneTimePrekeyUnavailable)
        .unwrap()
        .unwrap();
    inject(&addr, carol, refusal_env(&bob, late));
    assert!(carol.sync().dropped >= 1);
    assert_eq!(session(carol, &bob), ChatSessionState::Established);
    relay.stop();
}

/// F-144-1 of the 2026-11-12 review. Anyone who knows Bob's and Carol's
/// public keys can store a forged handshake "from Carol" in Bob's mailbox,
/// and read Bob's refusal from Carol's. That refusal must not prove to the
/// attacker, or to anyone the attacker shows it to, that Bob has Carol
/// pinned. With a signature it did: it verified under Bob's public key. Now:
/// Carol alone makes the very same bytes, and a third party cannot check
/// them at all.
#[test]
fn an_elicited_refusal_proves_nothing_to_a_third_party() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (bob, carol, mallory) = (Device::new(&addr, 2), Device::new(&addr, 3), Device::new(&addr, 4));
    bob.knows(&carol);
    bob.net.publish_prekeys().unwrap();
    // What the attacker has: Bob's public bundle and Carol's public key.
    let mut conn = relay::client::Connection::connect(&addr, Duration::from_secs(2)).unwrap();
    let bundle = conn.get_bundle(key(&bob)).unwrap().unwrap();
    let mut forged = vec![0u8; crate::INITIATOR_HANDSHAKE_V1_LEN];
    forged[0..3].copy_from_slice(&[1, 1, 1]); // version, suite, a one-time prekey used
    forged[4..36].copy_from_slice(&carol.pk);
    forged[36..68].copy_from_slice(&[9u8; 32]);
    forged[68..76].copy_from_slice(&core_crypto::spk_id::spk_id(&bundle[68..100].try_into().unwrap()));
    forged[76..84].copy_from_slice(&0xDEAD_BEEF_u64.to_be_bytes());
    inject(&addr, &bob, Envelope::Handshake { sender: key(&carol), handshake: forged.clone() }.encode());
    bob.sync();
    let refusals: Vec<Vec<u8>> = relay
        .stored(&key(&carol))
        .into_iter()
        .filter_map(|(_, e)| match Envelope::decode(&e) {
            Some(Envelope::Refusal { refusal, .. }) => Some(refusal),
            _ => None,
        })
        .collect();
    assert_eq!(refusals.len(), 1, "Bob refused the forged handshake");
    let elicited = &refusals[0];

    // Carol, with nobody's help, makes a byte-identical refusal.
    let alone = tagged(&carol, &bob, key(&bob), key(&carol), &fields(&bob, &carol, &forged, 1));
    assert_eq!(&alone, elicited, "the initiator can make the same bytes alone");
    // A third party holding its own identity cannot check the tag.
    let mallory_sk = mallory.core.load_identity().unwrap().unwrap().dh_key.clone();
    let (fields_part, tag) = elicited.split_at(elicited.len() - 32);
    for other in [key(&bob), key(&carol)] {
        assert!(!core_crypto::refusal_mac::verify_refusal_tag(
            &mallory_sk,
            &other,
            &key(&bob),
            &key(&carol),
            fields_part,
            tag,
        ));
    }
    // The object carries no signature and no signing key of Bob's.
    let bob_signing_pk = &bob.core.contact_card().unwrap()[33..65];
    assert!(!elicited.windows(32).any(|w| w == bob_signing_pk));
    relay.stop();
}

/// F-144-2: a refusal the relay refuses to store (the initiator's mailbox
/// is full) does not end Bob's round, stays queued and is sent once there is
/// room; a refusal whose SEND breaks the connection is not lost either.
#[test]
fn a_refusal_the_relay_cannot_store_now_is_sent_later() {
    let relay = relay::server::serve(
        std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
        relay::server::RelayConfig {
            max_mailbox: 8,
            canary: Some(CANARY.to_vec()),
            ..relay::server::RelayConfig::default()
        },
    )
    .unwrap();
    let addr = relay.addr().to_string();
    let (bob, writers) = offline_recipient(&addr, 2, true);
    let carol = writers
        .iter()
        .find(|w| session(&bob, w) != ChatSessionState::Established)
        .unwrap();
    let alice = writers.iter().find(|w| !std::ptr::eq(*w, carol)).unwrap();
    let dead = handshake_of(carol, &bob).unwrap();
    // Bob refused Carol's first message, which sends no refusal; her next
    // retransmission of the handshake is what Bob refuses and answers.
    assert_eq!(refusals_for(&relay, carol), 0);
    carol.net.sync_conversations();

    // Carol's mailbox is full while Bob's round wants to refuse her.
    let free = 8 - relay.stored(&key(carol)).len();
    for i in 0..free {
        inject(&addr, carol, vec![i as u8; 10]);
    }
    bob.net.set_refusal_interval(Duration::ZERO);
    let r = bob.net.sync();
    assert!(r.errors.iter().all(|e| !e.starts_with("network:")), "{:?}", r.errors);
    assert!(r.errors.iter().any(|e| e.starts_with("relay refused")), "{:?}", r.errors);
    assert_eq!(refusals_for(&relay, carol), 0);
    // The round went on for Alice: her first text is in Bob's history.
    assert!(received(&bob, alice).iter().any(|t| t.starts_with("first")));

    // Carol's mailbox is emptied without Carol sending anything (so no new
    // handshake reaches Bob, whose refused one was deleted): the refusal
    // Bob's next round sends can only be the one kept in his queue.
    let mut conn = relay::client::Connection::connect(&addr, Duration::from_secs(2)).unwrap();
    let stored: Vec<u64> = relay.stored(&key(carol)).into_iter().map(|(seq, _)| seq).collect();
    conn.delete(key(carol), stored).unwrap();
    let r = bob.net.sync();
    assert!(r.errors.iter().all(|e| !e.starts_with("relay refused")), "{:?}", r.errors);
    assert_eq!(refusals_for(&relay, carol), 1, "the kept refusal went out");
    carol.net.sync_conversations();
    assert_ne!(handshake_of(carol, &bob), Some(dead), "Carol gave up the dead session");
    until_established(&bob, &writers, 12);
    relay.stop();
}

/// F-144-2, the other half: a connection that breaks on the SEND of a
/// refusal ends Bob's round, as any network error does, but the refusal stays
/// queued and goes out in the next round. (Before, it was taken off the queue
/// first and lost.)
#[test]
fn a_refusal_lost_with_the_connection_is_sent_in_the_next_round() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (bob, writers) = offline_recipient(&addr, 2, true);
    let carol = writers
        .iter()
        .find(|w| session(&bob, w) != ChatSessionState::Established)
        .unwrap();
    let dead = handshake_of(carol, &bob).unwrap();
    assert_eq!(refusals_for(&relay, carol), 0);
    carol.net.sync_conversations();

    // Bob's next rounds go through a proxy that breaks the next SEND before
    // it reaches the relay: the refusal is the only thing Bob has to send.
    let proxy = Proxy::start(&addr);
    let net = crate::network::NetworkMessenger::new(bob.core.clone(), proxy.addr.clone(), 0, 2000);
    proxy.arm(3, Cut::Request);
    let r = net.sync();
    assert!(proxy.fired(), "the refusal's SEND was cut");
    assert!(r.errors.iter().any(|e| e.starts_with("network:")), "{:?}", r.errors);
    assert_eq!(refusals_for(&relay, carol), 0);

    let r = net.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(refusals_for(&relay, carol), 1, "the queued refusal went out");
    carol.net.sync_conversations();
    assert_ne!(handshake_of(carol, &bob), Some(dead), "Carol gave up the dead session");
    relay.stop();
}

/// Carol dies at each step of the restart (after marking, after abandoning,
/// after removing the dead session, after starting the new one) and is
/// started again. Nothing is lost, nothing reaches Bob twice, the dead
/// session's text stays NotDelivered, and a later text is delivered.
#[cfg(unix)]
#[test]
fn a_restart_killed_at_each_step_completes_without_losing_or_repeating_a_text() {
    for point in [
        "refusal_after_mark",
        "refusal_after_abandon",
        "refusal_after_remove",
        "refusal_after_restart",
    ] {
        let relay = start_relay();
        let addr = relay.addr().to_string();
        let (bob, writers) = offline_recipient(&addr, 2, true);
        let idx = writers
            .iter()
            .position(|w| session(&bob, w) != ChatSessionState::Established)
            .unwrap();
        let carol = &writers[idx];
        let dead_text = format!("first {idx}");
        // Carol retransmits her handshake; Bob refuses it and says so.
        carol.sync();
        bob.sync();
        assert_eq!(refusals_for(&relay, carol), 1, "{point}");

        super::network_crash::run_child(carol, &addr, "sync", Some(point), &bob.pk);
        let carol = carol.restart(&addr);
        // The first round after the restart finds the refusal still on the
        // relay (the crash came before its deletion) and completes the
        // restart, or drops it once the dead session is gone.
        carol.sync();
        say(&carol, &bob, "later", "later");
        for _ in 0..12 {
            rounds(&[&bob, &carol], 1);
            if session(&carol, &bob) == ChatSessionState::Established
                && state_of(&carol, &bob, "later") == Some(S::Delivered)
            {
                break;
            }
        }
        assert_eq!(session(&carol, &bob), ChatSessionState::Established, "{point}");
        assert_eq!(state_of(&carol, &bob, "later"), Some(S::Delivered), "{point}");
        assert_eq!(state_of(&carol, &bob, &dead_text), Some(S::NotDelivered), "{point}");
        let got = received(&bob, &carol);
        assert_eq!(got, vec!["later".to_string()], "{point}: once, and never the dead text");
        relay.stop();
    }
}
