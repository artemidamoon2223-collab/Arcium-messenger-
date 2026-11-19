//! Tracker R-6 over the network: each round rotates the signed prekey when
//! due before it reads the mailbox, handshakes built from the bundle before
//! a rotation are answered for one more period, later ones are refused and
//! made again, and a copy of the store stops working once the signed
//! prekey it holds is gone (`docs/NET-MESSAGING.md` section 8). The record
//! and the rule itself: `prekey_record.rs`.

use super::net_harness::*;
use super::restart::{chat, hsin, key, meet, peer_reset, round, rounds, say, session, waiting};
use super::*;
use crate::network::chat::{ChatEntryState as S, ChatSessionState};
use crate::network::wire::{Envelope, Payload};

const P: u64 = SIGNED_PREKEY_PERIOD_SECS;
const T0: u64 = 1_800_000_000;
/// `PUT_BUNDLE` in `relay::protocol`.
const PUT_BUNDLE: u8 = 1;

fn record(d: &Device) -> PrekeyRecord {
    unpack_prekeys(&read_record(&d.core)).unwrap()
}

fn id_of(sk: &StaticSecret) -> [u8; SPK_ID_LEN] {
    spk_id(PublicKey::from(sk).as_bytes())
}

fn current(d: &Device) -> [u8; SPK_ID_LEN] {
    id_of(&record(d).signed_prekey_sk)
}

/// The bundle the relay serves for `d`, parsed.
fn served(addr: &str, d: &Device) -> PrekeyBundle {
    let bundle = relay::client::Connection::connect(addr, std::time::Duration::from_secs(2))
        .unwrap()
        .get_bundle(key(d))
        .unwrap()
        .expect("a bundle on the relay");
    unpack_prekey_bundle(&bundle).unwrap()
}

fn served_spk(addr: &str, d: &Device) -> [u8; SPK_ID_LEN] {
    spk_id(served(addr, d).signed_prekey_pk.as_bytes())
}

/// Removes everything waiting in `to`'s mailbox and returns it, as a relay
/// that holds envelopes back would.
fn withhold(relay: &relay::server::RelayHandle, addr: &str, to: &Device) -> Vec<Vec<u8>> {
    let stored = relay.stored(&key(to));
    relay::client::Connection::connect(addr, std::time::Duration::from_secs(2))
        .unwrap()
        .delete(key(to), stored.iter().map(|(seq, _)| *seq).collect())
        .unwrap();
    stored.into_iter().map(|(_, e)| e).collect()
}

/// `alice` and `bob` as in `restart::talking`, with both clocks at `at`.
fn talking_at(addr: &str, at: u64) -> (Device, Device) {
    let (alice, bob) = (Device::new(addr, 1), Device::new(addr, 2));
    alice.net.set_now(Some(at));
    bob.net.set_now(Some(at));
    meet(&alice, &bob);
    round(&[&alice, &bob]);
    say(&alice, &bob, "a1", "hello bob");
    rounds(&[&alice, &bob], 3);
    say(&bob, &alice, "b1", "hello alice");
    rounds(&[&bob, &alice], 3);
    assert_eq!(session(&alice, &bob), ChatSessionState::Established);
    assert_eq!(session(&bob, &alice), ChatSessionState::Established);
    (alice, bob)
}

/// What someone holding `copy`, a copy of `victim`'s prekey record, and the
/// victim's identity secret (in the same store) can make while posing as
/// `posing_as`: a handshake naming the copied signed prekey and the
/// one-time prekey the relay serves now, and a first message under it.
/// Making it needs that one-time prekey's public key only (the initiator's
/// DH4 is DH(ephemeral, one-time prekey)); this computes the same value
/// from the responder's side, taking the secret from the live record as a
/// stand-in when it is the one served, and a random one otherwise (the
/// handshake is then refused before DH4 matters).
fn forge_restart(addr: &str, victim: &Device, copy: &PrekeyRecord, posing_as: &Device, text: &str) -> [Vec<u8>; 2] {
    let identity = victim.core.load_identity().unwrap().unwrap();
    let opk_id = served(addr, victim).one_time_prekey_id;
    let opk_sk = match record(victim).opk {
        Some((id, sk)) if Some(id) == opk_id => sk,
        _ => StaticSecret::random_from_rng(OsRng),
    };
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let posing = PublicKey::from(key(posing_as));
    let spk_pk = PublicKey::from(&copy.signed_prekey_sk);
    let derived = x3dh_respond(
        &identity.dh_key,
        PublicKey::from(&identity.dh_key),
        &copy.signed_prekey_sk,
        Some(&opk_sk),
        posing,
        PublicKey::from(&ephemeral),
    )
    .unwrap();
    let handshake = pack_initiator_handshake(
        &posing,
        &PublicKey::from(&ephemeral),
        &spk_id(spk_pk.as_bytes()),
        opk_id,
    );
    let session = Session {
        ratchet: DoubleRatchet::init_alice(&derived.root_key, spk_pk),
        ad: derived.ad.clone(),
        peer_identity_pk: key(victim),
    };
    // Encrypt the first message with that session on a scratch store. The
    // store binds a session to "our" identity and the peer's, in the order
    // of its associated data (initiator first): stored there under the
    // victim's identity, which the copy holds, as a responder session.
    let scratch = fresh_core(77);
    scratch.save_identity(victim.core.load_identity().unwrap().unwrap()).unwrap();
    let our = scratch.our_identity_pk().unwrap();
    let session = Session {
        peer_identity_pk: key(posing_as),
        ..session
    };
    {
        let (mut store, mut messenger) = scratch.lock().unwrap();
        messenger
            .create_session(
                &mut store,
                our,
                NewSession {
                    handle: 1,
                    session,
                    role: SessionRole::Responder,
                    initial_outbound: Some(handshake.clone()),
                    extra: Vec::new(),
                },
            )
            .unwrap();
    }
    let body = Payload::Text([text.as_bytes(), CANARY].concat().into()).encode().to_vec();
    let wire = match scratch.send_message(1, b"forged".to_vec(), body).unwrap() {
        SendResult::Sent { message } => message.wire,
        other => panic!("{other:?}"),
    };
    [handshake, wire]
}

fn inject_from(addr: &str, to: &Device, from: &Device, [handshake, wire]: [Vec<u8>; 2]) {
    let sender = key(from);
    inject(addr, to, Envelope::Handshake { sender, handshake }.encode());
    inject(addr, to, Envelope::Message { sender, wire }.encode());
}

/// Bob was offline for a period. His first round back rotates before it
/// reads his mailbox, and answers the handshake that waited there, built
/// from the bundle before the rotation, under the previous key. The relay
/// serves the new key from that round on.
#[test]
fn an_offline_device_rotates_first_and_answers_the_handshakes_waiting_for_it() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    bob.net.set_now(Some(T0));
    meet(&alice, &bob);
    round(&[&bob]);
    let before = served_spk(&addr, &bob);
    say(&alice, &bob, "a1", "while you were away");
    round(&[&alice]);

    bob.net.set_now(Some(T0 + P));
    round(&[&bob]);
    assert_eq!(session(&bob, &alice), ChatSessionState::Established);
    assert!(chat(&bob, &alice).contains(&(false, S::Received, "while you were away".into())));
    assert_ne!(served_spk(&addr, &bob), before, "the relay serves the new key");
    assert_eq!(served_spk(&addr, &bob), current(&bob));
    rounds(&[&alice, &bob, &alice], 2);
    assert!(chat(&alice, &bob).contains(&(true, S::Delivered, "while you were away".into())));
    relay.stop();
}

/// A rotation whose bundle the relay never accepted: the new key does not
/// age, so after any absence the previous key, which the relay kept
/// serving, still answers.
#[test]
fn a_rotation_whose_publication_failed_still_answers_the_served_bundle_after_a_long_absence() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let proxy = Proxy::start(&addr);
    let alice = Device::new(&addr, 1);
    let bob = Device::new(&proxy.addr, 2);
    bob.net.set_now(Some(T0));
    meet(&alice, &bob);
    round(&[&bob]);
    let published = served_spk(&addr, &bob);
    say(&alice, &bob, "a1", "built from the served bundle");
    round(&[&alice]);

    bob.net.set_now(Some(T0 + P));
    proxy.arm(PUT_BUNDLE, Cut::Request);
    assert!(!bob.net.sync_conversations().errors.is_empty(), "the round fails");
    assert!(proxy.fired());
    assert_ne!(current(&bob), published, "rotated");
    assert_eq!(record(&bob).prev.as_ref().map(id_of), Some(published));
    assert_eq!(record(&bob).published_at, 0, "never accepted");
    assert_eq!(served_spk(&addr, &bob), published, "the relay kept the old bundle");

    bob.net.set_now(Some(T0 + 3 * P));
    round(&[&bob]);
    assert_eq!(session(&bob, &alice), ChatSessionState::Established);
    assert!(chat(&bob, &alice).contains(&(false, S::Received, "built from the served bundle".into())));
    relay.stop();
}

/// A handshake that reaches Bob two rotations after the bundle it was built
/// from (held back by the relay) is refused as stale, reason 3 on the wire.
/// Alice gives that session up, its text reads `NotDelivered`, and she
/// starts again from the current bundle.
#[test]
fn a_handshake_past_its_grace_is_refused_and_the_initiator_starts_again() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    bob.net.set_now(Some(T0));
    meet(&alice, &bob);
    round(&[&bob]);
    say(&alice, &bob, "a1", "held back");
    round(&[&alice]);
    let held = withhold(&relay, &addr, &bob);
    assert!(!held.is_empty());

    bob.net.set_now(Some(T0 + P));
    round(&[&bob]);
    bob.net.set_now(Some(T0 + 2 * P));
    round(&[&bob]);
    for env in held {
        inject(&addr, &bob, env);
    }
    let r = bob.net.sync_conversations();
    assert_eq!(r.errors, ["handshake refused: signed prekey is stale"]);
    let refusals: Vec<Vec<u8>> = relay
        .stored(&key(&alice))
        .into_iter()
        .filter_map(|(_, e)| match Envelope::decode(&e) {
            Some(Envelope::Refusal { refusal, .. }) => Some(refusal),
            _ => None,
        })
        .collect();
    assert_eq!(refusals.len(), 1);
    assert_eq!(refusals[0][96], RefusalReason::StaleSignedPrekey as u8);
    assert_eq!(refusals[0][96], 3, "reason 3 on the wire");
    assert_ne!(session(&bob, &alice), ChatSessionState::Established);

    // Alice may send the refused handshake once more before she reads the
    // refusal; Bob refuses that copy too, and reports nothing else.
    for _ in 0..3 {
        for d in [&alice, &bob] {
            let r = d.net.sync_conversations();
            assert!(
                r.errors.iter().all(|e| e == "handshake refused: signed prekey is stale"),
                "{:?}",
                r.errors
            );
        }
    }
    assert_eq!(session(&alice, &bob), ChatSessionState::Established);
    assert_eq!(session(&bob, &alice), ChatSessionState::Established);
    assert!(chat(&alice, &bob).contains(&(true, S::NotDelivered, "held back".into())));
    say(&alice, &bob, "a2", "after the refusal");
    rounds(&[&alice, &bob, &alice], 2);
    assert!(chat(&bob, &alice).contains(&(false, S::Received, "after the refusal".into())));
    assert!(chat(&alice, &bob).contains(&(true, S::Delivered, "after the refusal".into())));
    relay.stop();
}

/// Option B across rotations: a restart built from the bundle before one
/// rotation replaces the session; one that arrives two rotations later is
/// refused, and Alice makes it again from the current bundle.
#[test]
fn a_restart_under_the_previous_replaces_the_session_and_one_past_grace_is_made_again() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking_at(&addr, T0);

    alice.net.reset_session(bob.pk.clone()).unwrap();
    round(&[&alice]);
    bob.net.set_now(Some(T0 + P));
    round(&[&bob]);
    assert!(peer_reset(&bob, &alice), "replaced under the previous key");
    rounds(&[&alice, &bob], 3);
    assert_eq!(session(&alice, &bob), ChatSessionState::Established);
    assert_eq!(session(&bob, &alice), ChatSessionState::Established);

    alice.net.reset_session(bob.pk.clone()).unwrap();
    let generation = bob.generation_with(&alice);
    round(&[&alice]);
    let held = withhold(&relay, &addr, &bob);
    bob.net.set_now(Some(T0 + 2 * P));
    round(&[&bob]);
    bob.net.set_now(Some(T0 + 3 * P));
    round(&[&bob]);
    for env in held {
        inject(&addr, &bob, env);
    }
    round(&[&bob]);
    assert_eq!(bob.generation_with(&alice), generation, "not replaced");
    assert!(waiting(&relay, &alice).1 >= 1, "the restart is refused");

    rounds(&[&alice, &bob], 4);
    assert_eq!(session(&alice, &bob), ChatSessionState::Established);
    assert_eq!(session(&bob, &alice), ChatSessionState::Established);
    say(&alice, &bob, "a3", "after both restarts");
    rounds(&[&alice, &bob, &alice], 2);
    assert!(chat(&bob, &alice).contains(&(false, S::Received, "after both restarts".into())));
    assert!(chat(&alice, &bob).contains(&(true, S::Delivered, "after both restarts".into())));
    relay.stop();
}

/// A late copy of the handshake Bob's session came from is read and not
/// refused, also after both keys it could name are gone.
#[test]
fn a_late_copy_of_the_accepted_handshake_is_not_refused_after_rotation() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    bob.net.set_now(Some(T0));
    meet(&alice, &bob);
    round(&[&bob]);
    say(&alice, &bob, "a1", "hello bob");
    round(&[&alice]);
    let copy = relay
        .stored(&key(&bob))
        .into_iter()
        .find(|(_, e)| matches!(Envelope::decode(e), Some(Envelope::Handshake { .. })))
        .map(|(_, e)| e)
        .expect("Alice's handshake");
    let first = current(&bob);
    round(&[&bob]);
    assert_eq!(session(&bob, &alice), ChatSessionState::Established);
    for at in [T0, T0 + P, T0 + 2 * P] {
        bob.net.set_now(Some(at));
        round(&[&bob]);
    }
    let held = record(&bob);
    assert_ne!(id_of(&held.signed_prekey_sk), first);
    assert_ne!(held.prev.as_ref().map(id_of), Some(first), "the key it names is gone");

    inject(&addr, &bob, copy);
    round(&[&bob]);
    assert_eq!(waiting(&relay, &bob).0, 0, "the copy was read");
    assert_eq!(waiting(&relay, &alice).1, 0, "and not refused");
    rounds(&[&alice, &bob, &alice], 2);
    assert_eq!(session(&alice, &bob), ChatSessionState::Established);
    assert!(chat(&alice, &bob).contains(&(true, S::Delivered, "hello bob".into())));
    assert!(!peer_reset(&bob, &alice));
    relay.stop();
}

/// No handshake is read in a round whose bundle publication failed: the
/// relay refuses the PUT and the connection stays open, and the round
/// still ends before the mailbox.
#[test]
fn a_round_whose_bundle_publication_fails_processes_no_handshake() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let proxy = Proxy::start(&addr);
    let alice = Device::new(&addr, 1);
    let bob = Device::new(&proxy.addr, 2);
    meet(&alice, &bob);
    round(&[&bob]);
    say(&alice, &bob, "a1", "waits for a published round");
    round(&[&alice]);

    proxy.arm(PUT_BUNDLE, Cut::Refuse);
    let r = bob.net.sync_conversations();
    assert!(proxy.fired());
    assert!(!r.errors.is_empty(), "the round fails");
    assert_eq!(r.fetched, 0, "nothing was read from the mailbox");
    assert_eq!(waiting(&relay, &bob).0, 1, "the handshake still waits");
    assert_eq!(hsin(&bob, &alice), None);
    assert!(!bob.core.has_session(super::restart::handle(&alice)).unwrap());

    round(&[&bob]);
    assert_eq!(session(&bob, &alice), ChatSessionState::Established);
    relay.stop();
}

#[derive(Clone, Copy, Debug)]
enum After {
    Nothing,
    OneRotation,
    OneTimePrekeyChange,
    TwoRotations,
}

/// THE R-6 REGRESSION. A copy of Bob's store (his identity and prekey
/// record) lets its holder make a restart "from" Alice that replaces Bob's
/// established session with her (option B), and read what follows. That
/// works while the copied signed prekey is still held (the first two
/// cases, which also show the probe works) and no longer once it is gone:
/// after the next round following a one-time-prekey change, or after two
/// time rotations. Then the session stays, and nothing is flagged.
#[test]
fn a_copied_store_cannot_replace_a_session_once_its_signed_prekey_is_gone() {
    for after in [After::Nothing, After::OneRotation, After::OneTimePrekeyChange, After::TwoRotations] {
        let relay = start_relay();
        let addr = relay.addr().to_string();
        let (alice, bob) = talking_at(&addr, T0);
        let copy = record(&bob);
        match after {
            After::Nothing => {}
            After::OneRotation => {
                bob.net.set_now(Some(T0 + P));
                round(&[&bob]);
            }
            After::OneTimePrekeyChange => {
                let carol = Device::new(&addr, 3);
                meet(&carol, &bob);
                say(&carol, &bob, "c1", "hello bob");
                round(&[&carol]);
                round(&[&bob]); // Carol's first contact consumes the one-time prekey.
                round(&[&bob]); // (E)
                assert_eq!(session(&bob, &carol), ChatSessionState::Established);
            }
            After::TwoRotations => {
                for at in [T0 + P, T0 + 2 * P] {
                    bob.net.set_now(Some(at));
                    round(&[&bob]);
                }
            }
        }
        let history = chat(&bob, &alice);
        let generation = bob.generation_with(&alice);
        inject_from(&addr, &bob, &alice, forge_restart(&addr, &bob, &copy, &alice, "forged"));
        round(&[&bob]);
        let inside = matches!(after, After::Nothing | After::OneRotation);
        assert_eq!(peer_reset(&bob, &alice), inside, "{after:?}");
        if inside {
            assert!(
                chat(&bob, &alice).contains(&(false, S::Received, "forged".into())),
                "{after:?}: the probe works"
            );
        } else {
            assert_eq!(hsin(&bob, &alice), None, "{after:?}: refused, not recorded");
            assert_eq!(session(&bob, &alice), ChatSessionState::Established, "{after:?}");
            assert_eq!(bob.generation_with(&alice), generation, "{after:?}");
            assert_eq!(chat(&bob, &alice), history, "{after:?}");
            say(&alice, &bob, "a2", "still our session");
            rounds(&[&alice, &bob], 2);
            assert!(
                chat(&bob, &alice).contains(&(false, S::Received, "still our session".into())),
                "{after:?}"
            );
        }
        relay.stop();
    }
}

/// One copy of the store makes at most one session replacement: the one
/// accepted consumes the one-time prekey and the previous signed prekey,
/// and the next round rotates before a new one-time prekey is published.
#[test]
fn a_copied_store_replaces_at_most_one_session() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking_at(&addr, T0);
    let carol = Device::new(&addr, 3);
    carol.net.set_now(Some(T0));
    meet(&carol, &bob);
    say(&carol, &bob, "c1", "hello bob");
    rounds(&[&carol, &bob], 3);
    say(&bob, &carol, "b2", "hello carol");
    rounds(&[&bob, &carol], 3);
    round(&[&bob]);
    assert_eq!(session(&bob, &carol), ChatSessionState::Established);

    let copy = record(&bob);
    let forged = [
        forge_restart(&addr, &bob, &copy, &alice, "forged as alice"),
        forge_restart(&addr, &bob, &copy, &carol, "forged as carol"),
    ];
    let [a, c] = forged;
    let (sa, sc) = (key(&alice), key(&carol));
    inject(&addr, &bob, Envelope::Handshake { sender: sa, handshake: a[0].clone() }.encode());
    inject(&addr, &bob, Envelope::Handshake { sender: sc, handshake: c[0].clone() }.encode());
    inject(&addr, &bob, Envelope::Message { sender: sa, wire: a[1].clone() }.encode());
    inject(&addr, &bob, Envelope::Message { sender: sc, wire: c[1].clone() }.encode());
    round(&[&bob]);
    let replaced = [peer_reset(&bob, &alice), peer_reset(&bob, &carol)];
    assert_eq!(replaced.iter().filter(|r| **r).count(), 1, "{replaced:?}");

    round(&[&bob]); // (E)
    let other = if replaced[0] { &carol } else { &alice };
    inject_from(&addr, &bob, other, forge_restart(&addr, &bob, &copy, other, "again"));
    round(&[&bob]);
    assert!(!peer_reset(&bob, other), "the copy is spent");
    relay.stop();
}
