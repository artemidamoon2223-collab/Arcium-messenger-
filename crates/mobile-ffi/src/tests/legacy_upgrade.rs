//! Upgrading databases written by the build of commit 590c936e, which stored
//! a responder session as soon as a handshake arrived.
//!
//! The databases are `fixtures/legacy-590c936e/*.db`, written by that build's
//! own code (`generator.rs`, run by `generate.sh` in a checkout of the
//! commit) with legitimate peers only. Each test opens copies of them with
//! this build, exactly as an upgraded installation would.
//!
//! - T1 (`t1-*`): Bob's old build stored a responder session for Alice's
//!   genuine handshake, and no message from her ever reached it. A text Bob
//!   queued meanwhile could not be encrypted, and from then on the old
//!   build's conversation refresh failed on it.
//! - T2 (`t2-*`): Bob's old build accepted Alice's session and authenticated
//!   her messages: one acknowledged (seen record), one text pending.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use super::net_harness::*;
use super::*;
use crate::network::chat::ChatEntryState;
use crate::network::wire::Envelope;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/legacy-590c936e");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).unwrap()
}

/// Copies of Alice's (device 1) and Bob's (device 2) databases from `case`,
/// opened by this build.
fn open_fixture(case: &str, relay: &str) -> (Device, Device) {
    let dir = tempdir().unwrap().keep();
    let open = |who: &str, byte: u8| {
        let path = dir.join(format!("{case}-{who}.db"));
        std::fs::write(&path, fixture(&format!("{case}-{who}.db"))).unwrap();
        Device::reopen(path.to_str().unwrap(), byte, relay)
    };
    (open("alice", 1), open("bob", 2))
}

fn handle(d: &Device) -> u64 {
    local_session_handle(d.pk.clone()).unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Every messaging, history and prekey record `core` holds about `peer`.
fn records(core: &ArciumCore, peer: &Device) -> BTreeMap<String, Vec<u8>> {
    let store = core.store.lock().unwrap();
    let mut out = BTreeMap::new();
    let entries = format!("chat-e.v1.{}:", hex(&peer.pk));
    for ns in [
        "session:",
        "handle:",
        "hsin:",
        "hsout:",
        "outbox:",
        "inbox:",
        "seen:",
        "sendid:",
        "chat-meta:",
        "chat-o:",
        "chat-i:",
        entries.as_str(),
        "prekeys/v2",
    ] {
        for key in store.list_keys_with_prefix(ns).unwrap() {
            let value = store.get(&key).unwrap();
            out.insert(key, value);
        }
    }
    out
}

/// Only the records in the namespaces a retirement must never touch.
fn history(records: &BTreeMap<String, Vec<u8>>) -> BTreeMap<String, Vec<u8>> {
    records
        .iter()
        .filter(|(k, _)| {
            ["seen:", "sendid:", "chat-"]
                .iter()
                .any(|ns| k.starts_with(ns))
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// The one-time prekey id a `PREKEY_BUNDLE_V1` publishes.
fn bundle_opk(bundle: &[u8]) -> Option<u64> {
    (bundle[2] & 1 == 1).then(|| u64::from_be_bytes(bundle[164..172].try_into().unwrap()))
}

/// The one-time prekey id an `INITIATOR_HANDSHAKE_V1` names.
fn handshake_opk(hs: &[u8]) -> Option<u64> {
    (hs[2] & 1 == 1).then(|| u64::from_be_bytes(hs[76..84].try_into().unwrap()))
}

fn sent(r: SendResult) -> Vec<u8> {
    match r {
        SendResult::Sent { message } => message.wire,
        other => panic!("expected a new message, got {other:?}"),
    }
}

fn plaintext(r: ReceiveResult) -> Vec<u8> {
    match r {
        ReceiveResult::Accepted { message } => message.plaintext.0,
        other => panic!("expected an accepted message, got {other:?}"),
    }
}

/// Alice gives up on her unanswered start with Bob and starts again, as the
/// application lets a user do. Her new handshake uses Bob's current bundle.
fn alice_starts_again(alice: &Device, bob: &Device) {
    let hb = handle(bob);
    for m in alice.core.pending_outgoing(hb).unwrap() {
        alice.core.abandon_outgoing(hb, m.message_id).unwrap();
    }
    alice.core.remove_session(hb).unwrap();
}

#[test]
fn the_fixtures_are_the_ones_the_old_build_wrote() {
    for line in String::from_utf8(fixture("SHA256SUMS")).unwrap().lines() {
        let (sum, name) = line.split_once("  ").unwrap();
        assert_eq!(hex(&Sha256::digest(fixture(name))), sum, "{name}");
    }
}

/// T1 at the FFI: the new first contact retires the old session in one
/// step that touches nothing else, and only the first authenticated message
/// makes a session again.
#[test]
fn t1_an_old_unconfirmed_responder_session_gives_way_to_a_new_first_contact() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = open_fixture("t1", &addr);
    let (ha, hb) = (handle(&alice), handle(&bob));
    let old_hs = fixture("t1-alice-handshake.bin");

    // What the old build left.
    assert!(bob.core.has_session(ha).unwrap());
    assert!(bob.core.is_legacy_unconfirmed(ha).unwrap());
    assert_eq!(bob.generation_with(&alice), 0);
    assert_eq!(alice.core.initiator_handshake(hb).unwrap(), Some(old_hs.clone()));
    let old_opk = handshake_opk(&old_hs).expect("the old handshake used a one-time prekey");
    let before = records(&bob.core, &alice);

    // The old session cannot encrypt, and trying writes nothing.
    assert!(matches!(
        bob.core.send_message(ha, b"x".to_vec(), b"y".to_vec()),
        Err(CoreError::Crypto { .. })
    ));
    // Its own handshake again cannot retire it: the old build consumed the
    // one-time prekey it names, and it stays consumed.
    assert!(matches!(
        bob.core.establish_session_responder(ha, old_hs.clone()),
        Err(CoreError::OneTimePrekeyUnavailable { opk_id }) if opk_id == old_opk
    ));
    assert_eq!(records(&bob.core, &alice), before);

    // A new, genuine first contact from Alice.
    alice_starts_again(&alice, &bob);
    let bundle = bob.core.export_prekey_bundle().unwrap();
    assert_ne!(bundle_opk(&bundle), Some(old_opk));
    let hs2 = alice.core.establish_session_initiator(hb, bundle.clone()).unwrap();
    let m1 = sent(
        alice
            .core
            .send_message(hb, b"first".to_vec(), b"hello again".to_vec())
            .unwrap(),
    );

    // Retirement: the old session and handle go, the new handshake is
    // recorded, nothing else changes — prekeys included.
    bob.core.establish_session_responder(ha, hs2.clone()).unwrap();
    assert!(!bob.core.has_session(ha).unwrap(), "a handshake has no authority");
    let mut want = before.clone();
    let session_key = format!("session:v1/{}", hex(&alice.pk));
    want.remove(&session_key).unwrap();
    want.remove(&format!("handle:v1/{ha:016x}")).unwrap();
    let mut after = records(&bob.core, &alice);
    let recorded = after.remove(&format!("hsin:v1/{ha:016x}")).expect("provisional record");
    assert_eq!(after, want);
    assert!(recorded.ends_with(&hs2));

    // The first authenticated message makes the session, and consumes the
    // current one-time prekey.
    assert_eq!(plaintext(bob.core.receive_message(ha, m1.clone()).unwrap()), b"hello again");
    assert!(bob.core.has_session(ha).unwrap());
    assert!(!bob.core.is_legacy_unconfirmed(ha).unwrap());
    assert_eq!(bob.generation_with(&alice), 1);
    assert!(matches!(
        bob.core.receive_message(ha, m1).unwrap(),
        ReceiveResult::Duplicate { .. }
    ));
    let now = bundle_opk(&bob.core.export_prekey_bundle().unwrap());
    assert_ne!(now, bundle_opk(&bundle));
    assert_ne!(now, Some(old_opk));

    // Both directions.
    let reply = sent(bob.core.send_message(ha, b"r".to_vec(), b"hi alice".to_vec()).unwrap());
    assert_eq!(plaintext(alice.core.receive_message(hb, reply).unwrap()), b"hi alice");
    let m2 = sent(alice.core.send_message(hb, b"2".to_vec(), b"and again".to_vec()).unwrap());
    assert_eq!(plaintext(bob.core.receive_message(ha, m2).unwrap()), b"and again");

    // History untouched throughout.
    let history_before = history(&before);
    let history_after = history(&records(&bob.core, &alice));
    for (k, v) in &history_before {
        assert_eq!(history_after.get(k), Some(v), "{k}");
    }
    assert!(history_before.keys().any(|k| k.starts_with("sendid:")));
}

/// Alice's identity on a second, empty database: device 3, knowing Bob.
/// Its first contact with Bob is an ordinary, genuine one.
fn alice_elsewhere(alice: &Device, bob: &Device, relay: &str) -> Device {
    let path = tempdir().unwrap().keep().join("db");
    let path = path.to_str().unwrap().to_string();
    let core = ArciumCore::new(path.clone(), key32(3)).unwrap();
    core.save_identity(alice.core.load_identity().unwrap().unwrap()).unwrap();
    drop(core);
    let d = Device::reopen(&path, 3, relay);
    assert_eq!(d.pk, alice.pk);
    d.knows(bob);
    d
}

/// T1 over the relay, with the application's conversation: the upgraded
/// device syncs again, a new first contact from Alice's identity goes
/// through, and the text queued under the old build is sent once, under its
/// original id.
#[test]
fn t1_over_the_network_the_new_session_forms_and_the_queued_text_follows() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice_old, bob) = open_fixture("t1", &addr);
    let ha = handle(&alice_old);
    let history_before = history(&records(&bob.core, &alice_old));

    // The conversation that failed to refresh under the old build.
    let entries = bob.net.chat_entries(alice_old.pk.clone()).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        (entries[0].state, entries[0].app_id.as_slice(), entries[0].text.0.as_str()),
        (ChatEntryState::Queued, &b"q1"[..], "queued before the upgrade")
    );
    let r = bob.net.sync_conversations();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    let entries = bob.net.chat_entries(alice_old.pk.clone()).unwrap();
    assert_eq!(entries[0].state, ChatEntryState::Queued);
    assert!(bob.core.is_legacy_unconfirmed(ha).unwrap());

    let alice = alice_elsewhere(&alice_old, &bob, &addr);
    drop(alice_old);
    alice.net.start_session(bob.pk.clone()).unwrap();
    let r = alice.sync();
    assert!(r.errors.is_empty() && r.published >= 2, "{r:?}");

    let r = bob.net.sync_conversations();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.sessions_accepted, 1, "{r:?}");
    assert!(!bob.core.is_legacy_unconfirmed(ha).unwrap());
    assert_eq!(bob.core.initiator_handshake(ha).unwrap(), None, "no session of Bob's own");
    settle(&[&alice, &bob]);

    // Sent once, under its original id, and delivered.
    let texts = alice.net.received_texts(bob.pk.clone()).unwrap();
    assert_eq!(texts.len(), 1);
    assert_eq!(texts[0].text.0, b"queued before the upgrade");
    bob.net.sync_conversations();
    let outgoing: Vec<_> = bob
        .net
        .chat_entries(alice.pk.clone())
        .unwrap()
        .into_iter()
        .filter(|e| e.outgoing)
        .collect();
    assert_eq!(outgoing.len(), 1);
    assert_eq!(
        (outgoing[0].state, outgoing[0].app_id.as_slice()),
        (ChatEntryState::Delivered, &b"q1"[..])
    );

    // Both directions on the new session.
    alice.send(&bob, "a2", "from alice after the upgrade");
    bob.send(&alice, "b2", "from bob after the upgrade");
    settle(&[&alice, &bob]);
    assert_eq!(bob.texts(&alice), ["from alice after the upgrade"]);
    assert!(alice
        .net
        .received_texts(bob.pk.clone())
        .unwrap()
        .iter()
        .any(|t| t.text.0.starts_with(b"from bob after the upgrade")));

    let history_after = history(&records(&bob.core, &alice));
    for (k, v) in history_before.iter().filter(|(k, _)| !k.starts_with("chat-")) {
        assert_eq!(history_after.get(k), Some(v), "{k}");
    }
}

/// T1, the other way it can end: Alice's original first message arrives
/// after all. It authenticates on the old session, which then carries on
/// as an ordinary session; the retransmitted old handshake changes nothing.
#[test]
fn t1_the_old_handshakes_own_first_message_still_completes_the_old_session() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = open_fixture("t1", &addr);
    let ha = handle(&alice);
    let session_key = format!("session:v1/{}", hex(&alice.pk));
    let old_record = records(&bob.core, &alice)[&session_key].clone();

    settle(&[&alice, &bob]);
    assert!(!bob.core.is_legacy_unconfirmed(ha).unwrap());
    assert!(bob.generation_with(&alice) >= 1);
    let now = records(&bob.core, &alice);
    assert_ne!(now[&session_key], old_record);
    assert!(!now.keys().any(|k| k.starts_with("hsin:")), "nothing recorded");

    let r = bob.net.sync_conversations();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    settle(&[&alice, &bob]);
    let texts = alice.net.received_texts(bob.pk.clone()).unwrap();
    assert_eq!(texts.len(), 1);
    assert_eq!(texts[0].text.0, b"queued before the upgrade");
}

/// T2: an old session that authenticated the peer is never replaced or
/// downgraded by a later handshake, and the conversation — the pending
/// text and the acknowledged history included — continues.
#[test]
fn t2_an_old_authenticated_responder_session_is_kept_and_continues() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = open_fixture("t2", &addr);
    let (ha, hb) = (handle(&alice), handle(&bob));

    assert!(bob.core.has_session(ha).unwrap());
    assert!(!bob.core.is_legacy_unconfirmed(ha).unwrap());
    assert!(bob.generation_with(&alice) >= 1);
    assert_eq!(bob.texts(&alice), ["pending before the upgrade"]);
    let kept = |core: &ArciumCore| -> BTreeMap<String, Vec<u8>> {
        records(core, &alice)
            .into_iter()
            .filter(|(k, _)| {
                ["session:", "handle:", "hsin:", "inbox:", "seen:", "prekeys/v2"]
                    .iter()
                    .any(|ns| k.starts_with(ns))
            })
            .collect()
    };
    let before = kept(&bob.core);
    assert!(before.keys().any(|k| k.starts_with("seen:")), "acknowledged history");
    assert!(before.keys().any(|k| k.starts_with("inbox:")), "pending text");

    // A later, genuine handshake from Alice's identity: Alice's keys on a
    // second, empty database, against Bob's current bundle.
    let second = ArciumCore::new(
        tempdir().unwrap().keep().join("db").to_str().unwrap().to_string(),
        key32(9),
    )
    .unwrap();
    second.save_identity(alice.core.load_identity().unwrap().unwrap()).unwrap();
    let hs2 = second
        .establish_session_initiator(hb, bob.core.export_prekey_bundle().unwrap())
        .unwrap();

    assert!(matches!(
        bob.core.establish_session_responder(ha, hs2.clone()),
        Err(CoreError::SessionAlreadyExists { .. })
    ));
    assert_eq!(kept(&bob.core), before);

    let alice_pk: [u8; 32] = alice.pk.as_slice().try_into().unwrap();
    inject(
        &addr,
        &bob,
        Envelope::Handshake {
            sender: alice_pk,
            handshake: hs2,
        }
        .encode(),
    );
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.fetched, r.dropped, r.sessions_accepted), (1, 1, 0));
    assert_eq!(kept(&bob.core), before);

    // The conversation continues in both directions.
    alice.send(&bob, "t2", "after the upgrade");
    settle(&[&alice, &bob]);
    assert_eq!(bob.texts(&alice), ["pending before the upgrade", "after the upgrade"]);
    bob.send(&alice, "r2", "reply after the upgrade");
    settle(&[&alice, &bob]);
    assert_eq!(alice.texts(&bob), ["reply after the upgrade"]);
    let now = records(&bob.core, &alice);
    for (k, v) in before.iter().filter(|(k, _)| k.starts_with("seen:")) {
        assert_eq!(now.get(k), Some(v), "{k}");
    }
}
