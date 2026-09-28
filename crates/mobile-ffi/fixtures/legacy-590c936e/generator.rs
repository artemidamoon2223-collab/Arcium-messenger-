//! Writes the databases in this directory. It is NOT part of this build:
//! `generate.sh` copies it into a checkout of commit 590c936e (the build
//! before ARCIUM-SESSION-CONFIRMATION-001) as `src/tests/legacy_fixture_gen.rs`
//! and runs it there, so every record in the output was written by that
//! build's own code. Only legitimate peers and the old build's public API
//! are used; no handshake or message is constructed by hand.
//!
//! Master keys are the test harness's `[byte; 32]`: Alice is device 1, Bob
//! device 2.

use super::net_harness::*;
use super::*;
use std::path::{Path, PathBuf};

fn out_dir() -> Option<PathBuf> {
    std::env::var("ARCIUM_LEGACY_FIXTURE_OUT").ok().map(PathBuf::from)
}

/// Closes the device's database and copies the file to `out/name`.
fn save(dev: Device, out: &Path, name: &str) {
    let path = dev.path.clone();
    drop(dev);
    let dir = Path::new(&path).parent().unwrap();
    for entry in std::fs::read_dir(dir).unwrap() {
        let file = entry.unwrap().file_name();
        assert_eq!(file, "db", "only the database file may remain: {file:?}");
    }
    std::fs::copy(&path, out.join(name)).unwrap();
}

fn handle(dev: &Device) -> u64 {
    local_session_handle(dev.pk.clone()).unwrap()
}

/// T1: Bob's old build stored a responder session from Alice's genuine
/// handshake, and no message from Alice ever reached it. Beside it: a
/// send-id record left by a session Bob started earlier and gave up on, and
/// a text Bob's user queued for Alice meanwhile.
#[test]
#[ignore = "fixture generator; run by fixtures/legacy-590c936e/generate.sh"]
fn generate_pristine_responder() {
    let Some(out) = out_dir() else { return };
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    alice.knows(&bob);
    bob.knows(&alice);
    alice.net.publish_prekeys().unwrap();
    bob.net.publish_prekeys().unwrap();

    // A session Bob started and abandoned before Alice's arrived.
    bob.net.start_session(alice.pk.clone()).unwrap();
    for m in bob.core.pending_outgoing(handle(&alice)).unwrap() {
        bob.core.abandon_outgoing(handle(&alice), m.message_id).unwrap();
    }
    bob.core.remove_session(handle(&alice)).unwrap();

    // Alice starts; only her handshake reaches Bob, whose build stores a
    // responder session for it on receipt.
    alice.net.start_session(bob.pk.clone()).unwrap();
    let hs = alice.core.initiator_handshake(handle(&bob)).unwrap().unwrap();
    bob.core.establish_session_responder(handle(&alice), hs.clone()).unwrap();
    assert!(bob.core.has_session(handle(&alice)).unwrap());

    // The old build records the text as queued, then cannot encrypt it on
    // that session. From then on every refresh of the conversation — even
    // listing it — fails the same way in the old build.
    let not_initialized = |r: Result<_, CoreError>| {
        matches!(r, Err(CoreError::Crypto { msg }) if msg.contains("not yet initialized"))
    };
    assert!(not_initialized(
        bob.net
            .chat_send(alice.pk.clone(), b"q1".to_vec(), "queued before the upgrade".into())
            .map(|_| ())
    ));
    assert!(not_initialized(bob.net.chat_entries(alice.pk.clone()).map(|_| ())));
    let sync = bob.net.sync_conversations();
    assert_eq!(sync.fetched, 0, "the old build's round ends before fetching");
    assert!(sync.errors.iter().any(|e| e.contains("not yet initialized")));

    std::fs::write(out.join("t1-alice-handshake.bin"), &hs).unwrap();
    save(alice, &out, "t1-alice.db");
    save(bob, &out, "t1-bob.db");
}

/// T2: Bob's old build accepted Alice's session and authenticated her
/// messages: her OPEN message acknowledged (only its seen record left) and a
/// text still pending in the inbox.
#[test]
#[ignore = "fixture generator; run by fixtures/legacy-590c936e/generate.sh"]
fn generate_authenticated_responder() {
    let Some(out) = out_dir() else { return };
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    alice.send(&bob, "t1", "pending before the upgrade");
    settle(&[&alice, &bob]);
    assert_eq!(bob.texts(&alice), ["pending before the upgrade"]);
    assert_eq!(alice.undelivered(&bob), 0);
    save(alice, &out, "t2-alice.db");
    save(bob, &out, "t2-bob.db");
}
