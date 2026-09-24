//! A long-running peer for the Android end-to-end test: a second, independent
//! device on the CI host that the app on the emulator talks to through a real
//! relay. It is this test binary running only `net_peer_bot`, which returns
//! at once unless `ARCIUM_PEER_RELAY` is set.
//!
//! Environment: `ARCIUM_PEER_RELAY` (`host:port`), `ARCIUM_PEER_DB` (database
//! path), `ARCIUM_PEER_CARD_OUT` (where its contact card is written, in hex).
//!
//! Behaviour: it answers every text `T` with `echo:T`. A text
//! `cmd:offline:N` makes it stop syncing for `N` milliseconds, simulating a
//! recipient that is away.
//!
//! **Test harness only: it trusts on first use.** The app pins this peer's
//! card, passed to the instrumentation test out of band. This peer instead
//! pins whoever sends it a handshake, building the card from that sender's
//! bundle on the relay. The application never does this.

use super::*;
use crate::contacts::Card;
use crate::network::wire::Envelope;
use crate::network::NetworkMessenger;
use relay::client::Connection;
use std::time::Duration;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn net_peer_bot() {
    let Ok(relay) = std::env::var("ARCIUM_PEER_RELAY") else {
        return; // Not a harness run.
    };
    let db = std::env::var("ARCIUM_PEER_DB").expect("ARCIUM_PEER_DB");
    let core = ArciumCore::new(db, key32(0x5e)).unwrap();
    if core.load_identity().is_none() {
        core.save_identity(Identity::generate()).unwrap();
    }
    let net = NetworkMessenger::new(core.clone(), relay.clone(), 2000, 5000);
    loop {
        match net.publish_prekeys() {
            Ok(()) => break,
            Err(e) => {
                eprintln!("peer: relay not ready: {e}");
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
    let card = hex(&core.contact_card().unwrap());
    std::fs::write(
        std::env::var("ARCIUM_PEER_CARD_OUT").expect("card out"),
        &card,
    )
    .unwrap();
    eprintln!("peer: ready, card {card}");

    let me: [u8; 32] = core.contact_card().unwrap()[1..33].try_into().unwrap();
    loop {
        pin_new_senders(&core, &relay, &me);
        let r = net.sync();
        if r.accepted + r.sessions_accepted + r.delivered + r.dropped > 0 || !r.errors.is_empty() {
            eprintln!("peer: sync {r:?}");
        }
        let mut offline = None;
        for peer in core.contacts().unwrap() {
            for t in net.received_texts(peer.clone()).unwrap() {
                let text = String::from_utf8_lossy(&t.text).to_string();
                eprintln!("peer: decrypted text from {}: {text:?}", &hex(&peer)[..8]);
                if let Some(ms) = text.strip_prefix("cmd:offline:") {
                    offline = ms.parse::<u64>().ok();
                } else {
                    let reply = [b"echo:".as_slice(), &t.text].concat();
                    let id = [b"echo-".as_slice(), &t.message_id[..16]].concat();
                    net.send_text(peer.clone(), id, reply).unwrap();
                }
                net.mark_read(peer.clone(), t.message_id).unwrap();
            }
        }
        match offline {
            Some(ms) => {
                // Push the receipt for the command first, then go away.
                net.sync();
                eprintln!("peer: offline for {ms} ms");
                std::thread::sleep(Duration::from_millis(ms));
                eprintln!("peer: back online");
            }
            None => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

/// Harness TOFU: pins the card of every unknown handshake sender, taken from
/// its bundle on the relay. Reads the mailbox without deleting anything.
fn pin_new_senders(core: &ArciumCore, relay: &str, me: &[u8; 32]) {
    let Ok(mut conn) = Connection::connect(relay, Duration::from_secs(5)) else {
        return;
    };
    let Ok(items) = conn.fetch(*me, 256) else {
        return;
    };
    let known = core.contacts().unwrap();
    for (_, env) in items {
        let Some(Envelope::Handshake { sender, .. }) = Envelope::decode(&env) else {
            continue;
        };
        if known.iter().any(|k| k.as_slice() == sender) {
            continue;
        }
        if let Ok(Some(bundle)) = conn.get_bundle(sender) {
            if let Ok(b) = unpack_prekey_bundle(&bundle) {
                if b.identity_pk.to_bytes() == sender {
                    let card = Card {
                        dh_pk: sender,
                        signing_pk: b.signing_pk.to_bytes(),
                    };
                    core.add_contact(card.encode()).unwrap();
                    eprintln!(
                        "peer: pinned new contact {} (harness TOFU)",
                        &hex(&sender)[..8]
                    );
                }
            }
        }
    }
}

/// Two independent processes, each with its own database, exchange messages
/// in both directions through a relay over TCP: this process as the app,
/// a child running `net_peer_bot` as the peer.
#[cfg(unix)]
#[test]
fn a_peer_in_another_process_answers_over_the_relay() {
    use super::net_harness::{start_relay, Device, CANARY};
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let dir = tempdir().unwrap().keep();
    let card_file = dir.join("card");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::net_peer::net_peer_bot",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ARCIUM_PEER_RELAY", &addr)
        .env("ARCIUM_PEER_DB", dir.join("peer.db"))
        .env("ARCIUM_PEER_CARD_OUT", &card_file)
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let card = loop {
        if let Ok(c) = std::fs::read_to_string(&card_file) {
            break (0..c.len() / 2)
                .map(|i| u8::from_str_radix(&c[2 * i..2 * i + 2], 16).unwrap())
                .collect::<Vec<u8>>();
        }
        assert!(std::time::Instant::now() < deadline, "peer did not start");
        std::thread::sleep(Duration::from_millis(100));
    };

    let alice = Device::new(&addr, 1);
    let peer = alice.core.add_contact(card).unwrap();
    alice.net.publish_prekeys().unwrap();
    alice.net.start_session(peer.clone()).unwrap();
    let body = [b"ping ".as_slice(), CANARY].concat();
    alice
        .net
        .send_text(peer.clone(), b"p1".to_vec(), body.clone())
        .unwrap();
    let reply = loop {
        let r = alice.sync();
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        if let Some(t) = alice.net.received_texts(peer.clone()).unwrap().pop() {
            break t.text;
        }
        assert!(std::time::Instant::now() < deadline, "no reply");
        std::thread::sleep(Duration::from_millis(100));
    };
    child.kill().unwrap();
    let _ = child.wait();
    assert_eq!(reply, [b"echo:".as_slice(), &body].concat());
    assert!(alice.net.undelivered(peer).unwrap().is_empty());
    assert_eq!(relay.canary_hits(), 0);
    relay.stop();
}
