//! V5: real process deaths around network messaging. The child is this test
//! binary running only `net_crash_child`: it opens one device's database,
//! does one step against the relay the parent runs, and dies by `abort()` —
//! at a named point inside `sync`, or right after the step returned. The
//! parent then restarts the device and checks that nothing was lost,
//! duplicated or accepted twice.

use super::net_harness::*;
use super::*;

const CHILD_ENV: &str = "ARCIUM_NET_CHILD";
const DIR_ENV: &str = "ARCIUM_NET_DIR";

#[test]
fn net_crash_child() {
    let (Ok(scenario), Ok(dir)) = (std::env::var(CHILD_ENV), std::env::var(DIR_ENV)) else {
        return; // Not a child run.
    };
    let dir = std::path::PathBuf::from(dir);
    let read = |n: &str| std::fs::read_to_string(dir.join(n)).unwrap();
    let device = Device::reopen(&read("path"), read("byte").parse().unwrap(), &read("relay"));
    match scenario.as_str() {
        "send" => {
            let peer = std::fs::read(dir.join("peer")).unwrap();
            device
                .net
                .send_text(
                    peer,
                    b"crash".to_vec(),
                    [b"sent before the crash".as_slice(), CANARY].concat(),
                )
                .unwrap();
        }
        "sync" => {
            device.sync();
        }
        "chat_send" => {
            let peer = std::fs::read(dir.join("peer")).unwrap();
            let text = format!(
                "sent from the chat{}",
                String::from_utf8(CANARY.to_vec()).unwrap()
            );
            device.net.chat_send(peer, b"crash".to_vec(), text).unwrap();
        }
        "chat_sync" => {
            device.net.sync_conversations();
        }
        other => panic!("unknown scenario {other}"),
    }
    std::process::abort();
}

/// Runs `scenario` for `device` in a child that dies at `point` inside
/// `sync`, or after the step returned when `point` is `None`.
#[cfg(unix)]
fn run_child(device: &Device, relay: &str, scenario: &str, point: Option<&str>, peer: &[u8]) {
    use std::os::unix::process::ExitStatusExt;
    let dir = tempdir().unwrap().keep();
    std::fs::write(dir.join("path"), &device.path).unwrap();
    std::fs::write(dir.join("byte"), device.byte.to_string()).unwrap();
    std::fs::write(dir.join("relay"), relay).unwrap();
    std::fs::write(dir.join("peer"), peer).unwrap();
    let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
    cmd.args([
        "--exact",
        "tests::network_crash::net_crash_child",
        "--nocapture",
        "--test-threads=1",
    ])
    .env(CHILD_ENV, scenario)
    .env(DIR_ENV, &dir);
    if let Some(p) = point {
        cmd.env("ARCIUM_NET_CRASH_AT", p);
    }
    let status = cmd.status().unwrap();
    assert_eq!(
        status.signal(),
        Some(6),
        "child must die by abort(): {status:?}"
    );
}

/// The sender dies after committing a text and before any network I/O. After
/// the restart the stored bytes are sent and delivered.
#[cfg(unix)]
#[test]
fn a_sender_killed_before_publishing_sends_the_stored_bytes_after_restart() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    run_child(&alice, &addr, "send", None, &bob.pk);

    let alice = alice.restart(&addr);
    let handle = local_session_handle(bob.pk.clone()).unwrap();
    let stored = alice.core.pending_outgoing(handle).unwrap();
    let texts: Vec<_> = stored
        .iter()
        .filter(|m| m.client_message_id == b"tcrash")
        .collect();
    assert_eq!(texts.len(), 1, "the text was committed before the crash");
    let wire = texts[0].wire.clone();
    settle(&[&alice, &bob]);
    assert_eq!(bob.texts(&alice), vec!["sent before the crash"]);
    assert_eq!(alice.undelivered(&bob), 0);
    assert_eq!(
        bob.net.received_texts(alice.pk.clone()).unwrap()[0].message_id,
        core_protocol::messaging::message_id(&wire).to_vec(),
        "Bob received the bytes committed before the crash"
    );
    relay.stop();
}

/// The recipient dies after accepting a text, after committing its receipt,
/// and after deleting it from the relay. Each time, the restarted device
/// shows the text once and the sender ends with it delivered.
#[cfg(unix)]
#[test]
fn a_recipient_killed_at_each_step_accepts_once_and_confirms_delivery() {
    for point in ["after_accept", "after_settle", "after_delete"] {
        let relay = start_relay();
        let addr = relay.addr().to_string();
        let (alice, bob) = connected(&addr);
        alice.send(&bob, "m", "survives");
        alice.sync();
        let gen_before = bob.generation_with(&alice);
        run_child(&bob, &addr, "sync", Some(point), &alice.pk);

        let bob = bob.restart(&addr);
        assert_eq!(
            bob.generation_with(&alice),
            gen_before + if point == "after_accept" { 1 } else { 2 },
            "{point}: the acceptance (and receipt) committed before the death"
        );
        settle(&[&bob, &alice]);
        assert_eq!(bob.texts(&alice), vec!["survives"], "{point}");
        assert_eq!(bob.accepted_total(), 0, "{point}: nothing accepted twice");
        assert_eq!(alice.undelivered(&bob), 0, "{point}");
        relay.stop();
    }
}

/// The sender dies right after accepting the recipient's receipt, before
/// applying it. The restarted device applies it from its inbox.
#[cfg(unix)]
#[test]
fn a_sender_killed_while_taking_a_receipt_applies_it_after_restart() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    alice.send(&bob, "m", "confirm me");
    alice.sync();
    bob.sync();
    run_child(&alice, &addr, "sync", Some("after_accept"), &bob.pk);

    let alice = alice.restart(&addr);
    assert_eq!(
        alice.undelivered(&bob),
        1,
        "the receipt is committed but not yet applied"
    );
    let r = alice.sync();
    assert_eq!(r.delivered, 1, "{r:?}");
    assert_eq!(alice.undelivered(&bob), 0);
    relay.stop();
}

/// Every chat round of `devices`, in turn, `n` times; no errors allowed.
fn chat_rounds(devices: &[&Device], n: usize) {
    for _ in 0..n {
        for d in devices {
            let r = d.net.sync_conversations();
            assert!(r.errors.is_empty(), "{:?}", r.errors);
        }
    }
}

/// The sender dies while sending from the chat: after recording the text,
/// after committing it to the outbox, and after the call returned. After the
/// restart it is committed once, recorded once and delivered once.
#[cfg(unix)]
#[test]
fn a_sender_killed_while_sending_from_the_chat_sends_the_text_once() {
    use crate::network::chat::ChatEntryState;
    for point in [Some("chat_after_queue"), Some("chat_after_outbox"), None] {
        let relay = start_relay();
        let addr = relay.addr().to_string();
        let (alice, bob) = connected(&addr);
        run_child(&alice, &addr, "chat_send", point, &bob.pk);

        let alice = alice.restart(&addr);
        let entries = alice.net.chat_entries(bob.pk.clone()).unwrap();
        assert_eq!(entries.len(), 1, "{point:?}: recorded once");
        assert_eq!(alice.undelivered(&bob), 1, "{point:?}: one ciphertext");
        chat_rounds(&[&alice, &bob, &alice], 2);
        let received = bob.net.chat_entries(alice.pk.clone()).unwrap();
        assert_eq!(received.len(), 1, "{point:?}: received once");
        assert!(received[0].text.starts_with("sent from the chat"));
        assert_eq!(
            alice.net.chat_entries(bob.pk.clone()).unwrap()[0].state,
            ChatEntryState::Delivered,
            "{point:?}"
        );
        assert_eq!(relay.canary_hits(), 0);
        relay.stop();
    }
}

/// The recipient dies after recording a received text in the history and
/// before marking it read, so the inbox lists it again after the restart.
/// The history shows it once.
#[cfg(unix)]
#[test]
fn a_recipient_killed_before_marking_a_recorded_text_read_shows_it_once() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    alice
        .net
        .chat_send(bob.pk.clone(), b"r".to_vec(), "recorded".into())
        .unwrap();
    chat_rounds(&[&alice], 1);
    run_child(
        &bob,
        &addr,
        "chat_sync",
        Some("chat_after_record"),
        &alice.pk,
    );

    let bob = bob.restart(&addr);
    assert_eq!(
        bob.net.received_texts(alice.pk.clone()).unwrap().len(),
        1,
        "the crash came before it was marked read"
    );
    let entries = bob.net.chat_entries(alice.pk.clone()).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].text, "recorded");
    assert!(bob.net.received_texts(alice.pk.clone()).unwrap().is_empty());
    relay.stop();
}
