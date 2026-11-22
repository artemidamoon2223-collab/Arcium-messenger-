//! V5: real process deaths around network messaging. The child is this test
//! binary running only `net_crash_child`: it opens one device's database,
//! does one step against the relay the parent runs, and dies by `abort()` —
//! at a named point inside `sync`, or right after the step returned. The
//! parent then restarts the device and checks that nothing was lost,
//! duplicated or accepted twice.

use super::net_harness::*;
use super::*;
use crate::network::wire::client_id;

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
        "cancel" => {
            let peer = std::fs::read(dir.join("peer")).unwrap();
            device.net.cancel_text(peer, b"cancel".to_vec()).unwrap();
        }
        "resolve" => {
            let peer = std::fs::read(dir.join("peer")).unwrap();
            device.net.resolve_session_conflict(peer).unwrap();
        }
        "reset" => {
            let peer = std::fs::read(dir.join("peer")).unwrap();
            device.net.reset_session(peer).unwrap();
        }
        other => panic!("unknown scenario {other}"),
    }
    std::process::abort();
}

/// Runs `scenario` for `device` in a child that dies at `point` inside
/// `sync`, or after the step returned when `point` is `None`.
#[cfg(unix)]
pub(super) fn run_child(
    device: &Device,
    relay: &str,
    scenario: &str,
    point: Option<&str>,
    peer: &[u8],
) {
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

/// The sender dies inside `settle`, after applying the recipient's receipt
/// and before acknowledging the receipt message itself. The delivery is
/// already stored; the receipt is still in the inbox (and still on the
/// relay, from which it comes again as a duplicate), and the next round
/// settles it without counting the delivery a second time.
#[cfg(unix)]
#[test]
fn a_sender_killed_between_applying_a_receipt_and_acknowledging_it_applies_it_once() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    alice.send(&bob, "m", "confirm me");
    alice.sync();
    bob.sync();
    run_child(&alice, &addr, "sync", Some("receipt_applied"), &bob.pk);

    let alice = alice.restart(&addr);
    let handle = local_session_handle(bob.pk.clone()).unwrap();
    assert_eq!(
        alice.undelivered(&bob),
        0,
        "the receipt was applied before the death"
    );
    assert_eq!(
        alice.core.pending_committed(handle).unwrap().len(),
        1,
        "the receipt message itself is still in the inbox"
    );
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.delivered, 0, "the delivery is not counted twice: {r:?}");
    assert_eq!(alice.undelivered(&bob), 0);
    assert!(
        alice.core.pending_committed(handle).unwrap().is_empty(),
        "the receipt was settled from the inbox"
    );
    relay.stop();
}

/// The sender dies inside `settle`, after abandoning the text a GONE message
/// names and before acknowledging the GONE message itself (R-21). The text
/// is already abandoned; the GONE message is still in the inbox (and still
/// on the relay, from which it comes again as a duplicate), and the next
/// round settles it. That text 0 is not abandoned a second time is not
/// asserted here: it follows from `settle` abandoning only what is pending.
#[cfg(unix)]
#[test]
fn a_sender_killed_between_applying_a_gone_message_and_acknowledging_it_settles_it_after_restart() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    let to_bob = local_session_handle(bob.pk.clone()).unwrap();
    let to_alice = local_session_handle(alice.pk.clone()).unwrap();

    // As in `beyond_recall`: Alice commits 2,101 texts in one sending chain
    // and Bob reads three of them, which evicts the key of text 0.
    let ids: Vec<Vec<u8>> = (0..2101)
        .map(|i| alice.send(&bob, &format!("g{i}"), "x"))
        .collect();
    let pending = alice.core.pending_outgoing(to_bob).unwrap();
    for i in [900, 1800, 2100] {
        let wire = &pending
            .iter()
            .find(|m| m.message_id == ids[i])
            .expect("pending")
            .wire;
        bob.core.receive_committed(to_alice, wire).unwrap();
    }
    for id in &ids[1..] {
        alice.core.abandon_outgoing(to_bob, id.clone()).unwrap();
    }
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    // Text 0 reaches Bob late; he cannot read it and names it.
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(alice.undelivered(&bob), 1);
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.dropped, r.published), (1, 1), "{r:?}");

    run_child(&alice, &addr, "sync", Some("gone_applied"), &bob.pk);

    let alice = alice.restart(&addr);
    assert_eq!(
        alice.undelivered(&bob),
        0,
        "text 0 was abandoned before the death"
    );
    assert_eq!(
        alice.core.pending_committed(to_bob).unwrap().len(),
        1,
        "the GONE message itself is still in the inbox"
    );
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(alice.undelivered(&bob), 0);
    assert!(
        alice.core.pending_committed(to_bob).unwrap().is_empty(),
        "the GONE message was settled from the inbox"
    );
    relay.stop();
}

/// The recipient dies inside `settle`, after committing its receipt for the
/// initiator's OPEN message and before acknowledging the OPEN message itself.
/// The session and the receipt are already stored; the OPEN message is still
/// in the inbox (and still on the relay, from which it comes again as a
/// duplicate). The next rounds settle it, and the initiator ends with its
/// OPEN message confirmed. The other order would lose the confirmation: an
/// OPEN acknowledged without a receipt is never answered again
/// (`receipt_again` answers only what was answered when it was accepted).
#[cfg(unix)]
#[test]
fn a_recipient_killed_between_receipting_an_open_message_and_acknowledging_it_confirms_it_after_restart() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    alice.knows(&bob);
    bob.knows(&alice);
    bob.net.publish_prekeys().unwrap();
    alice.net.start_session(bob.pk.clone()).unwrap();
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    let to_bob = local_session_handle(bob.pk.clone()).unwrap();
    let to_alice = local_session_handle(alice.pk.clone()).unwrap();
    let open = alice.core.pending_outgoing(to_bob).unwrap();
    assert_eq!(open.len(), 1, "Alice's OPEN message waits for its receipt");
    let open_id: [u8; 32] = open[0].message_id.as_slice().try_into().unwrap();

    run_child(&bob, &addr, "sync", Some("open_receipted"), &alice.pk);

    let bob = bob.restart(&addr);
    assert!(
        bob.core.has_session(to_alice).unwrap(),
        "the session was created before the death"
    );
    let receipts = bob.core.pending_outgoing(to_alice).unwrap();
    assert_eq!(receipts.len(), 1, "one receipt was committed before the death");
    assert_eq!(
        receipts[0].client_message_id,
        client_id::receipt(&open_id, 0),
        "and it answers the OPEN message"
    );
    assert_eq!(
        bob.core.pending_committed(to_alice).unwrap().len(),
        1,
        "the OPEN message itself is still in the inbox"
    );
    settle(&[&bob, &alice]);
    assert_eq!(bob.accepted_total(), 0, "nothing accepted twice");
    assert!(
        bob.core.pending_committed(to_alice).unwrap().is_empty(),
        "the OPEN message was settled from the inbox"
    );
    assert!(
        alice.core.pending_outgoing(to_bob).unwrap().is_empty(),
        "Alice's OPEN message is confirmed"
    );
    relay.stop();
}

/// The recipient dies while publishing, after the relay accepted its receipt
/// for a text and before the receipt left the outbox. The receipt is on the
/// relay, so the sender has its delivery; it is also still in the outbox, so
/// the restarted recipient publishes it a second time. In that round the
/// sender's text also reaches the recipient from the relay, as a duplicate,
/// which it answers with a later receipt (`receipt_again`). The sender gets
/// both: the repeated receipt is a duplicate and changes nothing, and the
/// later one is accepted without counting the delivery again.
#[cfg(unix)]
#[test]
fn a_recipient_killed_between_the_relay_accepting_a_receipt_and_dropping_it_from_the_outbox_sends_it_again() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    let to_bob = local_session_handle(bob.pk.clone()).unwrap();
    let to_alice = local_session_handle(alice.pk.clone()).unwrap();
    // Bob accepts the text without a round, so that its receipt is committed
    // and published by one and the same round: the child's.
    let id: [u8; 32] = alice.send(&bob, "m", "confirm me").as_slice().try_into().unwrap();
    let wire = alice
        .core
        .pending_outgoing(to_bob)
        .unwrap()
        .into_iter()
        .find(|m| m.message_id == id)
        .expect("pending")
        .wire;
    bob.core.receive_committed(to_alice, &wire).unwrap();

    run_child(&bob, &addr, "sync", Some("receipt_published"), &alice.pk);

    let bob = bob.restart(&addr);
    let receipt = client_id::receipt(&id, 0);
    let pending = bob.core.pending_outgoing(to_alice).unwrap();
    assert_eq!(pending.len(), 1, "the receipt is still in the outbox");
    assert_eq!(pending[0].client_message_id, receipt);
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.delivered, 1, "the relay had accepted the receipt: {r:?}");
    assert_eq!(alice.undelivered(&bob), 0);

    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(
        (r.duplicates, r.published),
        (1, 2),
        "the receipt again, and a later one for the text that came again: {r:?}"
    );
    assert!(
        bob.core
            .pending_outgoing(to_alice)
            .unwrap()
            .iter()
            .all(|m| m.client_message_id != receipt),
        "and this time it left the outbox"
    );
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(
        (r.duplicates, r.accepted, r.delivered),
        (1, 1, 0),
        "the delivery is not counted twice: {r:?}"
    );
    settle(&[&bob, &alice]);
    assert_eq!(bob.texts(&alice), vec!["confirm me"]);
    assert_eq!(alice.undelivered(&bob), 0);
    assert!(bob.core.pending_outgoing(to_alice).unwrap().is_empty());
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
        assert!(received[0].text.0.starts_with("sent from the chat"));
        assert_eq!(
            alice.net.chat_entries(bob.pk.clone()).unwrap()[0].state,
            ChatEntryState::Delivered,
            "{point:?}"
        );
        assert_eq!(relay.canary_hits(), 0);
        relay.stop();
    }
}

/// The recipient dies after accepting a text and before committing its
/// receipt. After the restart the chat reads the text into the history and
/// marks it read before any sync round; the text must still be answered, or
/// its sender would wait for a receipt that never comes. (Since a duplicate is
/// answered only when the original was, the receipt has to be committed
/// before the text is marked read.)
#[cfg(unix)]
#[test]
fn a_recipient_killed_before_its_receipt_still_confirms_the_text() {
    use crate::network::chat::ChatEntryState;
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    alice
        .net
        .chat_send(bob.pk.clone(), b"r".to_vec(), "confirm me".into())
        .unwrap();
    chat_rounds(&[&alice], 1);
    run_child(&bob, &addr, "chat_sync", Some("after_accept"), &alice.pk);

    let bob = bob.restart(&addr);
    // The history first, as the app does when the chat opens: the text is
    // recorded and marked read here.
    let entries = bob.net.chat_entries(alice.pk.clone()).unwrap();
    assert_eq!(entries.len(), 1);
    assert!(bob.net.received_texts(alice.pk.clone()).unwrap().is_empty());
    chat_rounds(&[&bob, &alice, &bob, &alice], 2);
    assert_eq!(
        alice.net.chat_entries(bob.pk.clone()).unwrap()[0].state,
        ChatEntryState::Delivered
    );
    assert_eq!(bob.net.chat_entries(alice.pk.clone()).unwrap().len(), 1);
    relay.stop();
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
    assert_eq!(entries[0].text.0, "recorded");
    assert!(bob.net.received_texts(alice.pk.clone()).unwrap().is_empty());
    relay.stop();
}

/// The sender dies while cancelling a committed text: after marking the
/// entry `Cancelled` and before abandoning the message, after abandoning it,
/// and after the call returned. After the restart the text is still in the
/// outbox only in the first case, and the next round abandons it instead of
/// sending it (`publish_pending`): the peer never gets it, and the entry
/// stays `Cancelled`.
#[cfg(unix)]
#[test]
fn a_sender_killed_while_cancelling_never_sends_the_text() {
    use crate::network::chat::ChatEntryState;
    for point in [Some("cancel_after_mark"), Some("cancel_after_abandon"), None] {
        let relay = start_relay();
        let addr = relay.addr().to_string();
        let (alice, bob) = connected(&addr);
        let text = format!("cancel me{}", String::from_utf8(CANARY.to_vec()).unwrap());
        let entry = alice
            .net
            .chat_send(bob.pk.clone(), b"cancel".to_vec(), text)
            .unwrap();
        assert_eq!(entry.state, ChatEntryState::Pending);
        run_child(&alice, &addr, "cancel", point, &bob.pk);

        let alice = alice.restart(&addr);
        let left = usize::from(point == Some("cancel_after_mark"));
        assert_eq!(alice.undelivered(&bob), left, "{point:?}");
        chat_rounds(&[&alice, &bob, &alice], 2);
        assert_eq!(alice.undelivered(&bob), 0, "{point:?}");
        assert!(stored_messages(&relay, &bob).is_empty(), "{point:?}");
        assert!(
            bob.net.chat_entries(alice.pk.clone()).unwrap().is_empty(),
            "{point:?}: never received"
        );
        let entries = alice.net.chat_entries(bob.pk.clone()).unwrap();
        assert_eq!(entries.len(), 1, "{point:?}");
        assert_eq!(entries[0].state, ChatEntryState::Cancelled, "{point:?}");
        assert_eq!(relay.canary_hits(), 0);
        relay.stop();
    }
}

/// Tracker R-6: Bob dies right after a rotation committed, and right after
/// the relay accepted the rotated bundle, before that was recorded. After
/// the restart the signed prekey is not rotated again, its publication is
/// recorded, and Alice's handshake, built from the bundle the relay served
/// before the rotation, is answered.
#[cfg(unix)]
#[test]
fn a_device_killed_around_a_rotation_rotates_once_and_answers_the_served_bundle() {
    let spk = |d: &Device| {
        let record = unpack_prekeys(&read_record(&d.core)).unwrap();
        (
            spk_id(record.signed_prekey_pk().as_bytes()),
            record.prev.as_ref().map(|sk| spk_id(PublicKey::from(sk).as_bytes())),
            record.published_at,
        )
    };
    let served = |addr: &str, d: &Device| {
        let bundle = relay::client::Connection::connect(addr, std::time::Duration::from_secs(2))
            .unwrap()
            .get_bundle(d.pk.as_slice().try_into().unwrap())
            .unwrap()
            .unwrap();
        spk_id(unpack_prekey_bundle(&bundle).unwrap().signed_prekey_pk.as_bytes())
    };
    for point in ["bundle_after_maintain", "bundle_after_put"] {
        let relay = start_relay();
        let addr = relay.addr().to_string();
        let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
        alice.knows(&bob);
        bob.knows(&alice);
        bob.net.publish_prekeys().unwrap();
        // Accepted by the relay a period and a minute ago by Bob's clock:
        // the child's round rotates it.
        {
            let store = bob.core.store.lock().unwrap();
            let mut record = unpack_prekeys(&store.get(PREKEYS_KEY).unwrap()).unwrap();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            record.published_at = now - SIGNED_PREKEY_PERIOD_SECS - 60;
            store.put(PREKEYS_KEY, &pack_prekeys(&record)).unwrap();
        }
        let (first, _, _) = spk(&bob);
        alice.net.start_session(bob.pk.clone()).unwrap();
        alice.send(&bob, "m", "across the rotation");
        alice.sync();

        run_child(&bob, &addr, "sync", Some(point), &alice.pk);
        let bob = bob.restart(&addr);
        let (rotated, prev, published_at) = spk(&bob);
        assert_ne!(rotated, first, "{point}: rotated before the death");
        assert_eq!(prev, Some(first), "{point}");
        assert_eq!(published_at, 0, "{point}: the publication is not recorded yet");
        let expected = if point == "bundle_after_put" { rotated } else { first };
        assert_eq!(served(&addr, &bob), expected, "{point}");

        let r = bob.sync();
        assert!(r.errors.is_empty(), "{point}: {:?}", r.errors);
        let (again, _, published_at) = spk(&bob);
        assert_eq!(again, rotated, "{point}: not rotated a second time");
        assert_ne!(published_at, 0, "{point}: the publication is recorded");
        assert_eq!(served(&addr, &bob), rotated, "{point}");
        assert_eq!(bob.texts(&alice), vec!["across the rotation"], "{point}");
        settle(&[&alice, &bob]);
        assert_eq!(alice.undelivered(&bob), 0, "{point}");
        relay.stop();
    }
}
