//! The outgoing path: once the application's text is in a wiping owner in
//! Rust, the internal send functions take it in that owner, and the bytes that
//! arrive are exactly the bytes that were given. These tests pin owner types
//! and bytes; they do not observe memory, and a copy made inside a function
//! that keeps these signatures is not detected.

use zeroize::Zeroizing;

use super::net_harness::*;
use super::*;
use crate::network::chat::ChatEntryState;
use crate::network::{NetworkMessenger, SentText, TextState};

/// The signatures of the internal send functions: the plaintext is borrowed
/// from, or moved in, a wiping owner.
type CoreSend = fn(&ArciumCore, u64, &[u8], &Zeroizing<Vec<u8>>) -> Result<SendResult, CoreError>;
type TextSend =
    fn(&NetworkMessenger, &[u8; 32], &[u8], Zeroizing<Vec<u8>>) -> Result<SentText, CoreError>;

/// The internal send functions accept the plaintext only in a wiping owner.
#[test]
fn the_internal_send_functions_take_a_wiping_owner() {
    let _: CoreSend = ArciumCore::send_committed;
    let _: TextSend = NetworkMessenger::send_committed_text;
}

/// The exported `send_message` and the internal `send_committed` are one
/// logical send: either one repeats the other's message under the same id, and
/// both fail the same way.
#[test]
fn the_exported_and_the_internal_send_are_one_path() {
    let session_id: u64 = 31;
    let bob = fresh_core(71);
    bob.save_identity(Identity::generate()).unwrap();
    bob.establish_prekeys().unwrap();
    let alice = fresh_core(72);
    alice.save_identity(Identity::generate()).unwrap();
    let handshake = alice
        .establish_session_initiator(session_id, bob.export_prekey_bundle().unwrap())
        .unwrap();
    bob.establish_session_responder(session_id, handshake)
        .unwrap();

    let SendResult::Sent { message: first } = alice
        .send_committed(session_id, b"c-1", &Zeroizing::new(b"first".to_vec()))
        .unwrap()
    else {
        panic!("expected Sent");
    };
    assert_eq!(
        alice
            .send_message(session_id, b"c-1".to_vec(), b"ignored".to_vec())
            .unwrap(),
        SendResult::AlreadyPending {
            message: first.clone()
        }
    );
    let SendResult::Sent { message: second } = alice
        .send_message(session_id, b"c-2".to_vec(), b"second".to_vec())
        .unwrap()
    else {
        panic!("expected Sent");
    };
    assert_eq!(
        alice
            .send_committed(session_id, b"c-2", &Zeroizing::new(b"ignored".to_vec()))
            .unwrap(),
        SendResult::AlreadyPending {
            message: second.clone()
        }
    );

    for (message, text) in [(first, &b"first"[..]), (second, b"second")] {
        let ReceiveResult::Accepted { message } =
            bob.receive_message(session_id, message.wire).unwrap()
        else {
            panic!("expected Accepted");
        };
        assert_eq!(message.plaintext, text);
    }

    let text = Zeroizing::new(b"x".to_vec());
    for (session, id) in [(session_id, &b""[..]), (99, b"c-3")] {
        assert_eq!(
            format!("{:?}", alice.send_committed(session, id, &text)),
            format!(
                "{:?}",
                alice.send_message(session, id.to_vec(), text.to_vec())
            ),
        );
    }
}

/// `send_text` delivers every byte of a text as given: empty, ASCII, UTF-8,
/// every byte value, and a large text.
#[test]
fn a_sent_text_arrives_byte_for_byte() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    let texts: Vec<Vec<u8>> = vec![
        vec![],
        b"plain ascii".to_vec(),
        "привет, ✓ 🜂".as_bytes().to_vec(),
        (0..=255).collect(),
        vec![0xA5; 16 * 1024],
    ];
    for (i, text) in texts.iter().enumerate() {
        let sent = alice
            .net
            .send_text(bob.pk.clone(), format!("b{i}").into_bytes(), text.clone())
            .unwrap();
        assert_eq!(sent.state, TextState::Pending);
    }
    settle(&[&alice, &bob]);
    let received: Vec<Vec<u8>> = bob
        .net
        .received_texts(alice.pk.clone())
        .unwrap()
        .into_iter()
        .map(|t| t.text)
        .collect();
    assert_eq!(received, texts);
    relay.stop();
}

/// A text queued while no session exists is sent from the history's own
/// wiping copy once a session exists, and arrives unchanged, once.
#[test]
fn a_queued_chat_text_is_sent_unchanged_once_a_session_exists() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    alice.knows(&bob);
    bob.knows(&alice);
    let text = format!("очередь ✓ {}", "q".repeat(16 * 1024 - 20));
    let queued = alice
        .net
        .chat_send(bob.pk.clone(), b"q-1".to_vec(), text.clone())
        .unwrap();
    assert_eq!(queued.state, ChatEntryState::Queued);

    bob.net.publish_prekeys().unwrap();
    for _ in 0..4 {
        alice.net.sync_conversations();
        bob.net.sync_conversations();
    }
    let got: Vec<String> = bob
        .net
        .chat_entries(alice.pk.clone())
        .unwrap()
        .into_iter()
        .filter(|e| !e.outgoing)
        .map(|e| e.text)
        .collect();
    assert_eq!(got, vec![text]);
    assert_eq!(
        alice.net.chat_entries(bob.pk.clone()).unwrap()[0].state,
        ChatEntryState::Delivered
    );
    relay.stop();
}
