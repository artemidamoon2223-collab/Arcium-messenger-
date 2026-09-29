//! Accidental `Debug` formatting (`{:?}`, `{:#?}`, an assertion failure, a
//! logged error context) of a value that carries a decrypted message must not
//! print the message. This covers every plaintext-bearing type of this crate
//! and the values a real receive produces. It is about formatting and logging
//! only; it says nothing about process memory or about the application's own
//! copy of the text once it has crossed the FFI boundary.

use zeroize::ZeroizeOnDrop;

use super::*;
use crate::network::chat::{ChatEntry, ChatEntryState, ChatSessionState, Conversation};
use crate::network::wire::Payload;
use crate::network::ReceivedText;

const CANARY: &[u8] = b"ARCIUM-PLAINTEXT-CANARY-7c1e";

/// Every rendering of `CANARY` a formatter could produce.
fn renderings() -> Vec<String> {
    let list = CANARY
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let hex: String = CANARY.iter().map(|b| format!("{b:02x}")).collect();
    vec![
        String::from_utf8(CANARY.to_vec()).unwrap(),
        list,
        hex.to_uppercase(),
        hex,
    ]
}

/// Formats `value` both ways and asserts the canary is in neither.
fn assert_redacted<T: std::fmt::Debug>(value: &T) -> Vec<String> {
    let outputs = vec![format!("{value:?}"), format!("{value:#?}")];
    for text in &outputs {
        for needle in renderings() {
            assert!(!text.contains(&needle), "{needle:?} found in {text}");
        }
    }
    outputs
}

fn entry() -> ChatEntry {
    ChatEntry {
        seq: 7,
        outgoing: false,
        state: ChatEntryState::Received,
        timestamp_ms: 1_700_000_000_000,
        app_id: vec![0xA1, 0xA2],
        text: String::from_utf8(CANARY.to_vec()).unwrap(),
    }
}

#[test]
fn ffi_incoming_message_and_its_results_hide_the_plaintext() {
    let message = IncomingMessage {
        message_id: vec![0x11; 32],
        plaintext: CANARY.to_vec(),
    };
    for text in assert_redacted(&message) {
        assert!(text.contains("IncomingMessage") && text.contains("message_id"));
        assert!(text.contains("<redacted>"), "{text}");
    }
    // The enclosing results use the same `Debug`.
    assert_redacted(&ReceiveResult::Accepted {
        message: message.clone(),
    });
    for text in assert_redacted(&ReceiveResult::Duplicate {
        message_id: vec![0x11; 32],
        undelivered: Some(message),
    }) {
        assert!(text.contains("Duplicate") && text.contains("undelivered"));
    }
}

#[test]
fn received_text_hides_the_text() {
    let received = ReceivedText {
        message_id: vec![0x22; 32],
        text: CANARY.to_vec(),
    };
    for text in assert_redacted(&received) {
        assert!(text.contains("ReceivedText") && text.contains("message_id"));
        assert!(text.contains("<redacted>"), "{text}");
    }
}

#[test]
fn payload_hides_a_text_and_shows_the_rest() {
    let text = Payload::Text(zeroize::Zeroizing::new(CANARY.to_vec()));
    for shown in assert_redacted(&text) {
        assert!(
            shown.contains("Text") && shown.contains("<redacted>"),
            "{shown}"
        );
    }
    // A receipt carries public ids and `Open` carries nothing: both stay
    // readable, so the redaction is not a blanket one.
    let receipt = format!("{:?}", Payload::Receipt(vec![[0x33; 32]]));
    assert!(
        receipt.contains("Receipt") && receipt.contains("51"),
        "{receipt}"
    );
    assert_eq!(format!("{:?}", Payload::Open), "Open");
}

#[test]
fn chat_entry_and_conversation_hide_the_text_and_keep_the_metadata() {
    let e = entry();
    for text in assert_redacted(&e) {
        for shown in ["seq", "outgoing", "state", "timestamp_ms", "app_id"] {
            assert!(text.contains(shown), "{shown} missing from {text}");
        }
        assert!(text.contains("<redacted>"), "{text}");
    }
    // A conversation holds its last entry, so it is covered through it.
    let conversation = Conversation {
        peer: vec![0x44; 32],
        name: "Bob".into(),
        fingerprint: "ab:cd".into(),
        session: ChatSessionState::Established,
        identity_mismatch: false,
        handshake_refused: false,
        note: String::new(),
        unread: 1,
        last: Some(e),
    };
    for text in assert_redacted(&conversation) {
        assert!(text.contains("Bob") && text.contains("last"), "{text}");
    }
}

/// The values a real receive returns, not values built by hand: Bob decrypts a
/// message Alice sent and every result formatted afterwards is free of it.
#[test]
fn what_a_real_receive_returns_hides_the_plaintext() {
    let session_id: u64 = 21;
    let bob = fresh_core(61);
    bob.save_identity(Identity::generate()).unwrap();
    bob.establish_prekeys().unwrap();
    let bundle = bob.export_prekey_bundle().unwrap();
    let alice = fresh_core(62);
    alice.save_identity(Identity::generate()).unwrap();
    let handshake = alice
        .establish_session_initiator(session_id, bundle)
        .unwrap();
    bob.establish_session_responder(session_id, handshake)
        .unwrap();

    let sent = alice
        .send_message(session_id, b"c-1".to_vec(), CANARY.to_vec())
        .unwrap();
    assert_redacted(&sent); // ciphertext only, but it must not regress
    let wire = match sent {
        SendResult::Sent { message } => message.wire,
        other => panic!("expected Sent, got {other:?}"),
    };

    let received = bob.receive_message(session_id, wire.clone()).unwrap();
    assert_redacted(&received);
    let ReceiveResult::Accepted { message } = &received else {
        panic!("expected Accepted");
    };
    assert_eq!(
        message.plaintext, CANARY,
        "the application still gets the text"
    );

    // The same message again, and the pending list, through the exported API.
    assert_redacted(&bob.receive_message(session_id, wire).unwrap());
    let pending = bob.pending_incoming(session_id).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].plaintext, CANARY);
    assert_redacted(&pending);

    // The internal accessor the network layer uses returns the messenger's own
    // type, with the plaintext in a wiping owner, and the same bytes.
    fn wiping<T: ZeroizeOnDrop>(_: &T) {}
    let committed = bob.pending_committed(session_id).unwrap();
    assert_eq!(committed.len(), 1);
    wiping(&committed[0].plaintext);
    assert_eq!(committed[0].plaintext.as_slice(), CANARY);
    assert_redacted(&committed);
}
