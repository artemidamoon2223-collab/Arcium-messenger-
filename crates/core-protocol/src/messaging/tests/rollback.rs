//! What a rollback of one record does today, for the cases the Owner's
//! decision D-009 left unexamined (docs/S2-B2-DURABLE-MESSAGING.md, section
//! 8, "Rollback decision"): a rollback across a DH-ratchet step, the
//! receiver's records, and the `sendid:` record. The network layer's
//! receipts are in `mobile-ffi` (`tests::rollback`).
//!
//! These are characterization tests. Each records what the code does now,
//! not what it should do: D-009 says v1 resists neither whole-file nor
//! single-record rollback, and an attacker who can write the application's
//! storage is outside the v1 threat model. Nothing here changes that. A
//! change to rollback handling should fail a test here, and the test is
//! then rewritten together with that change, deliberately.
//!
//! A rollback is made by writing a record's earlier plaintext back through
//! the store, or deleting a record that did not exist yet. That reads the
//! same as writing back its earlier ciphertext, which is what an attacker
//! with write access would do: a value authenticates under its key name
//! only, with no version or counter (`core-storage`,
//! `a_record_written_back_with_its_earlier_ciphertext_reads_as_its_earlier_value`).

use super::*;

/// The record at `key` now, or `None` if there is none.
fn record(store: &EncryptedStore, key: &str) -> Option<Vec<u8>> {
    match store.get(key) {
        Ok(value) => Some(value),
        Err(StorageError::NotFound) => None,
        Err(e) => panic!("reading {key}: {e:?}"),
    }
}

/// Puts back what [`record`] read earlier.
fn write_back(store: &EncryptedStore, key: &str, earlier: &Option<Vec<u8>>) {
    match earlier {
        Some(value) => store.put(key, value).unwrap(),
        None => store.delete(key).unwrap(),
    }
}

fn header(m: &OutgoingMessage) -> Header {
    Header::from_bytes(&m.wire[..HEADER_SIZE]).unwrap()
}

fn refused(r: Result<Received, MessagingError>) {
    assert!(
        matches!(r, Err(MessagingError::Ratchet(RatchetError::Decryption))),
        "expected the message to fail to decrypt, got {r:?}"
    );
}

fn duplicate(r: Result<Received, MessagingError>) -> Option<IncomingMessage> {
    match r {
        Ok(Received::Duplicate { undelivered, .. }) => undelivered,
        other => panic!("expected Duplicate, got {other:?}"),
    }
}

// ── Across a DH-ratchet step ────────────────────────────────────────────────

/// Alice's session record goes back to before she took Bob's first message,
/// which carried his new ratchet key, and so to before her own DH step; Bob
/// has since taken a message on the chain that step began, so his own
/// chain now comes from Alice's ratchet key of after the step, which the
/// rollback took from her. In this state every message tried, two each way,
/// fails to decrypt, and a refused message commits nothing on either side.
/// Alice's next message takes position 1 of her old chain, which no message
/// of hers had used, only because she sent nothing more on that chain after
/// the moment rolled back to. (D-009's own experiment shows the case where
/// she had: a position used again, with its message key.) The next test is
/// a rollback across a step the peer has not yet answered, which the
/// session survives.
#[test]
fn a_sender_session_rolled_back_across_a_dh_step_its_peer_has_used_can_no_longer_talk_to_it() {
    let mut p = memory_peers();
    let a1 = p.alice_sends(b"a1");
    accepted(p.bob_receives(&a1.wire).unwrap());
    let b1 = p.bob_sends(b"b1");
    let key = session_storage_key(&p.bob_pk);
    let before_step = record(&p.a, &key);
    accepted(p.alice_receives(&b1.wire).unwrap());
    let a2 = p.alice_sends(b"a2");
    assert_ne!(
        header(&a2).dh,
        header(&a1).dh,
        "after the step Alice sends on a new chain"
    );
    accepted(p.bob_receives(&a2.wire).unwrap());
    for m in [&a1, &a2] {
        assert!(p
            .am
            .acknowledge_outgoing(&mut p.a, ALICE_HANDLE, &m.message_id)
            .unwrap());
    }
    assert_eq!(generation(&mut p.a, p.alice_pk, ALICE_HANDLE), 3);

    write_back(&p.a, &key, &before_step);
    assert_eq!(generation(&mut p.a, p.alice_pk, ALICE_HANDLE), 1);

    // b1 is still in Alice's inbox: it is a duplicate and moves nothing.
    assert!(duplicate(p.alice_receives(&b1.wire)).is_some());

    let bob_before = generation(&mut p.b, p.bob_pk, BOB_HANDLE);
    // Alice sends on her old chain again, at its next position.
    let a3 = p.alice_sends(b"a3");
    assert_eq!(a3.generation, 2);
    assert_eq!((header(&a3).dh, header(&a3).n), (header(&a1).dh, 1));
    refused(p.bob_receives(&a3.wire));
    // Bob's chain now comes from the ratchet key Alice made in her step,
    // which the rollback took from her.
    let b2 = p.bob_sends(b"b2");
    refused(p.alice_receives(&b2.wire));
    // And again.
    let a4 = p.alice_sends(b"a4");
    assert_eq!((header(&a4).dh, header(&a4).n), (header(&a1).dh, 2));
    refused(p.bob_receives(&a4.wire));
    let b3 = p.bob_sends(b"b3");
    refused(p.alice_receives(&b3.wire));

    // A refused message commits nothing: Alice's two sends are her only
    // commits since the rollback, and both wait in her outbox; Bob's only
    // commits are his own two sends.
    assert_eq!(generation(&mut p.a, p.alice_pk, ALICE_HANDLE), 3);
    assert_eq!(generation(&mut p.b, p.bob_pk, BOB_HANDLE), bob_before + 2);
    let pending: Vec<_> =
        p.am.pending_outgoing(&p.a, ALICE_HANDLE)
            .unwrap()
            .into_iter()
            .map(|m| m.message_id)
            .collect();
    assert_eq!(pending, vec![a3.message_id, a4.message_id]);
}

/// Bob's session record goes back to before he took a2, the first message on
/// Alice's chain after her DH step, which he had acknowledged; he had sent
/// nothing on the chain his own step began. The rollback passes unnoticed:
/// a2 is refused as a duplicate by its `seen:` record, Bob's next message
/// goes out on his old chain and Alice takes it, and Alice's next message
/// makes Bob step again and is taken. But the restored state can derive
/// a2's message key again: with the `seen:` record of a2 also gone, a2 is
/// accepted a second time.
#[test]
fn a_receiver_session_rolled_back_across_a_dh_step_it_had_not_answered_goes_on_unnoticed() {
    let mut p = memory_peers();
    let a1 = p.alice_sends(b"a1");
    accepted(p.bob_receives(&a1.wire).unwrap());
    let b1 = p.bob_sends(b"b1");
    accepted(p.alice_receives(&b1.wire).unwrap());
    let a2 = p.alice_sends(b"a2");
    assert_ne!(
        header(&a2).dh,
        header(&a1).dh,
        "a2 starts Alice's new chain"
    );
    let key = session_storage_key(&p.alice_pk);
    let before_step = record(&p.b, &key);
    let got = accepted(p.bob_receives(&a2.wire).unwrap());
    assert!(p
        .bm
        .acknowledge_incoming(&mut p.b, BOB_HANDLE, &got.message_id)
        .unwrap());

    write_back(&p.b, &key, &before_step);
    assert!(duplicate(p.bob_receives(&a2.wire)).is_none());
    let b2 = p.bob_sends(b"b2");
    assert_eq!(header(&b2).dh, header(&b1).dh, "Bob's old chain");
    assert_eq!(
        *accepted(p.alice_receives(&b2.wire).unwrap()).plaintext,
        b"b2"
    );
    let a3 = p.alice_sends(b"a3");
    assert_eq!(
        *accepted(p.bob_receives(&a3.wire).unwrap()).plaintext,
        b"a3"
    );
    let b3 = p.bob_sends(b"b3");
    assert_eq!(
        *accepted(p.alice_receives(&b3.wire).unwrap()).plaintext,
        b"b3"
    );

    write_back(&p.b, &seen_key(&p.alice_pk, &got.message_id), &None);
    let again = accepted(p.bob_receives(&a2.wire).unwrap());
    assert_eq!(*again.plaintext, b"a2", "a2 is shown to Bob a second time");
}

// ── The receiver's records ──────────────────────────────────────────────────

/// Bob's session record goes back to before he took m1, which he had
/// acknowledged. His `seen:` record of m1 still refuses m1 as a duplicate,
/// and the next message is taken as usual. But the restored state can derive
/// m1's message key again (taking m2 keeps it as a skipped key): with the
/// `seen:` record also gone, m1 is accepted a second time.
#[test]
fn a_receiver_session_rolled_back_past_an_acknowledged_message_is_held_by_its_seen_record_alone() {
    let mut p = memory_peers();
    let m1 = p.alice_sends(b"m1");
    let m2 = p.alice_sends(b"m2");
    let key = session_storage_key(&p.alice_pk);
    let before = record(&p.b, &key);
    let first = accepted(p.bob_receives(&m1.wire).unwrap());
    assert_eq!(first.generation, 1);
    assert!(p
        .bm
        .acknowledge_incoming(&mut p.b, BOB_HANDLE, &first.message_id)
        .unwrap());

    write_back(&p.b, &key, &before);
    assert_eq!(generation(&mut p.b, p.bob_pk, BOB_HANDLE), 0);
    assert!(duplicate(p.bob_receives(&m1.wire)).is_none());
    // m2 commits the generation m1 had committed.
    assert_eq!(accepted(p.bob_receives(&m2.wire).unwrap()).generation, 1);
    assert!(duplicate(p.bob_receives(&m1.wire)).is_none());
    // The session goes on: Bob's reply reaches Alice.
    let b1 = p.bob_sends(b"b1");
    assert_eq!(
        *accepted(p.alice_receives(&b1.wire).unwrap()).plaintext,
        b"b1"
    );

    write_back(&p.b, &seen_key(&p.alice_pk, &m1.message_id), &None);
    let again = accepted(p.bob_receives(&m1.wire).unwrap());
    assert_eq!(*again.plaintext, b"m1", "m1 is shown to Bob a second time");
}

/// Bob's inbox record of m1 is put back after he acknowledged m1. The
/// message is pending for the application again, beside the `seen:` record
/// that acknowledging wrote; acknowledging it again succeeds. The session
/// is not touched: delivery to the application is at least once by design,
/// and its message id is what tells a repeat.
#[test]
fn an_inbox_record_put_back_after_acknowledgement_makes_the_message_pending_again() {
    let mut p = memory_peers();
    let m1 = p.alice_sends(b"m1");
    let got = accepted(p.bob_receives(&m1.wire).unwrap());
    let key = inbox_key(&p.alice_pk, &got.message_id);
    let undelivered = record(&p.b, &key);
    assert!(p
        .bm
        .acknowledge_incoming(&mut p.b, BOB_HANDLE, &got.message_id)
        .unwrap());
    assert!(p.bm.pending_incoming(&p.b, BOB_HANDLE).unwrap().is_empty());
    let after = generation(&mut p.b, p.bob_pk, BOB_HANDLE);

    write_back(&p.b, &key, &undelivered);
    let pending = p.bm.pending_incoming(&p.b, BOB_HANDLE).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(*pending[0].plaintext, b"m1");
    let repeat = duplicate(p.bob_receives(&m1.wire)).expect("reported as undelivered");
    assert_eq!(repeat.message_id, got.message_id);
    assert!(p
        .bm
        .acknowledge_incoming(&mut p.b, BOB_HANDLE, &got.message_id)
        .unwrap());
    assert!(p.bm.pending_incoming(&p.b, BOB_HANDLE).unwrap().is_empty());
    assert_eq!(generation(&mut p.b, p.bob_pk, BOB_HANDLE), after);
}

/// Bob's `seen:` record of an acknowledged m1 is rolled back to absent. On
/// its own that lets nothing in: the session no longer holds m1's key, so a
/// replay fails to decrypt. With his session record rolled back too, which
/// is a rollback of everything Bob stored about m1, m1 is accepted again as
/// a new message.
#[test]
fn a_seen_record_rolled_back_alone_lets_no_replay_in_and_with_the_session_it_does() {
    let mut p = memory_peers();
    let m1 = p.alice_sends(b"m1");
    let session = session_storage_key(&p.alice_pk);
    let before = record(&p.b, &session);
    let got = accepted(p.bob_receives(&m1.wire).unwrap());
    assert!(p
        .bm
        .acknowledge_incoming(&mut p.b, BOB_HANDLE, &got.message_id)
        .unwrap());

    write_back(&p.b, &seen_key(&p.alice_pk, &got.message_id), &None);
    refused(p.bob_receives(&m1.wire));
    assert!(p.bm.pending_incoming(&p.b, BOB_HANDLE).unwrap().is_empty());

    write_back(&p.b, &session, &before);
    let again = accepted(p.bob_receives(&m1.wire).unwrap());
    assert_eq!((again.message_id, again.generation), (got.message_id, 1));
    assert_eq!(p.bm.pending_incoming(&p.b, BOB_HANDLE).unwrap().len(), 1);
}

// ── The `sendid:` record ────────────────────────────────────────────────────

/// Alice's `sendid:` record of a logical message is rolled back to absent,
/// whether the message is still pending, was acknowledged, or was abandoned.
/// Sending the same logical message again then encrypts it again: a second
/// message with its own id, at the next generation, and Bob accepts both.
/// The repeat-safe `send` (one logical id, one message) holds only while
/// that record does.
#[test]
fn a_send_id_record_rolled_back_makes_a_repeated_send_a_second_message() {
    for state in ["pending", "acknowledged", "abandoned"] {
        let mut p = memory_peers();
        let client_id = cid();
        let first = new_message(
            p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, &client_id, b"first")
                .unwrap(),
        );
        match state {
            "acknowledged" => assert!(p
                .am
                .acknowledge_outgoing(&mut p.a, ALICE_HANDLE, &first.message_id)
                .unwrap()),
            "abandoned" => assert!(p
                .am
                .abandon_outgoing(&mut p.a, ALICE_HANDLE, &first.message_id)
                .unwrap()),
            _ => {}
        }
        let key = sendid_key(&p.bob_pk, &client_id);
        assert!(record(&p.a, &key).is_some(), "{state}");

        write_back(&p.a, &key, &None);
        assert!(p
            .am
            .prior_send(&mut p.a, &p.bob_pk, &client_id)
            .unwrap()
            .is_none());
        let second = match p
            .am
            .send(&mut p.a, p.alice_pk, ALICE_HANDLE, &client_id, b"second")
            .unwrap()
        {
            SendOutcome::Sent(m) => m,
            other => panic!("{state}: expected a new message, got {other:?}"),
        };
        assert_ne!(second.message_id, first.message_id, "{state}");
        assert_eq!(second.generation, 2, "{state}");
        let pending = p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap().len();
        assert_eq!(pending, if state == "pending" { 2 } else { 1 }, "{state}");

        assert_eq!(
            *accepted(p.bob_receives(&first.wire).unwrap()).plaintext,
            b"first"
        );
        assert_eq!(
            *accepted(p.bob_receives(&second.wire).unwrap()).plaintext,
            b"second"
        );
    }
}

/// Abandoning rewrites the `sendid:` record and deletes the outbox record
/// together. With the `sendid:` record rolled back to its earlier form, which
/// names a message no longer in the outbox, a repeated send reports the
/// message as acknowledged, and nothing is encrypted.
#[test]
fn an_abandoned_send_whose_send_id_record_is_rolled_back_reads_as_acknowledged() {
    let mut p = memory_peers();
    let client_id = cid();
    let first = new_message(
        p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, &client_id, b"t")
            .unwrap(),
    );
    let key = sendid_key(&p.bob_pk, &client_id);
    let before = record(&p.a, &key);
    assert!(p
        .am
        .abandon_outgoing(&mut p.a, ALICE_HANDLE, &first.message_id)
        .unwrap());
    assert!(matches!(
        p.am.prior_send(&mut p.a, &p.bob_pk, &client_id).unwrap(),
        Some(SendOutcome::Abandoned { message_id }) if message_id == first.message_id
    ));

    write_back(&p.a, &key, &before);
    let generation_before = generation(&mut p.a, p.alice_pk, ALICE_HANDLE);
    for outcome in [
        p.am.prior_send(&mut p.a, &p.bob_pk, &client_id).unwrap(),
        Some(
            p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, &client_id, b"t")
                .unwrap(),
        ),
    ] {
        assert!(matches!(
            outcome,
            Some(SendOutcome::AlreadyAcknowledged { message_id }) if message_id == first.message_id
        ));
    }
    assert_eq!(
        generation(&mut p.a, p.alice_pk, ALICE_HANDLE),
        generation_before
    );
}
