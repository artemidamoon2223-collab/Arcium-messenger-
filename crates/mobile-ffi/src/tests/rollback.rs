//! What a rollback of one record of the receipt exchange does today: the
//! fourth case the Owner's decision D-009 left unexamined
//! (docs/S2-B2-DURABLE-MESSAGING.md, section 8, "network-layer receipts").
//! The other three are in `core-protocol` (`messaging::tests::rollback`).
//!
//! Characterization tests: each records what the code does now, not what it
//! should do. D-009 says v1 resists no rollback, and an attacker who can
//! write the application's storage is outside the v1 threat model. A record
//! is rolled back by writing its earlier plaintext back through the store,
//! or by deleting it where it did not exist yet; that reads the same as
//! writing back its earlier ciphertext (`core-storage`,
//! `a_record_written_back_with_its_earlier_ciphertext_reads_as_its_earlier_value`).
//!
//! Both devices read a fixed minute, so a receipt for a message the contact
//! sent again is limited to one per minute here as in use
//! (`NetworkMessenger::receipt_again`), whenever the tests run.

use super::net_harness::*;
use crate::network::wire::client_id;
use crate::network::SyncReport;

const MINUTE: u64 = 29_000_000;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn record(d: &Device, key: &str) -> Option<Vec<u8>> {
    match d.core.store.lock().unwrap().get(key) {
        Ok(value) => Some(value),
        Err(core_storage::StorageError::NotFound) => None,
        Err(e) => panic!("reading {key}: {e:?}"),
    }
}

fn write_back(d: &Device, key: &str, earlier: &Option<Vec<u8>>) {
    let store = d.core.store.lock().unwrap();
    match earlier {
        Some(value) => store.put(key, value).unwrap(),
        None => store.delete(key).unwrap(),
    }
}

/// The key of `from`'s outbox record of its message `id`.
fn outbox_key(from: &Device, id: &[u8]) -> String {
    let keys = from
        .core
        .store
        .lock()
        .unwrap()
        .list_keys_with_prefix("outbox:")
        .unwrap();
    let mut matching = keys.into_iter().filter(|k| k.ends_with(&hex(id)));
    let key = matching.next().expect("an outbox record of the message");
    assert!(matching.next().is_none());
    key
}

/// The key of the `sendid:` record of the receipt `round` for `peer`'s
/// message `id` (the layout of `core-protocol`'s `sendid_key`).
fn receipt_send_id_key(peer: &Device, id: &[u8], round: u64) -> String {
    let receipt = client_id::receipt(id.try_into().unwrap(), round);
    format!("sendid:v1/{}/{}", hex(&peer.pk), hex(&receipt))
}

/// Alice and Bob through `relay`, both on [`MINUTE`].
fn pair(relay: &str) -> (Device, Device) {
    let (alice, bob) = connected(relay);
    for d in [&alice, &bob] {
        d.net.set_minute(Some(MINUTE));
    }
    (alice, bob)
}

/// One sync of Alice, then one of Bob.
fn round(alice: &Device, bob: &Device) -> (SyncReport, SyncReport) {
    let (a, b) = (alice.sync(), bob.sync());
    assert!(
        a.errors.is_empty() && b.errors.is_empty(),
        "{:?} {:?}",
        a.errors,
        b.errors
    );
    (a, b)
}

/// Alice's text `hello` to Bob, settled: Bob has it, Alice has his receipt.
/// Returns its id and Alice's outbox record of it from before the receipt.
fn delivered_text(alice: &Device, bob: &Device) -> (Vec<u8>, String, Option<Vec<u8>>) {
    let id = alice.send(bob, "t1", "hello");
    let key = outbox_key(alice, &id);
    let pending = record(alice, &key);
    settle(&[alice, bob]);
    assert_eq!(alice.undelivered(bob), 0);
    assert_eq!(bob.texts(alice), ["hello"]);
    (id, key, pending)
}

/// Alice's outbox record of a delivered text is put back. She sends the text
/// again every round; Bob reports a duplicate and shows it once. He answers
/// a message sent again with a new receipt at most once per minute, and he
/// already spent this minute's on a retransmission while the devices
/// settled. So the text stays undelivered until the minute changes; then
/// one new receipt confirms it again and the devices settle.
#[test]
fn a_delivered_text_put_back_in_the_outbox_is_sent_again_until_a_new_receipt_confirms_it() {
    let relay = start_relay();
    let (alice, bob) = pair(&relay.addr().to_string());
    let (id, key, pending) = delivered_text(&alice, &bob);
    // The receipts Bob committed: the first one, and this minute's.
    for round in [0, MINUTE + 1] {
        assert!(record(&bob, &receipt_send_id_key(&alice, &id, round)).is_some());
    }

    write_back(&alice, &key, &pending);
    assert_eq!(alice.undelivered(&bob), 1);
    for _ in 0..3 {
        let (a, b) = round(&alice, &bob);
        assert!(a.published >= 1, "Alice sends the text again");
        assert_eq!((b.duplicates, b.accepted, b.published), (1, 0, 0));
        assert_eq!(alice.undelivered(&bob), 1);
    }

    bob.net.set_minute(Some(MINUTE + 1));
    let (_, b) = round(&alice, &bob);
    assert_eq!((b.duplicates, b.published), (1, 1), "a new receipt");
    let (a, _) = round(&alice, &bob);
    assert_eq!((a.accepted, a.delivered), (1, 1));
    assert_eq!(alice.undelivered(&bob), 0);
    settle(&[&alice, &bob]);
    assert_eq!(bob.texts(&alice), ["hello"]);
}

/// Bob's `sendid:` record of his receipt for a text is rolled back to
/// absent. While the text is unread, it is still in his inbox, so his next
/// round answers it again: a second receipt message, which Alice accepts
/// and which confirms nothing new. Once Bob has read the text, the rollback
/// shows nothing by itself; but a message he no longer has a receipt record
/// for is not answered again (`receipt_again` stops at the missing record
/// before it reads the minute). With Alice's outbox record of the text put
/// back, which is also what she holds if Bob's receipt never reached her,
/// she sends it every round, Bob reports a duplicate every round, and the
/// text stays undelivered for her in each of the three later minutes tried.
#[test]
fn a_receipt_send_id_rolled_back_answers_again_while_unread_and_never_once_read() {
    let relay = start_relay();
    let addr = relay.addr().to_string();

    // Unread.
    let (alice, bob) = pair(&addr);
    let (id, _, _) = delivered_text(&alice, &bob);
    let key = receipt_send_id_key(&alice, &id, 0);
    assert!(
        record(&bob, &key).is_some(),
        "the key layout no longer matches"
    );
    write_back(&bob, &key, &None);
    let (_, b) = round(&alice, &bob);
    assert_eq!(b.published, 1, "a second receipt");
    assert!(record(&bob, &key).is_some());
    let (a, _) = round(&alice, &bob);
    assert_eq!((a.accepted, a.delivered), (1, 0));
    settle(&[&alice, &bob]);
    assert_eq!(alice.undelivered(&bob), 0);

    // Read.
    let (alice, bob) = pair(&addr);
    let (id, text_key, pending) = delivered_text(&alice, &bob);
    assert!(bob.net.mark_read(alice.pk.clone(), id.clone()).unwrap());
    let key = receipt_send_id_key(&alice, &id, 0);
    assert!(
        record(&bob, &key).is_some(),
        "the key layout no longer matches"
    );
    write_back(&bob, &key, &None);
    settle(&[&alice, &bob]);
    assert!(record(&bob, &key).is_none());

    write_back(&alice, &text_key, &pending);
    // From the next minute on: this minute's later receipt was already
    // spent while the devices settled, so a round in it shows nothing.
    for minute in MINUTE + 1..MINUTE + 4 {
        for d in [&alice, &bob] {
            d.net.set_minute(Some(minute));
        }
        let (a, b) = round(&alice, &bob);
        assert!(a.published >= 1, "Alice sends the text again");
        assert_eq!((b.duplicates, b.published), (1, 0), "minute {minute}");
        assert_eq!(alice.undelivered(&bob), 1);
    }
    assert!(bob.texts(&alice).is_empty(), "read, and not shown again");
}
