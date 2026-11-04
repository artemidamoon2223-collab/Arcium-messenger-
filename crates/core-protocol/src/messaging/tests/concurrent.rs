//! Two connections on one database file (two cores on the same store, as an
//! app with a second process or handle would have).

use super::*;
use crate::messaging::helpers::prior_send_hook;
use std::sync::{Arc, Mutex};

/// Another connection abandons the message between the two reads of
/// `prior_send` (a test hook runs it there). With both reads in one
/// transaction the other connection waits (and here gives up after the
/// store's busy timeout), so the answer is the state before the abandonment,
/// never "acknowledged". Read again afterwards, it is "abandoned".
#[test]
fn an_abandonment_from_another_connection_is_never_read_as_an_acknowledgement() {
    for via_send in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.db");
        let mut p = setup(
            EncryptedStore::open(&path, KEY).unwrap(),
            EncryptedStore::open(dir.path().join("b.db"), KEY).unwrap(),
        );
        let m = new_message(p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, b"L", b"x").unwrap());
        let other = Arc::new(Mutex::new((EncryptedStore::open(&path, KEY).unwrap(), Messenger::new())));
        let (o, id) = (other.clone(), m.message_id);
        let outcome = Arc::new(Mutex::new(None));
        let seen = outcome.clone();
        prior_send_hook::set(move || {
            let (store, messenger) = &mut *o.lock().unwrap();
            *seen.lock().unwrap() = Some(messenger.abandon_outgoing(store, ALICE_HANDLE, &id).is_ok());
        });
        let read = if via_send {
            p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, b"L", b"x").unwrap()
        } else {
            p.am.prior_send(&mut p.a, &p.bob_pk, b"L").unwrap().unwrap()
        };
        assert!(
            !matches!(read, SendOutcome::AlreadyAcknowledged { .. }),
            "via_send={via_send}: an abandoned message read as acknowledged"
        );
        assert!(matches!(read, SendOutcome::AlreadyPending(_)), "via_send={via_send}: {read:?}");
        assert_eq!(*outcome.lock().unwrap(), Some(false), "the other connection had to wait");
        let (store, messenger) = &mut *other.lock().unwrap();
        assert!(messenger.abandon_outgoing(store, ALICE_HANDLE, &m.message_id).unwrap());
        assert_eq!(
            p.am.prior_send(&mut p.a, &p.bob_pk, b"L").unwrap(),
            Some(SendOutcome::Abandoned { message_id: m.message_id })
        );
    }
}

/// The same race with real threads, many times: one connection sends and
/// abandons, the other keeps asking about the message being abandoned.
/// "Acknowledged" never appears: nothing in this run acknowledges anything.
#[test]
fn concurrent_abandonments_are_never_read_as_acknowledgements() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.db");
    let p = setup(
        EncryptedStore::open(&path, KEY).unwrap(),
        EncryptedStore::open(dir.path().join("b.db"), KEY).unwrap(),
    );
    let (alice_pk, bob_pk) = (p.alice_pk, p.bob_pk);
    drop(p);
    let n = 300;
    let current = Arc::new(AtomicUsize::new(usize::MAX));
    let cur = current.clone();
    let writer = std::thread::spawn(move || {
        let mut store = EncryptedStore::open(&path, KEY).unwrap();
        let mut m = Messenger::new();
        for k in 0..n {
            let cid = format!("c{k}").into_bytes();
            // NotCommitted (the reader holds the store) rolled back: repeat.
            let sent = loop {
                match m.send(&mut store, alice_pk, ALICE_HANDLE, &cid, b"x") {
                    Ok(o) => break new_message(o),
                    Err(MessagingError::NotCommitted(_) | MessagingError::Store(_)) => {}
                    Err(e) => panic!("{e:?}"),
                }
            };
            cur.store(k, Ordering::SeqCst);
            std::thread::yield_now();
            loop {
                match m.abandon_outgoing(&mut store, ALICE_HANDLE, &sent.message_id) {
                    Ok(_) => break,
                    Err(MessagingError::NotCommitted(_) | MessagingError::Store(_)) => {}
                    Err(e) => panic!("{e:?}"),
                }
            }
        }
    });
    let mut store = EncryptedStore::open(dir.path().join("a.db"), KEY).unwrap();
    let reader = Messenger::new();
    let (mut reads, mut acked) = (0, 0);
    while !writer.is_finished() {
        let k = current.load(Ordering::SeqCst);
        if k == usize::MAX {
            continue;
        }
        match reader.prior_send(&mut store, &bob_pk, format!("c{k}").as_bytes()) {
            Ok(Some(SendOutcome::AlreadyAcknowledged { .. })) => acked += 1,
            Ok(_) => reads += 1,
            Err(MessagingError::Store(_)) => {} // busy: the writer holds the store
            Err(e) => panic!("{e:?}"),
        }
        std::thread::sleep(std::time::Duration::from_micros(50));
    }
    writer.join().unwrap();
    assert_eq!(acked, 0, "{acked} of {} reads saw an abandoned message as acknowledged", reads + acked);
    assert!(reads > 0);
}
