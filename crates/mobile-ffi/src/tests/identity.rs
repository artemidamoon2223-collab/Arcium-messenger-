//! F-9: an identity that cannot be read is an error, never "no identity", and
//! `save_identity` creates an identity only where none is stored.
//!
//! Failures are injected through a second SQLite connection to the same file:
//! a lock held there makes this store's reads or writes fail, and editing the
//! stored ciphertext makes it fail authentication. No test prints key or
//! record bytes.

use super::*;
use rusqlite::Connection;
use std::sync::Barrier;

fn db_path() -> String {
    tempdir()
        .unwrap()
        .keep()
        .join("db")
        .to_str()
        .unwrap()
        .to_string()
}

/// Every stored row as raw bytes (`k`, `ek`, `v`), for "nothing changed".
fn raw_rows(path: &str) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let conn = Connection::open(path).unwrap();
    let mut stmt = conn.prepare("SELECT k, ek, v FROM kv ORDER BY k").unwrap();
    let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    rows
}

/// Flips one ciphertext byte of the only row, so it no longer authenticates.
fn corrupt_only_row(path: &str) {
    let conn = Connection::open(path).unwrap();
    let mut v: Vec<u8> = conn
        .query_row("SELECT v FROM kv", [], |r| r.get(0))
        .unwrap();
    v[30] ^= 0x01; // past the 24-byte nonce
    assert_eq!(
        conn.execute("UPDATE kv SET v = ?1", [v]).unwrap(),
        1,
        "exactly one row"
    );
}

/// A store holding one identity, written as every build so far writes it.
fn store_with_identity(byte: u8) -> (String, Arc<ArciumCore>, Vec<u8>) {
    let path = db_path();
    let core = ArciumCore::new(path.clone(), key32(byte)).unwrap();
    let id = Identity::generate();
    let pk = id.public_key_bytes();
    core.save_identity(id).unwrap();
    (path, core, pk)
}

fn loaded_pk(core: &ArciumCore) -> Vec<u8> {
    core.load_identity()
        .unwrap()
        .expect("identity stored")
        .public_key_bytes()
}

#[test]
fn a_record_written_in_the_existing_format_loads_with_the_same_keys() {
    // The 64-byte `identity/v1` record exactly as the previous `save_identity`
    // wrote it (signing secret, then X25519 secret), from fixed synthetic keys.
    let path = db_path();
    let (sk, dh) = ([0x11u8; 32], [0x22u8; 32]);
    {
        let store = EncryptedStore::open(&path, [7u8; 32]).unwrap();
        store.put(IDENTITY_KEY, &[sk, dh].concat()).unwrap();
    }
    let core = ArciumCore::new(path, key32(7)).unwrap();
    let id = core.load_identity().unwrap().expect("identity stored");
    assert_eq!(
        id.public_key_bytes(),
        SigningKey::from_bytes(&sk).verifying_key().to_bytes()
    );
    assert_eq!(
        id.dh_public_key_bytes(),
        PublicKey::from(&StaticSecret::from(dh)).to_bytes()
    );
}

#[test]
fn only_a_missing_record_is_no_identity() {
    let core = ArciumCore::new(db_path(), key32(1)).unwrap();
    assert!(matches!(core.load_identity(), Ok(None)));
    assert!(matches!(
        core.require_identity(),
        Err(CoreError::InvalidKey { msg }) if msg.starts_with("no identity saved")
    ));
}

#[test]
fn a_store_that_cannot_be_read_is_an_error_and_recovers_unchanged() {
    let (path, core, pk) = store_with_identity(2);
    let before = raw_rows(&path);

    // An exclusive lock on another connection: reads here wait out the busy
    // timeout and fail.
    let locker = Connection::open(&path).unwrap();
    locker.execute_batch("BEGIN EXCLUSIVE").unwrap();
    assert!(matches!(
        core.load_identity(),
        Err(CoreError::Storage { .. })
    ));
    assert!(matches!(
        core.require_identity(),
        Err(CoreError::Storage { .. })
    ));
    assert!(matches!(
        core.save_identity(Identity::generate()),
        Err(CoreError::Storage { .. })
    ));
    locker.execute_batch("ROLLBACK").unwrap();

    // The failure was transient: the same identity, nothing rewritten.
    assert_eq!(loaded_pk(&core), pk);
    assert_eq!(raw_rows(&path), before);
}

#[test]
fn require_identity_propagates_a_poisoned_mutex() {
    let (_path, core, _pk) = store_with_identity(3);
    let core2 = Arc::clone(&core);
    let _ = std::thread::spawn(move || {
        let _guard = core2.store.lock().unwrap();
        panic!("poison");
    })
    .join();
    assert!(matches!(
        core.require_identity(),
        Err(CoreError::Storage { .. })
    ));
}

#[test]
fn a_record_that_does_not_decrypt_is_unreadable_and_never_replaced() {
    let (path, core, _pk) = store_with_identity(4);
    corrupt_only_row(&path);
    let corrupt = raw_rows(&path);

    assert!(matches!(
        core.load_identity(),
        Err(CoreError::IdentityUnreadable { .. })
    ));
    assert!(matches!(
        core.require_identity(),
        Err(CoreError::IdentityUnreadable { .. })
    ));
    // Its existence cannot be confirmed, so creation fails rather than
    // reporting IdentityAlreadyExists — and writes nothing.
    assert!(core.save_identity(Identity::generate()).is_err());
    assert_eq!(raw_rows(&path), corrupt);
}

#[test]
fn a_record_of_the_wrong_length_is_unreadable_and_never_replaced() {
    for len in [0usize, 1, 32, 63, 65, 128] {
        let path = db_path();
        let core = ArciumCore::new(path.clone(), key32(5)).unwrap();
        let record = vec![0x5au8; len];
        core.store
            .lock()
            .unwrap()
            .put(IDENTITY_KEY, &record)
            .unwrap();
        let before = raw_rows(&path);

        assert!(
            matches!(
                core.load_identity(),
                Err(CoreError::IdentityUnreadable { .. })
            ),
            "length {len}"
        );
        assert!(
            core.save_identity(Identity::generate()).is_err(),
            "length {len}"
        );
        assert_eq!(raw_rows(&path), before, "length {len}");
        assert_eq!(
            core.store.lock().unwrap().get(IDENTITY_KEY).unwrap(),
            record,
            "length {len}"
        );
    }
}

#[test]
fn creating_in_an_empty_store_stores_exactly_that_identity() {
    let path = db_path();
    let core = ArciumCore::new(path.clone(), key32(6)).unwrap();
    let id = Identity::generate();
    let pk = id.public_key_bytes();
    core.save_identity(id).unwrap();
    assert_eq!(loaded_pk(&core), pk);
    assert_eq!(raw_rows(&path).len(), 1);
}

#[test]
fn creating_over_a_readable_identity_is_refused_and_changes_nothing() {
    let (path, core, pk) = store_with_identity(8);
    let before = raw_rows(&path);
    assert!(matches!(
        core.save_identity(Identity::generate()),
        Err(CoreError::IdentityAlreadyExists)
    ));
    assert_eq!(loaded_pk(&core), pk);
    assert_eq!(raw_rows(&path), before);
}

#[test]
fn concurrent_creators_store_at_most_one_identity() {
    for round in 0..10u8 {
        let path = db_path();
        // Two connections to one file (the cross-instance case), and two
        // threads on one of them (the in-process case).
        let a = ArciumCore::new(path.clone(), key32(9)).unwrap();
        let b = ArciumCore::new(path.clone(), key32(9)).unwrap();
        let creators = [a.clone(), b, a];
        let barrier = Arc::new(Barrier::new(creators.len()));
        let results: Vec<_> = creators
            .into_iter()
            .map(|core| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let id = Identity::generate();
                    let pk = id.public_key_bytes();
                    barrier.wait();
                    (pk, core.save_identity(id))
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();

        let winners: Vec<_> = results.iter().filter(|(_, r)| r.is_ok()).collect();
        assert_eq!(
            winners.len(),
            1,
            "round {round}: exactly one creation succeeds"
        );
        for (_, r) in results.iter().filter(|(_, r)| r.is_err()) {
            assert!(
                matches!(r, Err(CoreError::IdentityAlreadyExists)),
                "round {round}: a losing creator is refused, got {r:?}"
            );
        }
        let reader = ArciumCore::new(path.clone(), key32(9)).unwrap();
        assert_eq!(
            loaded_pk(&reader),
            winners[0].0,
            "round {round}: the winner is stored"
        );
        assert_eq!(raw_rows(&path).len(), 1, "round {round}");
    }
}

#[test]
fn a_failed_creation_reports_an_error_and_stores_nothing() {
    let path = db_path();
    let core = ArciumCore::new(path.clone(), key32(10)).unwrap();

    // Another writer holds the write lock: creation cannot begin.
    let writer = Connection::open(&path).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(matches!(
        core.save_identity(Identity::generate()),
        Err(CoreError::Storage { .. })
    ));
    writer.execute_batch("ROLLBACK").unwrap();

    assert!(matches!(core.load_identity(), Ok(None)), "no false success");
    assert!(raw_rows(&path).is_empty());
}
