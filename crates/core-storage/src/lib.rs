//! `core-storage` — encrypted key-value store on top of SQLite.
//!
//! Each value is encrypted with XChaCha20-Poly1305 using a key derived from
//! the user's master key + the storage key (so the same plaintext under two
//! different keys produces different ciphertexts).
//!
//! ## Local-attacker model (F-10)
//!
//! This store defends against an attacker who obtains the SQLite file (disk
//! theft, backup leak) but does not have the master key: values are
//! authenticated-encrypted per-key, and key *names* are stored only as a
//! master-key-derived hash (see `storage_key`/`key_name_hash`) rather than
//! plaintext, so the file no longer reveals which logical keys exist (e.g.
//! a `contact:`/`session:` naming convention would otherwise expose the
//! contact graph directly). `PRAGMA secure_delete = ON` makes SQLite
//! overwrite a row's on-disk bytes with zeros on `DELETE`/`UPDATE` instead
//! of just unlinking it, closing the "old ciphertext survives in the
//! freelist/WAL after delete" gap. Not defended (explicitly out of scope
//! for this fix, per the review): row-count and ciphertext-length metadata,
//! and rollback protection against an attacker with disk *write* access —
//! those remain optional hardening for a future audit.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection, Transaction, TransactionBehavior};
use sha2::Sha256;
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroize;

const NONCE_SIZE: usize = 24;
const NAME_HASH_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("decryption failed (wrong key or corrupted data)")]
    Decryption,
    #[error("key not found")]
    NotFound,
}

pub struct EncryptedStore {
    conn: Connection,
    keys: KeyMaterial,
}

/// The master key and every derivation made from it. Split out of
/// `EncryptedStore` so that a transaction can borrow the key material while
/// holding the connection mutably; the derivation bodies are unchanged.
struct KeyMaterial {
    master_key: [u8; 32],
}

impl EncryptedStore {
    pub fn open<P: AsRef<Path>>(path: P, master_key: [u8; 32]) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;
        Self::init(conn, master_key)
    }

    pub fn open_in_memory(master_key: [u8; 32]) -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn, master_key)
    }

    fn init(conn: Connection, master_key: [u8; 32]) -> Result<Self, StorageError> {
        conn.execute_batch(
            "PRAGMA secure_delete = ON;
             CREATE TABLE IF NOT EXISTS kv (
                k BLOB PRIMARY KEY,
                ek BLOB NOT NULL,
                v BLOB NOT NULL
            );",
        )?;
        Ok(Self {
            conn,
            keys: KeyMaterial { master_key },
        })
    }

    pub fn put(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        put_row(&self.conn, &self.keys, key, value)
    }

    pub fn get(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        get_row(&self.conn, &self.keys, key)
    }

    pub fn delete(&self, key: &str) -> Result<(), StorageError> {
        delete_row(&self.conn, &self.keys, key)
    }

    /// Begins a transaction over several records. Every `put`/`delete` made
    /// through it becomes durable together on [`StoreTransaction::commit`], or
    /// not at all.
    ///
    /// Takes `&mut self`, so while the transaction is alive nothing else can
    /// write through this store — the borrow checker rules out a stray `put`
    /// landing outside it, and a nested transaction on the same connection.
    ///
    /// # Begin mode
    ///
    /// `BEGIN IMMEDIATE`: the write lock is taken at `BEGIN`, not at the first
    /// write. The store runs in SQLite's rollback-journal mode, where a
    /// deferred transaction that reads first and writes later can fail its lock
    /// upgrade with `SQLITE_BUSY` *without* the busy handler being consulted, in
    /// the middle of the work. Taking the lock up front means a transaction
    /// either cannot start or runs to its commit; it never dies half-way over a
    /// lock another connection holds.
    ///
    /// # Contention
    ///
    /// No busy handling is configured here. The connection keeps the timeout
    /// `rusqlite` applies when it opens a connection (5000 ms), so `BEGIN`
    /// waits up to that long for another connection's write transaction and
    /// then fails with [`StorageError::Db`] carrying `SQLITE_BUSY`. Nothing is
    /// written in that case. Retrying is the caller's decision.
    ///
    /// # What not to do while it is open
    ///
    /// The write lock blocks every other writer to this database file until
    /// commit or rollback. Do not hold a transaction across a JNI/Android
    /// callback, a network operation, or anything else whose duration this
    /// code does not control: build the records first, then open, write,
    /// commit.
    pub fn transaction(&mut self) -> Result<StoreTransaction<'_>, StorageError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        Ok(StoreTransaction {
            tx,
            keys: &self.keys,
        })
    }

    /// Lists the real key names sharing `prefix`'s namespace. `prefix` is
    /// matched as an exact namespace, not an arbitrary substring: since
    /// stored keys are hashed (F-10), only a `prefix` that equals the
    /// namespace a key was written under (everything up to and including
    /// its first `:`, or the whole key if it has none) can match — the
    /// same convention `namespace_of` uses when writing.
    pub fn list_keys_with_prefix(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        let ns_hash = self.keys.key_name_hash(prefix);
        let mut stmt = self
            .conn
            .prepare("SELECT ek FROM kv WHERE substr(k, 1, ?1) = ?2 ORDER BY k")?;
        let rows: Result<Vec<Vec<u8>>, _> = stmt
            .query_map(params![NAME_HASH_LEN as i64, ns_hash.as_slice()], |r| {
                r.get::<_, Vec<u8>>(0)
            })?
            .collect();
        let mut keys: Vec<String> = rows?
            .into_iter()
            .map(|ek| self.keys.decrypt_key_name(&ek))
            .collect::<Result<_, _>>()?;
        keys.sort();
        Ok(keys)
    }

    /// Test-only shortcut to the lookup key a record is stored under.
    #[cfg(test)]
    fn storage_key(&self, key: &str) -> Vec<u8> {
        self.keys.storage_key(key)
    }
}

impl KeyMaterial {
    /// Everything up to and including the first `:` — the "namespace" a
    /// group of keys (`contact:alice`, `contact:bob`, ...) shares. A key
    /// with no `:` is its own namespace.
    fn namespace_of(key: &str) -> &str {
        match key.find(':') {
            Some(idx) => &key[..=idx],
            None => key,
        }
    }

    /// Master-key-derived, deterministic pseudorandom digest of `s` — used
    /// both to hash a full key name and (on the same input space) its
    /// namespace, so equal inputs always hash identically and prefix
    /// listing stays possible without storing plaintext key names (F-10).
    fn key_name_hash(&self, s: &str) -> [u8; NAME_HASH_LEN] {
        let hk = Hkdf::<Sha256>::new(Some(b"core-storage/key-name-hash/v1"), &self.master_key);
        let mut out = [0u8; NAME_HASH_LEN];
        hk.expand(s.as_bytes(), &mut out).expect("hkdf expand");
        out
    }

    /// The actual primary-key bytes stored in `kv.k`: the key's namespace
    /// hash followed by its own full-key hash (both fixed-length, so no
    /// separator is needed). The namespace component lets
    /// `list_keys_with_prefix` find every key sharing it; the full-key
    /// component keeps different keys under the same namespace distinct.
    fn storage_key(&self, key: &str) -> Vec<u8> {
        let ns_hash = self.key_name_hash(Self::namespace_of(key));
        let full_hash = self.key_name_hash(key);
        let mut out = Vec::with_capacity(NAME_HASH_LEN * 2);
        out.extend_from_slice(&ns_hash);
        out.extend_from_slice(&full_hash);
        out
    }

    /// Fixed (not per-key) subkey for encrypting key *names* themselves —
    /// domain-separated from both the per-value subkeys (`subkey`) and the
    /// key-name hash (`key_name_hash`) via distinct HKDF info strings.
    fn key_name_encryption_subkey(&self) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(b"core-storage/key-name-enc/v1"), &self.master_key);
        let mut sk = [0u8; 32];
        hk.expand(&[], &mut sk).expect("hkdf expand");
        sk
    }

    /// Encrypts `key` itself so `list_keys_with_prefix` can recover the
    /// real key names of a matched namespace without the DB file storing
    /// them in plaintext.
    fn encrypt_key_name(&self, key: &str) -> Vec<u8> {
        let mut sk = self.key_name_encryption_subkey();
        let cipher = XChaCha20Poly1305::new((&sk).into());
        let mut nonce = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt((&nonce).into(), key.as_bytes())
            .expect("encryption with a valid key/nonce cannot fail");
        sk.zeroize();
        let mut out = Vec::with_capacity(NONCE_SIZE + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    fn decrypt_key_name(&self, ct_with_nonce: &[u8]) -> Result<String, StorageError> {
        if ct_with_nonce.len() < NONCE_SIZE {
            return Err(StorageError::Decryption);
        }
        let (nonce, ct) = ct_with_nonce.split_at(NONCE_SIZE);
        let mut sk = self.key_name_encryption_subkey();
        let cipher = XChaCha20Poly1305::new((&sk).into());
        let pt = cipher
            .decrypt(nonce.into(), ct)
            .map_err(|_| StorageError::Decryption)?;
        sk.zeroize();
        String::from_utf8(pt).map_err(|_| StorageError::Decryption)
    }

    fn subkey(&self, key: &str) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(b"core-storage/v1"), &self.master_key);
        let mut sk = [0u8; 32];
        hk.expand(key.as_bytes(), &mut sk).expect("hkdf expand");
        sk
    }

    fn encrypt(&self, key: &str, plaintext: &[u8]) -> Result<Vec<u8>, StorageError> {
        let sk = self.subkey(key);
        let cipher = XChaCha20Poly1305::new((&sk).into());
        let mut nonce = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: key.as_bytes(),
                },
            )
            .map_err(|_| StorageError::Decryption)?;
        let mut out = Vec::with_capacity(NONCE_SIZE + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        let mut sk = sk;
        sk.zeroize();
        Ok(out)
    }

    fn decrypt(&self, key: &str, ct_with_nonce: &[u8]) -> Result<Vec<u8>, StorageError> {
        if ct_with_nonce.len() < NONCE_SIZE {
            return Err(StorageError::Decryption);
        }
        let (nonce, ct) = ct_with_nonce.split_at(NONCE_SIZE);
        let sk = self.subkey(key);
        let cipher = XChaCha20Poly1305::new((&sk).into());
        let pt = cipher
            .decrypt(
                nonce.into(),
                Payload {
                    msg: ct,
                    aad: key.as_bytes(),
                },
            )
            .map_err(|_| StorageError::Decryption)?;
        let mut sk = sk;
        sk.zeroize();
        Ok(pt)
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        self.master_key.zeroize();
    }
}

// ── Row operations ──────────────────────────────────────────────────────────
//
// One implementation of each, shared by the store and by transactions. A
// `Transaction` dereferences to `Connection`, so both paths run exactly the same
// statements and produce exactly the same on-disk encoding — there is no second
// encoder to drift out of step with the first.

fn put_row(
    conn: &Connection,
    keys: &KeyMaterial,
    key: &str,
    value: &[u8],
) -> Result<(), StorageError> {
    let ct = keys.encrypt(key, value)?;
    let sk = keys.storage_key(key);
    let ek = keys.encrypt_key_name(key);
    conn.execute(
        "INSERT INTO kv (k, ek, v) VALUES (?1, ?2, ?3)
         ON CONFLICT(k) DO UPDATE SET v = excluded.v",
        params![sk, ek, ct],
    )?;
    Ok(())
}

fn get_row(conn: &Connection, keys: &KeyMaterial, key: &str) -> Result<Vec<u8>, StorageError> {
    let sk = keys.storage_key(key);
    let row: Vec<u8> = conn
        .query_row("SELECT v FROM kv WHERE k = ?1", params![sk], |r| r.get(0))
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound,
            other => StorageError::Db(other),
        })?;
    keys.decrypt(key, &row)
}

fn delete_row(conn: &Connection, keys: &KeyMaterial, key: &str) -> Result<(), StorageError> {
    let sk = keys.storage_key(key);
    conn.execute("DELETE FROM kv WHERE k = ?1", params![sk])?;
    Ok(())
}

// ── Transactions ────────────────────────────────────────────────────────────

/// A multi-record transaction, from [`EncryptedStore::transaction`].
///
/// Records are encrypted exactly as [`EncryptedStore::put`] encrypts them; the
/// transaction changes when writes become visible, never how they are stored.
///
/// Nothing written here is visible to any other connection before
/// [`commit`](Self::commit). Reads through the transaction see its own writes.
///
/// **Dropping it without committing rolls every write back.** That includes
/// leaving a function early with `?` after a failed operation: the records
/// written before the failure are discarded with it.
pub struct StoreTransaction<'a> {
    tx: Transaction<'a>,
    keys: &'a KeyMaterial,
}

impl StoreTransaction<'_> {
    /// Inserts `key`, or replaces its value if it already exists.
    pub fn put(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        put_row(&self.tx, self.keys, key, value)
    }

    /// Reads `key` as this transaction currently sees it, including writes made
    /// earlier in the same transaction.
    pub fn get(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        get_row(&self.tx, self.keys, key)
    }

    /// Deletes `key`. Deleting a key that does not exist is not an error, as
    /// with [`EncryptedStore::delete`].
    pub fn delete(&self, key: &str) -> Result<(), StorageError> {
        delete_row(&self.tx, self.keys, key)
    }

    /// Makes every write in the transaction durable at once.
    ///
    /// If the commit itself fails, the transaction is rolled back and none of
    /// its writes are kept.
    pub fn commit(self) -> Result<(), StorageError> {
        self.tx.commit()?;
        Ok(())
    }

    /// Discards every write in the transaction. Equivalent to dropping it,
    /// but reports an error instead of swallowing it.
    pub fn rollback(self) -> Result<(), StorageError> {
        self.tx.rollback()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};
    use tempfile::tempdir;

    fn random_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        k
    }

    #[test]
    fn put_and_get_round_trip() {
        let store = EncryptedStore::open_in_memory(random_key()).unwrap();
        store.put("contact:alice", b"alice public key bytes").unwrap();
        let got = store.get("contact:alice").unwrap();
        assert_eq!(got, b"alice public key bytes");
    }

    #[test]
    fn missing_key_is_not_found() {
        let store = EncryptedStore::open_in_memory(random_key()).unwrap();
        match store.get("nope") {
            Err(StorageError::NotFound) => {}
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    #[test]
    fn overwrite_replaces_value() {
        let store = EncryptedStore::open_in_memory(random_key()).unwrap();
        store.put("session:bob", b"first").unwrap();
        store.put("session:bob", b"second").unwrap();
        assert_eq!(store.get("session:bob").unwrap(), b"second");
    }

    #[test]
    fn delete_removes_key() {
        let store = EncryptedStore::open_in_memory(random_key()).unwrap();
        store.put("k", b"v").unwrap();
        store.delete("k").unwrap();
        assert!(matches!(store.get("k"), Err(StorageError::NotFound)));
    }

    #[test]
    fn list_keys_with_prefix_works() {
        let store = EncryptedStore::open_in_memory(random_key()).unwrap();
        store.put("contact:alice", b"a").unwrap();
        store.put("contact:bob", b"b").unwrap();
        store.put("session:bob", b"s").unwrap();
        let mut contacts = store.list_keys_with_prefix("contact:").unwrap();
        contacts.sort();
        assert_eq!(contacts, vec!["contact:alice", "contact:bob"]);
    }

    #[test]
    fn list_keys_with_prefix_percent_is_literal() {
        let store = EncryptedStore::open_in_memory(random_key()).unwrap();
        store.put("a%b:foo", b"target").unwrap();
        store.put("axb:bar", b"should not match").unwrap();
        let keys = store.list_keys_with_prefix("a%b:").unwrap();
        assert_eq!(keys, vec!["a%b:foo"], "% in prefix must be treated literally");
    }

    #[test]
    fn list_keys_with_prefix_underscore_is_literal() {
        let store = EncryptedStore::open_in_memory(random_key()).unwrap();
        store.put("a_b:foo", b"target").unwrap();
        store.put("axb:bar", b"should not match").unwrap();
        let keys = store.list_keys_with_prefix("a_b:").unwrap();
        assert_eq!(keys, vec!["a_b:foo"], "_ in prefix must be treated literally");
    }

    #[test]
    fn wrong_master_key_cannot_read_value() {
        // F-10 behavior note: storage_key() now derives the lookup hash
        // from master_key too (not just the value's encryption subkey), so
        // a wrong master key can no longer even find the row — it's
        // NotFound, not Decryption as it was when key names were stored
        // in plaintext. This is a strict privacy improvement: previously a
        // wrong-key caller learned "a row with this exact name exists but
        // won't decrypt"; now it learns nothing. Callers never distinguish
        // the two (see mobile-ffi's load_identity, which already treats
        // both as "no identity" — F-9), so this changes no behavior above
        // this crate. Either way, the value must not be readable.
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let key1 = random_key();
        {
            let store = EncryptedStore::open(&path, key1).unwrap();
            store.put("secret", b"top secret value").unwrap();
        }
        let key2 = random_key();
        let store = EncryptedStore::open(&path, key2).unwrap();
        match store.get("secret") {
            Err(StorageError::NotFound) | Err(StorageError::Decryption) => {}
            other => panic!("expected NotFound or Decryption, got {:?}", other),
        }
    }

    #[test]
    fn data_persists_across_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let key = random_key();
        {
            let store = EncryptedStore::open(&path, key).unwrap();
            store.put("contact:alice", b"persistent value").unwrap();
        }
        let store = EncryptedStore::open(&path, key).unwrap();
        assert_eq!(store.get("contact:alice").unwrap(), b"persistent value");
    }

    #[test]
    fn each_key_has_its_own_subkey() {
        let store = EncryptedStore::open_in_memory(random_key()).unwrap();
        store.put("a", b"same value").unwrap();
        store.put("b", b"same value").unwrap();
        let ct_a: Vec<u8> = store
            .conn
            .query_row(
                "SELECT v FROM kv WHERE k = ?1",
                params![store.storage_key("a")],
                |r| r.get(0),
            )
            .unwrap();
        let ct_b: Vec<u8> = store
            .conn
            .query_row(
                "SELECT v FROM kv WHERE k = ?1",
                params![store.storage_key("b")],
                |r| r.get(0),
            )
            .unwrap();
        assert_ne!(ct_a, ct_b, "subkeys must produce different ciphertexts");
    }

    // ── F-10 regression: key names are no longer stored in plaintext ──

    #[test]
    fn key_names_are_not_stored_in_plaintext() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let store = EncryptedStore::open(&path, random_key()).unwrap();
        store.put("contact:alice", b"alice's key material").unwrap();
        drop(store);

        // Read the raw file bytes directly, bypassing the store entirely —
        // an attacker with just the file, no master key.
        let raw = std::fs::read(&path).unwrap();
        let raw_lossy = String::from_utf8_lossy(&raw);
        assert!(
            !raw_lossy.contains("contact:alice"),
            "the plaintext key name must not appear anywhere in the raw DB file"
        );
        assert!(
            !raw_lossy.contains("alice's key material"),
            "the plaintext value must not appear anywhere in the raw DB file either"
        );
    }

    #[test]
    fn same_key_name_hashes_identically_across_instances() {
        // storage_key is a pure function of (master_key, key name) — reopening
        // the same store must compute the same lookup key, or nothing already
        // written would ever be found again.
        let key = random_key();
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        {
            let store = EncryptedStore::open(&path, key).unwrap();
            store.put("identity/v1", b"identity bytes").unwrap();
        }
        let store = EncryptedStore::open(&path, key).unwrap();
        assert_eq!(store.get("identity/v1").unwrap(), b"identity bytes");
    }

    #[test]
    fn list_keys_with_prefix_does_not_match_partial_non_namespace_prefix() {
        // Prefix matching is now exact-namespace, not arbitrary-substring:
        // "cont" is not the namespace "contact:" was written under, so it
        // must not match — documents the F-10 semantic change explicitly.
        let store = EncryptedStore::open_in_memory(random_key()).unwrap();
        store.put("contact:alice", b"a").unwrap();
        assert_eq!(
            store.list_keys_with_prefix("cont").unwrap(),
            Vec::<String>::new(),
            "a prefix that isn't the full namespace must not match"
        );
        assert_eq!(
            store.list_keys_with_prefix("contact:").unwrap(),
            vec!["contact:alice"]
        );
    }

    // ── F-10 regression: secure_delete removes the value ──

    #[test]
    fn deleted_value_is_not_recoverable_via_get() {
        let store = EncryptedStore::open_in_memory(random_key()).unwrap();
        store.put("k", b"sensitive").unwrap();
        store.delete("k").unwrap();
        assert!(matches!(store.get("k"), Err(StorageError::NotFound)));
    }

    #[test]
    fn secure_delete_pragma_is_enabled() {
        let store = EncryptedStore::open_in_memory(random_key()).unwrap();
        let mode: i64 = store
            .conn
            .query_row("PRAGMA secure_delete", [], |r| r.get(0))
            .unwrap();
        // SQLite reports secure_delete as 0/1 (or 2 for FAST mode); ON
        // must not be the default-off 0.
        assert_ne!(mode, 0, "secure_delete must be enabled, not left at the SQLite default");
    }

    #[test]
    fn deleted_row_bytes_are_overwritten_on_disk() {
        // With secure_delete=ON, SQLite zeroes a deleted row's on-disk
        // content instead of just unlinking it. Capture the actual stored
        // ciphertext bytes (high-entropy and effectively unique thanks to
        // the random per-encryption nonce) and confirm they no longer
        // appear anywhere in the raw file after delete.
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let store = EncryptedStore::open(&path, random_key()).unwrap();
        store.put("k", b"sensitive value").unwrap();

        let stored_ct: Vec<u8> = store
            .conn
            .query_row(
                "SELECT v FROM kv WHERE k = ?1",
                params![store.storage_key("k")],
                |r| r.get(0),
            )
            .unwrap();
        assert!(stored_ct.len() >= 16, "sanity: ciphertext should be non-trivial");

        store.delete("k").unwrap();
        drop(store);

        let raw = std::fs::read(&path).unwrap();
        assert!(
            !raw.windows(stored_ct.len()).any(|w| w == stored_ct.as_slice()),
            "the deleted row's ciphertext bytes must not survive anywhere in the raw file \
             once secure_delete has zeroed the freed page"
        );
    }

    // ── S1: multi-record transactions ──────────────────────────────────────
    //
    // Three failure kinds are exercised separately and must not be conflated:
    // an ordinary rollback (the transaction is dropped or rolled back in a
    // live process), a process that dies mid-transaction (no destructor runs,
    // SQLite recovers from its hot journal on the next open), and physical
    // power loss. The last is NOT tested anywhere here — a process-termination
    // test says nothing about whether the device's storage honoured fsync.

    use std::time::Duration;

    fn file_store(dir: &std::path::Path, key: [u8; 32]) -> EncryptedStore {
        EncryptedStore::open(dir.join("store.db"), key).unwrap()
    }

    fn assert_absent(store: &EncryptedStore, key: &str) {
        assert!(
            matches!(store.get(key), Err(StorageError::NotFound)),
            "{key} must not exist"
        );
    }

    #[test]
    fn transaction_commits_multiple_records_together() {
        let dir = tempdir().unwrap();
        let mut store = file_store(dir.path(), random_key());

        let tx = store.transaction().unwrap();
        tx.put("session:alice", b"ratchet-a").unwrap();
        tx.put("outbox:1", b"blob-1").unwrap();
        tx.put("outbox:2", b"blob-2").unwrap();
        tx.commit().unwrap();

        assert_eq!(store.get("session:alice").unwrap(), b"ratchet-a");
        assert_eq!(store.get("outbox:1").unwrap(), b"blob-1");
        assert_eq!(store.get("outbox:2").unwrap(), b"blob-2");
    }

    /// A transaction's own writes are visible to its later reads — the
    /// read-modify-write a future session manager will depend on.
    #[test]
    fn transaction_reads_its_own_writes() {
        let mut store = EncryptedStore::open_in_memory(random_key()).unwrap();
        store.put("k", b"before").unwrap();
        let tx = store.transaction().unwrap();
        assert_eq!(tx.get("k").unwrap(), b"before");
        tx.put("k", b"during").unwrap();
        assert_eq!(tx.get("k").unwrap(), b"during");
        tx.delete("k").unwrap();
        assert!(matches!(tx.get("k"), Err(StorageError::NotFound)));
        tx.commit().unwrap();
        assert!(matches!(store.get("k"), Err(StorageError::NotFound)));
    }

    /// Writes that succeed, followed by an operation that genuinely fails,
    /// followed by the ordinary `?` early return. Nothing written before the
    /// failure may survive.
    #[test]
    fn failed_operation_rolls_back_earlier_writes() {
        fn work(store: &mut EncryptedStore) -> Result<(), StorageError> {
            let tx = store.transaction()?;
            tx.put("a", b"1")?;
            tx.put("b", b"2")?;
            tx.delete("base")?;
            tx.get("does-not-exist")?; // a real storage failure: NotFound
            tx.commit()
        }

        let dir = tempdir().unwrap();
        let mut store = file_store(dir.path(), random_key());
        store.put("base", b"kept").unwrap();

        assert!(matches!(work(&mut store), Err(StorageError::NotFound)));

        assert_absent(&store, "a");
        assert_absent(&store, "b");
        assert_eq!(
            store.get("base").unwrap(),
            b"kept",
            "the delete must be undone too"
        );
    }

    #[test]
    fn mixed_insert_update_delete_commit_together() {
        let mut store = EncryptedStore::open_in_memory(random_key()).unwrap();
        store.put("update", b"old").unwrap();
        store.put("remove", b"gone-soon").unwrap();

        let tx = store.transaction().unwrap();
        tx.put("insert", b"new").unwrap();
        tx.put("update", b"new-value").unwrap();
        tx.delete("remove").unwrap();
        tx.commit().unwrap();

        assert_eq!(store.get("insert").unwrap(), b"new");
        assert_eq!(store.get("update").unwrap(), b"new-value");
        assert_absent(&store, "remove");
    }

    #[test]
    fn mixed_insert_update_delete_roll_back_together() {
        let mut store = EncryptedStore::open_in_memory(random_key()).unwrap();
        store.put("update", b"old").unwrap();
        store.put("remove", b"still-here").unwrap();

        let tx = store.transaction().unwrap();
        tx.put("insert", b"new").unwrap();
        tx.put("update", b"new-value").unwrap();
        tx.delete("remove").unwrap();
        tx.rollback().unwrap();

        assert_absent(&store, "insert");
        assert_eq!(store.get("update").unwrap(), b"old");
        assert_eq!(store.get("remove").unwrap(), b"still-here");
    }

    #[test]
    fn dropping_without_commit_rolls_back() {
        let mut store = EncryptedStore::open_in_memory(random_key()).unwrap();
        {
            let tx = store.transaction().unwrap();
            tx.put("k", b"v").unwrap();
        }
        assert_absent(&store, "k");
    }

    #[test]
    fn committed_records_are_visible_after_reopen() {
        let dir = tempdir().unwrap();
        let key = random_key();
        {
            let mut store = file_store(dir.path(), key);
            let tx = store.transaction().unwrap();
            tx.put("x", b"1").unwrap();
            tx.put("y", b"2").unwrap();
            tx.commit().unwrap();
        }
        let store = file_store(dir.path(), key);
        assert_eq!(store.get("x").unwrap(), b"1");
        assert_eq!(store.get("y").unwrap(), b"2");
    }

    #[test]
    fn aborted_transaction_preserves_committed_records_across_reopen() {
        let dir = tempdir().unwrap();
        let key = random_key();
        {
            let mut store = file_store(dir.path(), key);
            store.put("a", b"committed-a").unwrap();
            store.put("c", b"committed-c").unwrap();
            let tx = store.transaction().unwrap();
            tx.put("a", b"uncommitted").unwrap();
            tx.put("b", b"uncommitted").unwrap();
            tx.delete("c").unwrap();
            drop(tx);
        }
        let store = file_store(dir.path(), key);
        assert_eq!(store.get("a").unwrap(), b"committed-a");
        assert_absent(&store, "b");
        assert_eq!(store.get("c").unwrap(), b"committed-c");
    }

    /// A second connection to the same file must never observe part of an
    /// open transaction — it sees the state before, then the whole of it.
    #[test]
    fn other_connection_never_sees_partial_transaction() {
        let dir = tempdir().unwrap();
        let key = random_key();
        let mut writer = file_store(dir.path(), key);
        let reader = file_store(dir.path(), key);
        writer.put("left", b"0").unwrap();

        let tx = writer.transaction().unwrap();
        tx.put("left", b"1").unwrap();
        tx.put("right", b"1").unwrap();

        assert_eq!(
            reader.get("left").unwrap(),
            b"0",
            "uncommitted update leaked"
        );
        assert_absent(&reader, "right");

        tx.commit().unwrap();

        assert_eq!(reader.get("left").unwrap(), b"1");
        assert_eq!(reader.get("right").unwrap(), b"1");
    }

    /// Writers on separate connections race; a reader on its own connection
    /// must only ever see both halves of a pair from the same commit.
    ///
    /// The reader runs for as long as the writers do and yields between reads.
    /// An earlier version gave it a fixed 80 iterations; SQLite's busy handler
    /// is not a fair queue, so a tight loop of `BEGIN IMMEDIATE` on one
    /// connection kept re-taking the lock while the writers slept in backoff,
    /// and the reader regularly finished before a single commit happened. The
    /// `seen > 0` guard caught those runs as vacuous. Neither assertion was
    /// changed; only the reader's schedule, so that it actually overlaps the
    /// writers.
    #[test]
    fn concurrent_connections_only_observe_whole_transactions() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Barrier};

        let dir = tempdir().unwrap();
        let key = random_key();
        let path = dir.path().join("store.db");
        drop(EncryptedStore::open(&path, key).unwrap());

        let start = Arc::new(Barrier::new(3));
        let writers_running = Arc::new(AtomicUsize::new(2));
        let mut handles = Vec::new();
        for writer_id in 0..2 {
            let (path, start, running) = (path.clone(), start.clone(), writers_running.clone());
            handles.push(std::thread::spawn(move || {
                let mut store = EncryptedStore::open(&path, key).unwrap();
                start.wait();
                for i in 0..40 {
                    let v = format!("w{writer_id}-{i}");
                    let tx = store.transaction().unwrap();
                    tx.put("pair:left", v.as_bytes()).unwrap();
                    tx.put("pair:right", v.as_bytes()).unwrap();
                    tx.commit().unwrap();
                    std::thread::yield_now();
                }
                running.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        let reader = {
            let (path, start, running) = (path.clone(), start.clone(), writers_running.clone());
            std::thread::spawn(move || {
                let mut store = EncryptedStore::open(&path, key).unwrap();
                start.wait();
                let mut seen = 0usize;
                while running.load(Ordering::SeqCst) > 0 {
                    let tx = store.transaction().unwrap();
                    match (tx.get("pair:left"), tx.get("pair:right")) {
                        (Ok(l), Ok(r)) => {
                            assert_eq!(l, r, "observed a pair from two different commits");
                            seen += 1;
                        }
                        (Err(StorageError::NotFound), Err(StorageError::NotFound)) => {}
                        other => panic!("observed half a transaction: {other:?}"),
                    }
                    tx.commit().unwrap();
                    std::thread::sleep(Duration::from_millis(1));
                }
                seen
            })
        };
        for h in handles {
            h.join().unwrap();
        }
        let seen = reader.join().unwrap();
        let store = EncryptedStore::open(&path, key).unwrap();
        assert_eq!(
            store.get("pair:left").unwrap(),
            store.get("pair:right").unwrap()
        );
        assert!(
            seen > 0,
            "the reader never observed a committed pair; the test proved nothing"
        );
    }

    /// While another connection holds the write lock, `transaction()` waits
    /// for the busy timeout and then fails without writing anything; once the
    /// lock is released the same call succeeds.
    #[test]
    fn contended_begin_fails_cleanly_and_later_succeeds() {
        let dir = tempdir().unwrap();
        let key = random_key();
        let mut holder = file_store(dir.path(), key);
        let mut other = file_store(dir.path(), key);
        // Test-only: shorten the wait so the test does not sit for 5 s.
        other.conn.busy_timeout(Duration::from_millis(50)).unwrap();

        let held = holder.transaction().unwrap();
        held.put("holder", b"1").unwrap();

        match other.transaction() {
            Err(StorageError::Db(rusqlite::Error::SqliteFailure(e, _))) => {
                assert_eq!(e.code, rusqlite::ErrorCode::DatabaseBusy);
            }
            Err(e) => panic!("expected SQLITE_BUSY, got {e:?}"),
            Ok(_) => panic!("a second writer must not begin while the first holds the lock"),
        }

        held.commit().unwrap();

        let tx = other.transaction().unwrap();
        tx.put("other", b"2").unwrap();
        tx.commit().unwrap();
        assert_eq!(holder.get("other").unwrap(), b"2");
        assert_eq!(other.get("holder").unwrap(), b"1");
    }

    /// Records written through a transaction use the same encoding as `put`:
    /// each path reads what the other wrote, namespace listing still works,
    /// and neither the key name nor the value reaches the file in plaintext.
    #[test]
    fn transactional_and_plain_operations_share_one_encoding() {
        let dir = tempdir().unwrap();
        let key = random_key();
        {
            let mut store = file_store(dir.path(), key);
            store.put("contact:alice", b"plain-written").unwrap();
            let tx = store.transaction().unwrap();
            assert_eq!(tx.get("contact:alice").unwrap(), b"plain-written");
            tx.put("contact:bob", b"tx-written secret value").unwrap();
            tx.put("contact:alice", b"tx-updated").unwrap();
            tx.commit().unwrap();
        }
        let raw = std::fs::read(dir.path().join("store.db")).unwrap();
        let lossy = String::from_utf8_lossy(&raw);
        assert!(
            !lossy.contains("contact:bob"),
            "key name reached disk in plaintext"
        );
        assert!(
            !lossy.contains("tx-written secret value"),
            "value reached disk in plaintext"
        );

        let store = file_store(dir.path(), key);
        assert_eq!(
            store.get("contact:bob").unwrap(),
            b"tx-written secret value"
        );
        assert_eq!(store.get("contact:alice").unwrap(), b"tx-updated");
        assert_eq!(
            store.list_keys_with_prefix("contact:").unwrap(),
            vec!["contact:alice", "contact:bob"]
        );
        assert_absent(
            &EncryptedStore::open(dir.path().join("store.db"), random_key()).unwrap(),
            "contact:bob",
        );
    }

    /// S1 must not change the durability configuration of existing databases.
    /// These are the values observed on unmodified `main`; the test fails if
    /// anything — this change, a dependency bump, a bundled-SQLite default —
    /// moves them, so the change is at least visible.
    #[test]
    fn durability_configuration_is_unchanged() {
        let dir = tempdir().unwrap();
        let store = file_store(dir.path(), random_key());
        let journal: String = store
            .conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        let sync: i64 = store
            .conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        let busy: i64 = store
            .conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!(journal, "delete", "rollback-journal mode");
        assert_eq!(sync, 2, "synchronous = FULL");
        assert_eq!(busy, 5000, "rusqlite's per-connection default");
    }

    // ── S1: process termination ────────────────────────────────────────────
    //
    // The child is this same test binary, re-run to execute only
    // `s1_process_termination_child`. It ends with `std::process::abort()`, so
    // no destructor runs: the transaction is never rolled back or committed by
    // Rust, and SQLite is left exactly as a killed process leaves it.

    const CHILD_ENV_PATH: &str = "CORE_STORAGE_S1_CHILD_PATH";
    const CHILD_ENV_STAGE: &str = "CORE_STORAGE_S1_CHILD_STAGE";
    const CHILD_KEY: [u8; 32] = [0x5a; 32];
    const CHILD_RECORDS: usize = 300;

    #[test]
    #[ignore = "child role for the process-termination tests; does nothing when run directly"]
    fn s1_process_termination_child() {
        let (Ok(path), Ok(stage)) = (
            std::env::var(CHILD_ENV_PATH),
            std::env::var(CHILD_ENV_STAGE),
        ) else {
            return;
        };
        let mut store = EncryptedStore::open(&path, CHILD_KEY).unwrap();
        // A tiny page cache forces SQLite to spill modified pages into the
        // database file before commit, so a kill leaves uncommitted bytes on
        // disk and a hot journal — the case recovery actually has to handle.
        store.conn.pragma_update(None, "cache_size", 2).unwrap();
        let tx = store.transaction().unwrap();
        let payload = vec![0xa5u8; 4096];
        for i in 0..CHILD_RECORDS {
            tx.put(&format!("bulk:{i}"), &payload).unwrap();
        }
        match stage.as_str() {
            "before_commit" => std::process::abort(),
            "after_commit" => {
                tx.commit().unwrap();
                std::process::abort()
            }
            other => panic!("unknown stage {other}"),
        }
    }

    fn run_child(path: &std::path::Path, stage: &str) {
        use std::os::unix::process::ExitStatusExt;
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::s1_process_termination_child",
                "--ignored",
                "--test-threads=1",
                "-q",
            ])
            .env(CHILD_ENV_PATH, path)
            .env(CHILD_ENV_STAGE, stage)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(
            status.signal(),
            Some(6),
            "child must die by SIGABRT at stage {stage}, got {status:?}"
        );
    }

    #[test]
    fn process_killed_before_commit_leaves_no_trace() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        EncryptedStore::open(&path, CHILD_KEY)
            .unwrap()
            .put("base", b"kept")
            .unwrap();
        let size_before = std::fs::metadata(&path).unwrap().len();

        run_child(&path, "before_commit");

        // Evidence the kill landed mid-transaction ON DISK, not just in memory.
        let journal = dir.path().join("store.db-journal");
        let journal_len = std::fs::metadata(&journal).map(|m| m.len()).unwrap_or(0);
        let size_after_kill = std::fs::metadata(&path).unwrap().len();
        assert!(journal_len > 0, "expected a hot journal after the kill");
        assert!(
            size_after_kill > size_before,
            "uncommitted pages should have reached the file"
        );

        let store = EncryptedStore::open(&path, CHILD_KEY).unwrap();
        assert_eq!(store.get("base").unwrap(), b"kept");
        for i in [0, CHILD_RECORDS / 2, CHILD_RECORDS - 1] {
            assert_absent(&store, &format!("bulk:{i}"));
        }
        assert!(store.list_keys_with_prefix("bulk:").unwrap().is_empty());
        assert!(
            !journal.exists(),
            "recovery should have consumed the hot journal"
        );
    }

    #[test]
    fn process_killed_after_commit_keeps_every_record() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        EncryptedStore::open(&path, CHILD_KEY)
            .unwrap()
            .put("base", b"kept")
            .unwrap();

        run_child(&path, "after_commit");

        let store = EncryptedStore::open(&path, CHILD_KEY).unwrap();
        assert_eq!(store.get("base").unwrap(), b"kept");
        assert_eq!(
            store.list_keys_with_prefix("bulk:").unwrap().len(),
            CHILD_RECORDS
        );
    }
}
