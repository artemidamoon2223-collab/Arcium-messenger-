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
use rusqlite::{params, Connection};
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
        Ok(Self { conn, master_key })
    }

    pub fn put(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let ct = self.encrypt(key, value)?;
        let sk = self.storage_key(key);
        let ek = self.encrypt_key_name(key);
        self.conn.execute(
            "INSERT INTO kv (k, ek, v) VALUES (?1, ?2, ?3)
             ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            params![sk, ek, ct],
        )?;
        Ok(())
    }

    pub fn get(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        let sk = self.storage_key(key);
        let row: Vec<u8> = self
            .conn
            .query_row("SELECT v FROM kv WHERE k = ?1", params![sk], |r| r.get(0))
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound,
                other => StorageError::Db(other),
            })?;
        self.decrypt(key, &row)
    }

    pub fn delete(&self, key: &str) -> Result<(), StorageError> {
        let sk = self.storage_key(key);
        self.conn
            .execute("DELETE FROM kv WHERE k = ?1", params![sk])?;
        Ok(())
    }

    /// Lists the real key names sharing `prefix`'s namespace. `prefix` is
    /// matched as an exact namespace, not an arbitrary substring: since
    /// stored keys are hashed (F-10), only a `prefix` that equals the
    /// namespace a key was written under (everything up to and including
    /// its first `:`, or the whole key if it has none) can match — the
    /// same convention `namespace_of` uses when writing.
    pub fn list_keys_with_prefix(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        let ns_hash = self.key_name_hash(prefix);
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
            .map(|ek| self.decrypt_key_name(&ek))
            .collect::<Result<_, _>>()?;
        keys.sort();
        Ok(keys)
    }

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

impl Drop for EncryptedStore {
    fn drop(&mut self) {
        self.master_key.zeroize();
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
}
