//! `core-storage` — encrypted key-value store on top of SQLite.
//!
//! Each value is encrypted with XChaCha20-Poly1305 using a key derived from
//! the user's master key + the storage key (so the same plaintext under two
//! different keys produces different ciphertexts).

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
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS kv (
                k TEXT PRIMARY KEY,
                v BLOB NOT NULL
            );",
        )?;
        Ok(Self { conn, master_key })
    }

    pub fn open_in_memory(master_key: [u8; 32]) -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS kv (
                k TEXT PRIMARY KEY,
                v BLOB NOT NULL
            );",
        )?;
        Ok(Self { conn, master_key })
    }

    pub fn put(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let ct = self.encrypt(key, value)?;
        self.conn.execute(
            "INSERT INTO kv (k, v) VALUES (?1, ?2)
             ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            params![key, ct],
        )?;
        Ok(())
    }

    pub fn get(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        let row: Vec<u8> = self
            .conn
            .query_row("SELECT v FROM kv WHERE k = ?1", params![key], |r| r.get(0))
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound,
                other => StorageError::Db(other),
            })?;
        self.decrypt(key, &row)
    }

    pub fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.conn
            .execute("DELETE FROM kv WHERE k = ?1", params![key])?;
        Ok(())
    }

    pub fn list_keys_with_prefix(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        let pattern = format!("{}%", prefix);
        let mut stmt = self.conn.prepare("SELECT k FROM kv WHERE k LIKE ?1 ORDER BY k")?;
        let keys: Result<Vec<String>, _> = stmt
            .query_map(params![pattern], |r| r.get::<_, String>(0))?
            .collect();
        Ok(keys?)
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
    fn wrong_master_key_cannot_decrypt() {
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
            Err(StorageError::Decryption) => {}
            other => panic!("expected Decryption error, got {:?}", other),
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
            .query_row("SELECT v FROM kv WHERE k = 'a'", [], |r| r.get(0))
            .unwrap();
        let ct_b: Vec<u8> = store
            .conn
            .query_row("SELECT v FROM kv WHERE k = 'b'", [], |r| r.get(0))
            .unwrap();
        assert_ne!(ct_a, ct_b, "subkeys must produce different ciphertexts");
    }
}