use core_crypto::ratchet::{DoubleRatchet, Header, RatchetError};
use core_protocol::SessionManager;
use core_storage::{EncryptedStore, StorageError};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

#[derive(Debug, Error, uniffi::Error)]
pub enum CoreError {
    #[error("storage error: {msg}")]
    Storage { msg: String },
    #[error("invalid master key: {msg}")]
    InvalidKey { msg: String },
    #[error("session error: {msg}")]
    Session { msg: String },
}

impl From<StorageError> for CoreError {
    fn from(e: StorageError) -> Self {
        CoreError::Storage { msg: e.to_string() }
    }
}

impl From<RatchetError> for CoreError {
    fn from(e: RatchetError) -> Self {
        CoreError::Session { msg: e.to_string() }
    }
}

// ── Ratchet FFI records ─────────────────────────────────────────────────────

#[derive(Debug, Clone, uniffi::Record)]
pub struct HeaderFfi {
    pub dh: Vec<u8>,
    pub pn: u32,
    pub n: u32,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct EncryptedMessage {
    pub header: HeaderFfi,
    pub ciphertext: Vec<u8>,
}

impl From<Header> for HeaderFfi {
    fn from(h: Header) -> Self {
        HeaderFfi { dh: h.dh.to_vec(), pn: h.pn, n: h.n }
    }
}

impl TryFrom<HeaderFfi> for Header {
    type Error = CoreError;

    fn try_from(h: HeaderFfi) -> Result<Self, CoreError> {
        let dh: [u8; 32] = h.dh.try_into().map_err(|_| CoreError::InvalidKey {
            msg: "header.dh must be exactly 32 bytes".into(),
        })?;
        Ok(Header { dh, pn: h.pn, n: h.n })
    }
}

/// Re-export of the canonical contact-hash function so Kotlin callers can
/// derive a `SessionManager` contact id without reimplementing the hash.
#[uniffi::export]
pub fn hash_contact(phone: String) -> u64 {
    core_crypto::contact_hash::hash_contact(&phone)
}

// ── Identity ──────────────────────────────────────────────────────────────────

#[derive(uniffi::Object)]
pub struct Identity {
    signing_key: SigningKey,
    dh_key: StaticSecret,
}

#[uniffi::export]
impl Identity {
    #[uniffi::constructor]
    pub fn generate() -> Arc<Self> {
        Arc::new(Self {
            signing_key: SigningKey::generate(&mut OsRng),
            dh_key: StaticSecret::random_from_rng(OsRng),
        })
    }

    /// Returns the 32-byte Ed25519 verifying (public) key.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }
}

// ── ArciumCore ────────────────────────────────────────────────────────────────

const IDENTITY_KEY: &str = "identity/v1";

#[derive(uniffi::Object)]
pub struct ArciumCore {
    store: Mutex<EncryptedStore>,
    sessions: Mutex<SessionManager>,
}

#[uniffi::export]
impl ArciumCore {
    #[uniffi::constructor]
    pub fn new(storage_path: String, master_key: Vec<u8>) -> Result<Arc<Self>, CoreError> {
        let key: [u8; 32] = master_key.try_into().map_err(|_| CoreError::InvalidKey {
            msg: "expected exactly 32 bytes".into(),
        })?;
        let store = EncryptedStore::open(&storage_path, key)?;
        Ok(Arc::new(Self {
            store: Mutex::new(store),
            sessions: Mutex::new(SessionManager::new()),
        }))
    }

    pub fn save_identity(&self, identity: Arc<Identity>) -> Result<(), CoreError> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(64));
        bytes.extend_from_slice(identity.signing_key.as_bytes());
        bytes.extend_from_slice(&identity.dh_key.to_bytes());
        self.store
            .lock()
            .map_err(|_| CoreError::Storage { msg: "mutex poisoned".into() })?
            .put(IDENTITY_KEY, &bytes)?;
        Ok(())
    }

    pub fn load_identity(&self) -> Option<Arc<Identity>> {
        let bytes = match self.store.lock().unwrap().get(IDENTITY_KEY) {
            Ok(b) => b,
            Err(_) => return None, // NotFound or wrong-key Decryption → None
        };
        if bytes.len() != 64 {
            return None;
        }
        let sk_bytes: [u8; 32] = bytes[..32].try_into().ok()?;
        let dh_bytes: [u8; 32] = bytes[32..].try_into().ok()?;
        Some(Arc::new(Identity {
            signing_key: SigningKey::from_bytes(&sk_bytes),
            dh_key: StaticSecret::from(dh_bytes),
        }))
    }

    /// Create an in-memory Alice-side ratchet session for `contact_id`.
    /// `root_key` and `their_initial_dh` are caller-supplied 32-byte values
    /// (normally produced by an X3DH handshake, out of scope for this package).
    pub fn create_session_alice(
        &self,
        contact_id: u64,
        root_key: Vec<u8>,
        their_initial_dh: Vec<u8>,
    ) -> Result<(), CoreError> {
        let rk: [u8; 32] = root_key.try_into().map_err(|_| CoreError::InvalidKey {
            msg: "root_key must be exactly 32 bytes".into(),
        })?;
        let dh_bytes: [u8; 32] = their_initial_dh.try_into().map_err(|_| CoreError::InvalidKey {
            msg: "their_initial_dh must be exactly 32 bytes".into(),
        })?;
        let ratchet = DoubleRatchet::init_alice(rk, PublicKey::from(dh_bytes));
        self.sessions
            .lock()
            .map_err(|_| CoreError::Session { msg: "mutex poisoned".into() })?
            .new_session(contact_id, ratchet);
        Ok(())
    }

    /// Create an in-memory Bob-side ratchet session for `contact_id`.
    /// `root_key` and `our_initial_dh` are caller-supplied (see above).
    pub fn create_session_bob(
        &self,
        contact_id: u64,
        root_key: Vec<u8>,
        our_initial_dh: Vec<u8>,
    ) -> Result<(), CoreError> {
        let rk: [u8; 32] = root_key.try_into().map_err(|_| CoreError::InvalidKey {
            msg: "root_key must be exactly 32 bytes".into(),
        })?;
        let dh_bytes: [u8; 32] = our_initial_dh.try_into().map_err(|_| CoreError::InvalidKey {
            msg: "our_initial_dh must be exactly 32 bytes".into(),
        })?;
        let ratchet = DoubleRatchet::init_bob(rk, StaticSecret::from(dh_bytes));
        self.sessions
            .lock()
            .map_err(|_| CoreError::Session { msg: "mutex poisoned".into() })?
            .new_session(contact_id, ratchet);
        Ok(())
    }

    /// Encrypt `plaintext` through the existing ratchet session for `contact_id`.
    pub fn encrypt_message(
        &self,
        contact_id: u64,
        plaintext: Vec<u8>,
        ad: Vec<u8>,
    ) -> Result<EncryptedMessage, CoreError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| CoreError::Session { msg: "mutex poisoned".into() })?;
        let ratchet = sessions
            .get_session(contact_id)
            .ok_or_else(|| CoreError::Session { msg: "no session for contact".into() })?;
        let (header, ciphertext) = ratchet.encrypt(&plaintext, &ad)?;
        Ok(EncryptedMessage { header: header.into(), ciphertext })
    }

    /// Decrypt `ciphertext` through the existing ratchet session for `contact_id`.
    pub fn decrypt_message(
        &self,
        contact_id: u64,
        header: HeaderFfi,
        ciphertext: Vec<u8>,
        ad: Vec<u8>,
    ) -> Result<Vec<u8>, CoreError> {
        let hdr: Header = header.try_into()?;
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| CoreError::Session { msg: "mutex poisoned".into() })?;
        let ratchet = sessions
            .get_session(contact_id)
            .ok_or_else(|| CoreError::Session { msg: "no session for contact".into() })?;
        let plaintext = ratchet.decrypt(&hdr, &ciphertext, &ad)?;
        Ok(plaintext)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn key32(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    #[test]
    fn identity_generates_keys() {
        let id = Identity::generate();
        assert_ne!(id.public_key_bytes(), vec![0u8; 32], "public key must not be all zeros");
    }

    #[test]
    fn identity_public_key_correct_size() {
        assert_eq!(Identity::generate().public_key_bytes().len(), 32);
    }

    #[test]
    fn core_saves_and_loads_identity() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db").to_str().unwrap().to_string();

        let core = ArciumCore::new(path, key32(0)).unwrap();
        let id = Identity::generate();
        let pk = id.public_key_bytes();
        core.save_identity(id).unwrap();

        let loaded = core.load_identity().expect("identity must be present after save");
        assert_eq!(loaded.public_key_bytes(), pk);
    }

    #[test]
    fn core_with_wrong_key_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db").to_str().unwrap().to_string();

        // Save with key 0x00…
        let core = ArciumCore::new(path.clone(), key32(0)).unwrap();
        core.save_identity(Identity::generate()).unwrap();

        // Open same file with key 0x01… → Decryption fails → None
        let core2 = ArciumCore::new(path, key32(1)).unwrap();
        assert!(core2.load_identity().is_none());
    }

    #[test]
    fn core_new_rejects_short_master_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db").to_str().unwrap().to_string();
        let result = ArciumCore::new(path, vec![0u8; 16]);
        assert!(matches!(result, Err(CoreError::InvalidKey { .. })));
    }

    #[test]
    fn save_identity_returns_ok_on_success() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db").to_str().unwrap().to_string();
        let core = ArciumCore::new(path, key32(0)).unwrap();
        let result = core.save_identity(Identity::generate());
        assert!(result.is_ok(), "save_identity must return Ok on success");
    }

    #[test]
    fn save_identity_returns_err_on_poisoned_mutex() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db").to_str().unwrap().to_string();
        let core = Arc::new(ArciumCore::new(path, key32(0)).unwrap());
        // Poison the mutex by panicking while holding the lock in another thread.
        let core2 = Arc::clone(&core);
        let _ = std::thread::spawn(move || {
            let _guard = core2.store.lock().unwrap();
            panic!("poison");
        })
        .join();
        // The mutex is now poisoned; save_identity must return Err, not panic.
        let result = core.save_identity(Identity::generate());
        assert!(
            matches!(result, Err(CoreError::Storage { .. })),
            "poisoned mutex must surface as CoreError::Storage, got {:?}",
            result
        );
    }

    // ── Ratchet FFI surface ─────────────────────────────────────────────────

    fn open_core(dir: &tempfile::TempDir, name: &str, key_byte: u8) -> Arc<ArciumCore> {
        let path = dir.path().join(name).to_str().unwrap().to_string();
        ArciumCore::new(path, key32(key_byte)).unwrap()
    }

    #[test]
    fn ffi_roundtrip_alice_to_bob() {
        let dir = tempdir().unwrap();
        let alice = open_core(&dir, "alice.db", 0);
        let bob = open_core(&dir, "bob.db", 1);

        let root_key = vec![0x42u8; 32];
        let bob_dh_sk = StaticSecret::random_from_rng(OsRng);
        let bob_dh_pk = PublicKey::from(&bob_dh_sk);

        alice
            .create_session_alice(1, root_key.clone(), bob_dh_pk.as_bytes().to_vec())
            .unwrap();
        bob.create_session_bob(1, root_key, bob_dh_sk.to_bytes().to_vec()).unwrap();

        let ad = b"test-ad".to_vec();
        let msg = b"hello bob".to_vec();
        let enc = alice.encrypt_message(1, msg.clone(), ad.clone()).unwrap();
        let pt = bob.decrypt_message(1, enc.header, enc.ciphertext, ad).unwrap();

        assert_eq!(pt, msg);
    }

    #[test]
    fn encrypt_without_session_returns_error() {
        let dir = tempdir().unwrap();
        let core = open_core(&dir, "db", 0);

        let result = core.encrypt_message(999, b"hi".to_vec(), b"ad".to_vec());
        assert!(
            matches!(result, Err(CoreError::Session { .. })),
            "expected CoreError::Session, got {:?}",
            result
        );
    }

    #[test]
    fn create_session_rejects_short_root_key() {
        let dir = tempdir().unwrap();
        let core = open_core(&dir, "db", 0);

        let short_key = vec![0u8; 31];
        let dh = vec![0u8; 32];
        let result = core.create_session_alice(1, short_key, dh);
        assert!(
            matches!(result, Err(CoreError::InvalidKey { .. })),
            "expected CoreError::InvalidKey, got {:?}",
            result
        );
    }

    #[test]
    fn ffi_out_of_order_delivery() {
        let dir = tempdir().unwrap();
        let alice = open_core(&dir, "alice.db", 0);
        let bob = open_core(&dir, "bob.db", 1);

        let root_key = vec![0x11u8; 32];
        let bob_dh_sk = StaticSecret::random_from_rng(OsRng);
        let bob_dh_pk = PublicKey::from(&bob_dh_sk);

        alice
            .create_session_alice(2, root_key.clone(), bob_dh_pk.as_bytes().to_vec())
            .unwrap();
        bob.create_session_bob(2, root_key, bob_dh_sk.to_bytes().to_vec()).unwrap();

        let ad = b"ooo-test".to_vec();
        let m0 = alice.encrypt_message(2, b"msg-0".to_vec(), ad.clone()).unwrap();
        let m1 = alice.encrypt_message(2, b"msg-1".to_vec(), ad.clone()).unwrap();
        let m2 = alice.encrypt_message(2, b"msg-2".to_vec(), ad.clone()).unwrap();

        let pt2 = bob.decrypt_message(2, m2.header, m2.ciphertext, ad.clone()).unwrap();
        let pt1 = bob.decrypt_message(2, m1.header, m1.ciphertext, ad.clone()).unwrap();
        let pt0 = bob.decrypt_message(2, m0.header, m0.ciphertext, ad).unwrap();

        assert_eq!(pt2, b"msg-2");
        assert_eq!(pt1, b"msg-1");
        assert_eq!(pt0, b"msg-0");
    }

    #[test]
    fn hash_contact_matches_core_crypto() {
        let phone = "+15551234567".to_string();
        assert_eq!(hash_contact(phone.clone()), core_crypto::contact_hash::hash_contact(&phone));
    }
}
