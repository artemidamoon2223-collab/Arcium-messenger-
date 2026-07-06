use core_storage::{EncryptedStore, StorageError};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

#[derive(Debug, Error, uniffi::Error)]
pub enum CoreError {
    #[error("storage error: {msg}")]
    Storage { msg: String },
    #[error("invalid master key: {msg}")]
    InvalidKey { msg: String },
}

impl From<StorageError> for CoreError {
    fn from(e: StorageError) -> Self {
        CoreError::Storage { msg: e.to_string() }
    }
}

/// Deterministic, non-secret marker proving the Kotlin<->Rust FFI bridge is
/// wired and callable. Carries no key, message, or session data — safe to
/// surface directly in a debug-only UI control.
#[uniffi::export]
pub fn bridge_version() -> String {
    "arcium-mobile-ffi-bridge-v1".to_string()
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
}

#[uniffi::export]
impl ArciumCore {
    #[uniffi::constructor]
    pub fn new(storage_path: String, master_key: Vec<u8>) -> Result<Arc<Self>, CoreError> {
        let key: [u8; 32] = master_key.try_into().map_err(|_| CoreError::InvalidKey {
            msg: "expected exactly 32 bytes".into(),
        })?;
        let store = EncryptedStore::open(&storage_path, key)?;
        Ok(Arc::new(Self { store: Mutex::new(store) }))
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
        // A poisoned mutex must not panic across the FFI boundary; treat the
        // store as unavailable, consistent with save_identity's error path.
        let store = match self.store.lock() {
            Ok(guard) => guard,
            Err(_) => return None,
        };
        let bytes = match store.get(IDENTITY_KEY) {
            Ok(b) => Zeroizing::new(b),
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
    fn bridge_version_is_deterministic_and_non_empty() {
        let v1 = bridge_version();
        let v2 = bridge_version();
        assert_eq!(v1, v2, "bridge_version must be deterministic");
        assert!(!v1.is_empty(), "bridge_version must not be empty");
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

    #[test]
    fn load_identity_returns_none_on_poisoned_mutex() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db").to_str().unwrap().to_string();
        let core = Arc::new(ArciumCore::new(path, key32(0)).unwrap());
        core.save_identity(Identity::generate()).unwrap();
        // Poison the mutex by panicking while holding the lock in another thread.
        let core2 = Arc::clone(&core);
        let _ = std::thread::spawn(move || {
            let _guard = core2.store.lock().unwrap();
            panic!("poison");
        })
        .join();
        // The mutex is now poisoned; load_identity must return None, not panic.
        assert!(
            core.load_identity().is_none(),
            "poisoned mutex must yield None, not a panic across FFI"
        );
    }
}
