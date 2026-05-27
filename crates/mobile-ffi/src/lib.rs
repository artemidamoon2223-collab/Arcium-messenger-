use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

uniffi::setup_scaffolding!();

#[derive(Debug, Error, uniffi::Error)]
pub enum CoreError {
    #[error("crypto error: {msg}")]
    Crypto { msg: String },
    #[error("storage error: {msg}")]
    Storage { msg: String },
    #[error("transport error: {msg}")]
    Transport { msg: String },
}

#[derive(uniffi::Object)]
pub struct Identity {
    inner: Mutex<()>,
}

#[uniffi::export]
impl Identity {
    #[uniffi::constructor]
    pub fn generate() -> Arc<Self> {
        Arc::new(Self { inner: Mutex::new(()) })
    }

    pub fn onion_address(&self) -> String {
        "TODO.onion".to_string()
    }

    pub fn prekey_bundle_bytes(&self) -> Vec<u8> {
        vec![]
    }
}

#[derive(uniffi::Object)]
pub struct ArciumCore {
    identity: Arc<Identity>,
}

#[uniffi::export]
impl ArciumCore {
    #[uniffi::constructor]
    pub fn new(identity: Arc<Identity>) -> Arc<Self> {
        Arc::new(Self { identity })
    }

    pub fn my_prekey_bundle(&self) -> Vec<u8> {
        self.identity.prekey_bundle_bytes()
    }
}