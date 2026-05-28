use arti_client::{TorClient, TorClientConfig};
use std::sync::Arc;
use thiserror::Error;
use tor_rtcompat::PreferredRuntime;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("bootstrap failed: {0}")]
    Bootstrap(String),
    #[error("connection failed: {0}")]
    Connect(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct TorTransport {
    client: Arc<TorClient<PreferredRuntime>>,
    onion_address: String,
}

impl TorTransport {
    pub async fn new(state_dir: &std::path::Path) -> Result<Self, TransportError> {
        let config = TorClientConfig::default();
        let client = TorClient::create_bootstrapped(config)
            .await
            .map_err(|e| TransportError::Bootstrap(e.to_string()))?;
        Ok(Self {
            client: Arc::new(client),
            onion_address: "TODO.onion".to_string(),
        })
    }

    pub fn onion_address(&self) -> &str {
        &self.onion_address
    }
}

pub struct TorStream {
    inner: arti_client::DataStream,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::io;

    // TransportError::Bootstrap —————————————————————————————————————————————

    #[test]
    fn bootstrap_error_display() {
        let e = TransportError::Bootstrap("no consensus".to_string());
        assert_eq!(e.to_string(), "bootstrap failed: no consensus");
    }

    // TransportError::Connect ———————————————————————————————————————————————

    #[test]
    fn connect_error_display() {
        let e = TransportError::Connect("refused".to_string());
        assert_eq!(e.to_string(), "connection failed: refused");
    }

    // TransportError::Io ————————————————————————————————————————————————————

    #[test]
    fn io_error_display() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file missing");
        let e = TransportError::Io(io_err);
        assert_eq!(e.to_string(), "io error: file missing");
    }

    #[test]
    fn io_error_from_conversion() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let e: TransportError = io_err.into();
        assert!(matches!(e, TransportError::Io(_)));
    }

    #[test]
    fn io_error_exposes_source() {
        let io_err = io::Error::new(io::ErrorKind::BrokenPipe, "broken");
        let e = TransportError::Io(io_err);
        assert!(e.source().is_some(), "Io variant must expose its source via std::error::Error");
    }

    // TorTransport::new ——————————————————————————————————————————————————————
    // Requires a live Tor network; run manually with: cargo test -- --ignored

    #[tokio::test]
    #[ignore]
    async fn new_fails_gracefully_without_tor() {
        let dir = tempfile::tempdir().unwrap();
        let result = TorTransport::new(dir.path()).await;
        assert!(
            matches!(result, Err(TransportError::Bootstrap(_))),
            "expected Bootstrap error"
        );
    }
}