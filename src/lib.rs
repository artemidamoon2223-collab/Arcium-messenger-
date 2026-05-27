//! Anonymous transport layer over Tor onion services.

use arti_client::{TorClient, TorClientConfig};
use std::sync::Arc;
use thiserror::Error;
use tor_rtcompat::PreferredRuntime;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("tor client bootstrap failed: {0}")]
    Bootstrap(String),
    #[error("onion service launch failed: {0}")]
    OnionService(String),
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
        let config = TorClientConfig::builder()
            .storage()
            .cache_dir(state_dir.join("tor-cache").into())
            .state_dir(state_dir.join("tor-state").into())
            .done()
            .map_err(|e| TransportError::Bootstrap(e.to_string()))?;

        let client = TorClient::create_bootstrapped(config)
            .await
            .map_err(|e| TransportError::Bootstrap(e.to_string()))?;

        let onion_address = "TODO.onion".to_string();

        Ok(Self {
            client: Arc::new(client),
            onion_address,
        })
    }

    pub fn onion_address(&self) -> &str {
        &self.onion_address
    }

    pub async fn connect(
        &self,
        peer_onion: &str,
        port: u16,
    ) -> Result<TorStream, TransportError> {
        let target = format!("{}:{}", peer_onion, port);
        let stream = self
            .client
            .connect(&target)
            .await
            .map_err(|e| TransportError::Connect(e.to_string()))?;
        Ok(TorStream { inner: stream })
    }
}

pub struct TorStream {
    inner: arti_client::DataStream,
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {
        assert_eq!(2 + 2, 4);
    }
}