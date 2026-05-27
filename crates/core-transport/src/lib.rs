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
    #[test]
    fn placeholder() {
        assert_eq!(2 + 2, 4);
    }
}