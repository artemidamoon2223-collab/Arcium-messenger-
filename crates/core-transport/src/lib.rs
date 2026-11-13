use arti_client::{TorClient, TorClientConfig};
use std::fmt::Display;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tor_rtcompat::PreferredRuntime;

/// Longest time [`TorTransport::new`] waits for Tor to bootstrap before it
/// returns [`TransportError::Bootstrap`].
///
/// Without a bound, arti keeps retrying its directory download (128 attempts
/// with growing pauses by default), so an unreachable Tor network made `new`
/// wait for hours instead of reporting an error (D-008).
pub const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("bootstrap failed: {0}")]
    Bootstrap(String),
    #[error("connection failed: {0}")]
    Connect(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[allow(dead_code)]
pub struct TorTransport {
    client: Arc<TorClient<PreferredRuntime>>,
    onion_address: String,
}

impl TorTransport {
    /// Bootstraps a Tor client, giving up after [`BOOTSTRAP_TIMEOUT`].
    pub async fn new(state_dir: &std::path::Path) -> Result<Self, TransportError> {
        Self::new_within(state_dir, BOOTSTRAP_TIMEOUT).await
    }

    async fn new_within(
        _state_dir: &std::path::Path,
        bound: Duration,
    ) -> Result<Self, TransportError> {
        let config = TorClientConfig::default();
        let client = bootstrap_within(bound, TorClient::create_bootstrapped(config)).await?;
        Ok(Self {
            client: Arc::new(client),
            onion_address: "TODO.onion".to_string(),
        })
    }

    pub fn onion_address(&self) -> &str {
        &self.onion_address
    }
}

/// Runs a bootstrap future for at most `bound`. A timeout and an error from
/// the future both become [`TransportError::Bootstrap`]. On a timeout the
/// future is dropped, which drops the client it was building.
async fn bootstrap_within<T, E: Display>(
    bound: Duration,
    bootstrap: impl Future<Output = Result<T, E>>,
) -> Result<T, TransportError> {
    match tokio::time::timeout(bound, bootstrap).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(TransportError::Bootstrap(e.to_string())),
        Err(_) => Err(TransportError::Bootstrap(format!(
            "no bootstrap within {} s",
            bound.as_secs_f64()
        ))),
    }
}

#[allow(dead_code)]
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

    // bootstrap_within ———————————————————————————————————————————————————————

    #[tokio::test]
    async fn bootstrap_within_times_out_on_a_bootstrap_that_never_finishes() {
        let bound = Duration::from_millis(50);
        let start = std::time::Instant::now();
        let result = bootstrap_within(bound, std::future::pending::<Result<(), String>>()).await;
        assert!(
            matches!(&result, Err(TransportError::Bootstrap(m)) if m.contains("no bootstrap within")),
            "expected a Bootstrap timeout, got {result:?}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "must return near the bound"
        );
    }

    #[tokio::test]
    async fn bootstrap_within_reports_a_bootstrap_error_as_bootstrap() {
        let result = bootstrap_within(Duration::from_secs(5), async {
            Err::<(), _>("no consensus")
        })
        .await;
        assert!(
            matches!(&result, Err(TransportError::Bootstrap(m)) if m == "no consensus"),
            "got {result:?}"
        );
    }

    #[tokio::test]
    async fn bootstrap_within_returns_a_finished_bootstrap() {
        let result = bootstrap_within(Duration::from_secs(5), async { Ok::<_, String>(7) }).await;
        assert!(matches!(result, Ok(7)));
    }

    // TorTransport::new ——————————————————————————————————————————————————————
    // Uses the network and writes arti's default cache and state directories
    // under $HOME; run manually with: cargo test -- --ignored
    // Without a reachable Tor network it must return a Bootstrap error within
    // the bound it was given (before D-008 it did not return at all).

    #[tokio::test]
    #[ignore]
    async fn new_fails_gracefully_without_tor() {
        let dir = tempfile::tempdir().unwrap();
        let bound = Duration::from_secs(5);
        let start = std::time::Instant::now();
        let result = TorTransport::new_within(dir.path(), bound).await;
        assert!(
            matches!(result, Err(TransportError::Bootstrap(_))),
            "expected Bootstrap error"
        );
        assert!(
            start.elapsed() < bound + Duration::from_secs(5),
            "must return near the bound"
        );
    }
}
