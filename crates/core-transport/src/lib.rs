use arti_client::config::TorClientConfigBuilder;
use arti_client::{ErrorKind, HasKind, TorClient, TorClientBuilder, TorClientConfig};
use std::fmt::Display;
use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tor_rtcompat::PreferredRuntime;

mod connector;
pub use connector::{TorConnector, TorStream};

/// Installs ring as this process's default rustls crypto provider, once
/// (decision D-193). arti's rustls runtime uses the process default and
/// installs none itself; the app calls this when its core starts, before any
/// Tor client exists. The relay client does not depend on it: it builds its
/// TLS configuration with ring explicitly (`relay::tls`). A provider already
/// installed stays: no other crate in the app installs one.
pub fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // Err only when a provider is already installed; it stays.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

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
    /// The Tor network requires a protocol this version of arti does not
    /// implement. arti 0.48 ends the whole process (`std::process::exit(1)`)
    /// when a running client gets such a consensus. If its directory cache
    /// is writable, it has saved the requirement there before that, so while
    /// that cache is kept every later bootstrap fails instead, with an error
    /// of kind `SoftwareDeprecated`, which is this. That lasts until an app
    /// update brings an arti that implements the protocol (or one released
    /// after that consensus).
    #[error("Tor stopped: the Tor network requires a newer version of this app")]
    NeedsUpdate,
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
        state_dir: &std::path::Path,
        bound: Duration,
    ) -> Result<Self, TransportError> {
        Self::create(state_dir, Start::Bootstrap(bound)).await
    }

    /// A transport whose client keeps its state under `state_dir` and starts
    /// as `start` says. Must run inside a tokio runtime: the client runs on
    /// the current one.
    async fn create(state_dir: &Path, start: Start) -> Result<Self, TransportError> {
        let builder = builder(state_dir)?;
        let client = match start {
            Start::Bootstrap(bound) => bootstrap_within(bound, builder.create_bootstrapped()).await?,
            #[cfg(test)]
            Start::Unbootstrapped => builder
                .bootstrap_behavior(arti_client::BootstrapBehavior::Manual)
                .create_unbootstrapped()
                .map_err(|e| TransportError::Bootstrap(e.to_string()))?,
        };
        Ok(Self {
            client,
            onion_address: "TODO.onion".to_string(),
        })
    }

    pub fn onion_address(&self) -> &str {
        &self.onion_address
    }
}

/// How [`TorTransport::create`] starts its client.
enum Start {
    /// Bootstrap, giving up after the bound.
    Bootstrap(Duration),
    /// Create the client without bootstrapping, and never bootstrap: offline,
    /// for tests.
    #[cfg(test)]
    Unbootstrapped,
}

/// A Tor client builder whose client keeps its state under `state_dir/state`
/// and its cache under `state_dir/cache`. Before, `state_dir` was ignored and
/// arti used its default directories under `$HOME` (F-15(b)). Must be called
/// inside a tokio runtime: the client runs on the current one.
fn builder(state_dir: &Path) -> Result<TorClientBuilder<PreferredRuntime>, TransportError> {
    let config: TorClientConfig =
        TorClientConfigBuilder::from_directories(state_dir.join("state"), state_dir.join("cache"))
            .build()
            .map_err(|e| TransportError::Bootstrap(format!("configuration: {e}")))?;
    Ok(TorClient::builder().config(config))
}

/// Runs a bootstrap future for at most `bound`. A timeout and an error from
/// the future both become [`TransportError::Bootstrap`], except an error of
/// kind `SoftwareDeprecated` (arti's cached consensus requires a protocol it
/// lacks), which becomes [`TransportError::NeedsUpdate`]. On a timeout the
/// future is dropped, which drops the client it was building.
async fn bootstrap_within<T, E: Display + HasKind>(
    bound: Duration,
    bootstrap: impl Future<Output = Result<T, E>>,
) -> Result<T, TransportError> {
    match tokio::time::timeout(bound, bootstrap).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) if e.kind() == ErrorKind::SoftwareDeprecated => Err(TransportError::NeedsUpdate),
        Ok(Err(e)) => Err(TransportError::Bootstrap(e.to_string())),
        Err(_) => Err(TransportError::Bootstrap(format!(
            "no bootstrap within {} s",
            bound.as_secs_f64()
        ))),
    }
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

    // TransportError::NeedsUpdate ———————————————————————————————————————————

    #[test]
    fn needs_update_error_display() {
        assert_eq!(
            TransportError::NeedsUpdate.to_string(),
            "Tor stopped: the Tor network requires a newer version of this app"
        );
    }

    // bootstrap_within ———————————————————————————————————————————————————————

    /// A bootstrap error with a kind, as arti's errors have.
    #[derive(Debug)]
    struct Failure(ErrorKind, &'static str);

    impl Display for Failure {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.1)
        }
    }

    impl HasKind for Failure {
        fn kind(&self) -> ErrorKind {
            self.0
        }
    }

    #[tokio::test]
    async fn bootstrap_within_times_out_on_a_bootstrap_that_never_finishes() {
        let bound = Duration::from_millis(50);
        let start = std::time::Instant::now();
        let result = bootstrap_within(bound, std::future::pending::<Result<(), Failure>>()).await;
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
            Err::<(), _>(Failure(ErrorKind::TorAccessFailed, "no consensus"))
        })
        .await;
        assert!(
            matches!(&result, Err(TransportError::Bootstrap(m)) if m == "no consensus"),
            "got {result:?}"
        );
    }

    /// arti's bootstrap fails with this kind when its cached consensus
    /// requires a protocol it lacks (`MissingProtocol`): an update to ask
    /// for, not a failure to retry.
    #[tokio::test]
    async fn bootstrap_within_reports_deprecated_software_as_needs_update() {
        let result = bootstrap_within(Duration::from_secs(5), async {
            Err::<(), _>(Failure(ErrorKind::SoftwareDeprecated, "missing protocol"))
        })
        .await;
        assert!(matches!(result, Err(TransportError::NeedsUpdate)), "got {result:?}");
    }

    #[tokio::test]
    async fn bootstrap_within_returns_a_finished_bootstrap() {
        let result = bootstrap_within(Duration::from_secs(5), async { Ok::<_, Failure>(7) }).await;
        assert!(matches!(result, Ok(7)));
    }

    // TLS crypto provider ————————————————————————————————————————————————————

    /// A Tor client, and with it arti's rustls runtime, can be created with
    /// what this crate itself brings. arti 0.48 installs no TLS crypto
    /// provider; rustls picks one from its crate features when exactly one is
    /// on, and this crate's Cargo.toml turns on `ring`. Run alone (`cargo test
    /// -p core-transport`), no other crate supplies one, so this fails if that
    /// line goes; with all workspace crates it would also fail if a second
    /// provider (`aws_lc_rs`) were turned on. Offline: the client is created
    /// without bootstrapping, in its own directories.
    #[tokio::test]
    async fn a_tor_client_can_be_created_from_this_crate_alone() {
        let dir = tempfile::tempdir().unwrap();
        let config = arti_client::config::TorClientConfigBuilder::from_directories(
            dir.path().join("state"),
            dir.path().join("cache"),
        )
        .build()
        .unwrap();
        let client = TorClient::builder().config(config).create_unbootstrapped();
        assert!(client.is_ok(), "{:?}", client.err());
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_some(),
            "creating the client installed no process-level provider"
        );
    }

    /// The client keeps its state and cache under the directory it is given
    /// (F-15(b)), not in arti's default directories under `$HOME`. Creating
    /// it writes all three (its state lock, its key store, its directory
    /// cache); offline, nothing is bootstrapped. Only the bootstrap itself
    /// differs from the production path (`Start::Bootstrap`).
    #[tokio::test]
    async fn the_client_keeps_its_state_and_cache_under_the_given_directory() {
        let dir = tempfile::tempdir().unwrap();
        let transport = TorTransport::create(dir.path(), Start::Unbootstrapped).await;
        assert!(transport.is_ok(), "{:?}", transport.err());
        assert!(dir.path().join("state/state/state.lock").is_file(), "no state lock under the directory");
        assert!(dir.path().join("state/keystore").is_dir(), "no key store under the directory");
        assert!(dir.path().join("cache/dir.lock").is_file(), "no cache lock under the directory");
    }

    // TorTransport::new ——————————————————————————————————————————————————————
    // Uses the network and writes arti's cache and state under the temporary
    // directory it is given; run manually with: cargo test -- --ignored
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
