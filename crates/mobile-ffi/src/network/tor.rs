//! The relay over Tor (docs/NET-MESSAGING.md, section 3a).
//!
//! A relay whose host is an onion name is reached only through the Tor
//! client embedded in the app (arti, `core-transport`), never directly: its
//! name never reaches this device's resolver or a TCP connect (decision
//! D-189). Any other host is reached directly, as before. There is no
//! switching between the two: the relay's address decides.
//!
//! One Tor client serves the whole process. It starts at the first
//! connection to an onion relay, which then waits for it (up to
//! `core_transport::BOOTSTRAP_TIMEOUT`), and it then stays for the life of
//! the process. Its state lives in the directory the first caller names,
//! next to the store (`ArciumCore::tor_dir`). A start that fails is tried
//! again at the next connection.

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use core_transport::{TorConnector, TorStream, TransportError};
use relay::client::{Connector, RelayStream};

use crate::CoreError;

/// The longest wait for a stream to an onion relay (decision D-194): Tor
/// builds a rendezvous circuit first. Reads and writes keep the messenger's
/// own timeout. A starting point, to be tuned with a real Tor network (plan
/// step 5.1).
#[cfg_attr(test, allow(dead_code))] // used by `OverTor`, which tests never reach
pub(crate) const ONION_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// The bound of every request as a whole to an onion relay (decision D-194),
/// instead of the 30 s of a direct relay.
pub(crate) const ONION_REQUEST_DEADLINE: Duration = Duration::from_secs(60);

/// Whether `host` is an onion name: its last label is `onion`, in any case,
/// with or without a final dot. Such a name is only ever reached through Tor.
pub(crate) fn is_onion(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    let last = host.rsplit('.').next().unwrap_or(host);
    last.eq_ignore_ascii_case("onion")
}

/// The host of a `host:port` string as a development (V1) relay is given: all
/// before the last `:`, without IPv6 brackets; the whole string if it has no
/// `:`.
pub(crate) fn v1_host(addr: &str) -> &str {
    let host = addr.rsplit_once(':').map_or(addr, |(host, _)| host);
    host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host)
}

/// Where a messenger gets the connector for an onion relay.
pub(crate) trait OnionPath: Send + Sync {
    fn connector(&self) -> Result<Box<dyn Connector>, CoreError>;
}

/// What the app can show about the process's Tor client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TorState {
    /// Not started: no connection to an onion relay was made yet.
    NotStarted,
    /// Starting: a connection waits for Tor to bootstrap.
    Starting,
    /// Running: connections to onion relays go through it.
    Running,
    /// The Tor network requires a protocol this version's Tor lacks
    /// (`TransportError::NeedsUpdate`): Tor stays off until the app is
    /// updated. arti 0.48 ends the process once when a running client learns
    /// this (D-199); this is what every later start reports.
    NeedsUpdate,
    /// The last start failed (no network, a timeout, ...); the next
    /// connection to an onion relay tries again.
    Failed,
}

/// The state of this process's Tor client.
#[uniffi::export]
pub fn tor_state() -> TorState {
    PROCESS_TOR.state()
}

/// A Tor client started once, on first use, and shared. `T` is the client;
/// the tests use a stand-in.
pub(crate) struct Shared<T> {
    slot: Mutex<Slot<T>>,
}

struct Slot<T> {
    client: Option<Arc<T>>,
    state: TorState,
}

impl<T> Shared<T> {
    pub(crate) const fn new() -> Self {
        Self {
            slot: Mutex::new(Slot {
                client: None,
                state: TorState::NotStarted,
            }),
        }
    }

    pub(crate) fn state(&self) -> TorState {
        self.slot.lock().unwrap_or_else(|e| e.into_inner()).state
    }

    /// The client, started with `start` if there is none yet. Callers that
    /// come while it starts wait for that start (the lock is held through
    /// it) and then get its client, or start once more if it failed.
    pub(crate) fn get_or_start(
        &self,
        start: impl FnOnce() -> Result<T, TransportError>,
    ) -> Result<Arc<T>, CoreError> {
        let mut slot = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(client) = &slot.client {
            return Ok(Arc::clone(client));
        }
        slot.state = TorState::Starting;
        match start() {
            Ok(client) => {
                let client = Arc::new(client);
                slot.client = Some(Arc::clone(&client));
                slot.state = TorState::Running;
                Ok(client)
            }
            Err(TransportError::NeedsUpdate) => {
                slot.state = TorState::NeedsUpdate;
                Err(CoreError::Network {
                    msg: "Tor needs an app update: the Tor network requires a newer version of this app"
                        .into(),
                })
            }
            Err(e) => {
                slot.state = TorState::Failed;
                Err(CoreError::Network {
                    msg: format!("Tor did not start: {e}"),
                })
            }
        }
    }
}

/// The process's Tor client. It is never dropped: dropping its runtime from
/// inside an async context panics (`core_transport::TorConnector`), and the
/// process keeps it to the end.
static PROCESS_TOR: Shared<TorConnector> = Shared::new();

/// The production path: the process's Tor client, its state kept in `dir`
/// when this is the call that starts it.
pub(crate) struct ProcessTor {
    pub(crate) dir: PathBuf,
}

impl OnionPath for ProcessTor {
    fn connector(&self) -> Result<Box<dyn Connector>, CoreError> {
        // A unit test that got here would bootstrap real Tor over the
        // network: tests give their messengers a stand-in path instead.
        #[cfg(test)]
        panic!("a test reached the process Tor client ({})", self.dir.display());
        #[cfg(not(test))]
        {
            let tor = PROCESS_TOR.get_or_start(|| TorConnector::bootstrap(&self.dir))?;
            Ok(Box::new(OverTor(tor)))
        }
    }
}

/// The relay client's [`Connector`] over a Tor client.
#[cfg_attr(test, allow(dead_code))]
struct OverTor(Arc<TorConnector>);

impl Connector for OverTor {
    /// Waits for the stream up to [`ONION_CONNECT_TIMEOUT`], or `timeout` if
    /// that is longer; the stream's reads and writes are then bounded by the
    /// connection's own `timeout`, which the relay client sets.
    fn connect(&self, addr: &str, timeout: Duration) -> io::Result<Box<dyn RelayStream>> {
        let stream = self.0.connect(addr, ONION_CONNECT_TIMEOUT.max(timeout))?;
        Ok(Box::new(TorRelayStream(stream)))
    }
}

/// A [`TorStream`] as the relay client's [`RelayStream`]. A wrapper, since
/// both the trait and the type live in other crates.
#[cfg_attr(test, allow(dead_code))]
struct TorRelayStream(TorStream);

impl Read for TorRelayStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for TorRelayStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl RelayStream for TorRelayStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_read_timeout(timeout)
    }

    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_write_timeout(timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering::SeqCst};

    #[test]
    fn onion_names_are_told_apart_from_other_hosts() {
        let onion = format!("{}.onion", "a".repeat(56));
        for host in [onion.as_str(), "x.onion", "X.ONION", "x.Onion.", "onion"] {
            assert!(is_onion(host), "{host}");
        }
        for host in ["relay.example.com", "onion.example.com", "127.0.0.1", "::1", "xonion", "x.onions", ""] {
            assert!(!is_onion(host), "{host}");
        }
    }

    #[test]
    fn the_host_of_a_v1_address_is_all_before_the_last_colon() {
        assert_eq!(v1_host("abc.onion:7700"), "abc.onion");
        assert_eq!(v1_host("abc.onion"), "abc.onion");
        assert_eq!(v1_host("[::1]:7700"), "::1");
        assert_eq!(v1_host("10.0.2.2:7700"), "10.0.2.2");
    }

    /// The client starts once, and every later call gets the same one.
    #[test]
    fn a_started_client_is_shared() {
        let shared = Shared::<u32>::new();
        assert_eq!(shared.state(), TorState::NotStarted);
        let starts = AtomicU32::new(0);
        let start = || {
            starts.fetch_add(1, SeqCst);
            Ok(7)
        };
        let a = shared.get_or_start(start).unwrap();
        let b = shared.get_or_start(|| panic!("started twice")).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!((starts.load(SeqCst), shared.state()), (1, TorState::Running));
    }

    /// `NeedsUpdate` is its own state and its own error text; the next call
    /// tries again (arti answers it from its cache, in milliseconds).
    #[test]
    fn a_start_that_needs_an_update_says_so_and_is_tried_again() {
        let shared = Shared::<u32>::new();
        let e = shared.get_or_start(|| Err(TransportError::NeedsUpdate)).err().unwrap();
        assert_eq!(shared.state(), TorState::NeedsUpdate);
        assert!(
            matches!(&e, CoreError::Network { msg } if msg.starts_with("Tor needs an app update")),
            "{e}"
        );
        assert_eq!(*shared.get_or_start(|| Ok(3)).unwrap(), 3);
        assert_eq!(shared.state(), TorState::Running);
    }

    /// Opening a core installs ring as the process's rustls provider
    /// (decision D-193), before any Tor client could exist: nothing else in
    /// this test binary installs one (the relay client passes ring to each
    /// TLS configuration itself, and no test starts Tor). The core keeps
    /// Tor's state in `tor/` next to the store file.
    #[test]
    fn opening_a_core_installs_ring_and_names_the_tor_directory_next_to_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("arcium.db");
        let core = crate::ArciumCore::new(store.to_str().unwrap().to_string(), vec![7u8; 32]).unwrap();
        let installed = rustls::crypto::CryptoProvider::get_default().expect("no provider installed").clone();
        let ring = rustls::crypto::ring::default_provider();
        let suites = |p: &rustls::crypto::CryptoProvider| p.cipher_suites.iter().map(|s| s.suite()).collect::<Vec<_>>();
        assert_eq!(suites(&installed), suites(&ring));
        assert_eq!(core.tor_dir, dir.path().join("tor"));
        // A second core installs nothing new: the provider stays the same one.
        let other = tempfile::tempdir().unwrap();
        crate::ArciumCore::new(other.path().join("db").to_str().unwrap().to_string(), vec![8u8; 32]).unwrap();
        let after = rustls::crypto::CryptoProvider::get_default().expect("no provider");
        assert!(Arc::ptr_eq(&installed, after), "a second core replaced the provider");
    }

    #[test]
    fn a_failed_start_is_failed_and_is_tried_again() {
        let shared = Shared::<u32>::new();
        let e = shared
            .get_or_start(|| Err(TransportError::Bootstrap("no network".into())))
            .err()
            .unwrap();
        assert_eq!(shared.state(), TorState::Failed);
        assert!(matches!(&e, CoreError::Network { msg } if msg.contains("no network")), "{e}");
        assert_eq!(*shared.get_or_start(|| Ok(4)).unwrap(), 4);
    }
}
