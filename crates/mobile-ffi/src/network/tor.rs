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
//! next to the store (`ArciumCore::tor_dir`). After a start that fails,
//! connections fail at once with its error for [`RETRY_AFTER`]; the first
//! connection after that tries again.

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use core_transport::{TorConnector, TorStream, TransportError};
use relay::client::{Connector, RelayStream};

use crate::CoreError;

/// The longest wait for a stream to an onion relay (decision D-194): Tor
/// builds a rendezvous circuit first. Reads and writes keep the messenger's
/// own timeout. A starting point, to be tuned with a real Tor network (plan
/// step 5.1).
pub(crate) const ONION_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// The bound of every request as a whole to an onion relay (decision D-194),
/// instead of the 30 s of a direct relay.
pub(crate) const ONION_REQUEST_DEADLINE: Duration = Duration::from_secs(60);

/// How long after a failed start connections fail at once with its error,
/// instead of each waiting for another start of up to 120 s. A sync round
/// every 30 s (background receive) so tries a start about every other round.
pub(crate) const RETRY_AFTER: Duration = Duration::from_secs(60);

/// Whether `host` is an onion name: its last non-empty label is `onion`, in
/// any case, whatever dots follow it. Such a name is only ever reached
/// through Tor.
pub(crate) fn is_onion(host: &str) -> bool {
    let host = host.trim_end_matches('.');
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
    /// Running: a client was started; connections to onion relays go through
    /// it. Not re-evaluated later (whether Tor still reaches the network
    /// shows in each connection's result).
    Running,
    /// The Tor network requires a protocol this version's Tor lacks
    /// (`TransportError::NeedsUpdate`): Tor stays off until the app is
    /// updated. arti 0.48 ends the process once when a running client learns
    /// this (D-199); this is what every later start reports.
    NeedsUpdate,
    /// The last start failed (no network, a timeout, ...); a connection after
    /// [`RETRY_AFTER`] tries again.
    Failed,
}

/// The state of this process's Tor client. Returns at once, also while Tor
/// starts: it never waits for a start.
#[uniffi::export]
pub fn tor_state() -> TorState {
    PROCESS_TOR.state()
}

/// A Tor client started once, on first use, and shared. `T` is the client;
/// the tests use a stand-in.
///
/// Two locks: `state` is held only to read or write it, so [`Self::state`]
/// never waits for a start; `slot` is held through a start, so a start runs
/// once at a time and callers that come meanwhile wait for its outcome.
pub(crate) struct Shared<T> {
    state: Mutex<TorState>,
    slot: Mutex<Slot<T>>,
    retry_after: Duration,
}

struct Slot<T> {
    client: Option<Arc<T>>,
    /// When the last start failed, and its error's text, while no client
    /// runs.
    failed: Option<(Instant, String)>,
}

/// The lock's content, also after a panic in another thread that held it.
fn lock<V>(m: &Mutex<V>) -> MutexGuard<'_, V> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl<T> Shared<T> {
    pub(crate) const fn new(retry_after: Duration) -> Self {
        Self {
            state: Mutex::new(TorState::NotStarted),
            slot: Mutex::new(Slot {
                client: None,
                failed: None,
            }),
            retry_after,
        }
    }

    pub(crate) fn state(&self) -> TorState {
        *lock(&self.state)
    }

    /// The client, started with `start` if there is none yet. Callers that
    /// come while it starts wait for that start and then get its client or
    /// its error. Within `retry_after` of a failed start, every call fails at
    /// once with that start's error; the first call after that starts again.
    /// A start that panics is a failed start like any other (Arcium 2
    /// R275-1): the panic is caught here, so it neither leaves `Starting`
    /// behind nor skips the pause.
    pub(crate) fn get_or_start(
        &self,
        start: impl FnOnce() -> Result<T, TransportError>,
    ) -> Result<Arc<T>, CoreError> {
        let mut slot = lock(&self.slot);
        if let Some(client) = &slot.client {
            return Ok(Arc::clone(client));
        }
        if let Some((at, msg)) = &slot.failed {
            if at.elapsed() < self.retry_after {
                return Err(CoreError::Network { msg: msg.clone() });
            }
        }
        *lock(&self.state) = TorState::Starting;
        let started = std::panic::catch_unwind(std::panic::AssertUnwindSafe(start))
            .unwrap_or_else(|_| Err(TransportError::Bootstrap("the start panicked".into())));
        let (state, result) = match started {
            Ok(client) => {
                let client = Arc::new(client);
                slot.client = Some(Arc::clone(&client));
                slot.failed = None;
                (TorState::Running, Ok(client))
            }
            Err(TransportError::NeedsUpdate) => (
                TorState::NeedsUpdate,
                Err(CoreError::Network {
                    msg: "Tor needs an app update: the Tor network requires a newer version of this app"
                        .into(),
                }),
            ),
            Err(e) => (
                TorState::Failed,
                Err(CoreError::Network {
                    msg: format!("Tor did not start: {e}"),
                }),
            ),
        };
        if let Err(CoreError::Network { msg }) = &result {
            slot.failed = Some((Instant::now(), msg.clone()));
        }
        *lock(&self.state) = state;
        result
    }
}

/// The process's Tor client. It is never dropped: dropping its runtime from
/// inside an async context panics (`core_transport::TorConnector`), and the
/// process keeps it to the end.
static PROCESS_TOR: Shared<TorConnector> = Shared::new(RETRY_AFTER);

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

/// What [`OverTor`] needs of a Tor client: a stream to `addr` within
/// `timeout`. The process's client is a [`TorConnector`]; tests use a
/// stand-in.
pub(crate) trait Dial: Send + Sync {
    type Stream: TimedStream;
    fn dial(&self, addr: &str, timeout: Duration) -> io::Result<Self::Stream>;
}

impl Dial for TorConnector {
    type Stream = TorStream;
    fn dial(&self, addr: &str, timeout: Duration) -> io::Result<TorStream> {
        self.connect(addr, timeout)
    }
}

/// A stream with the read and write timeouts the relay client sets.
pub(crate) trait TimedStream: Read + Write + Send + 'static {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()>;
}

impl TimedStream for TorStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        TorStream::set_read_timeout(self, timeout)
    }
    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        TorStream::set_write_timeout(self, timeout)
    }
}

/// The relay client's [`Connector`] over a Tor client.
pub(crate) struct OverTor<D>(pub(crate) Arc<D>);

impl<D: Dial> Connector for OverTor<D> {
    /// Waits for the stream up to [`ONION_CONNECT_TIMEOUT`], or `timeout` if
    /// that is longer; the stream's reads and writes are then bounded by the
    /// connection's own `timeout`, which the relay client sets.
    fn connect(&self, addr: &str, timeout: Duration) -> io::Result<Box<dyn RelayStream>> {
        let stream = self.0.dial(addr, ONION_CONNECT_TIMEOUT.max(timeout))?;
        Ok(Box::new(TorRelayStream(stream)))
    }
}

/// A Tor stream as the relay client's [`RelayStream`]: every call passed on
/// as it is. A wrapper, since the trait and [`TorStream`] live in other
/// crates.
pub(crate) struct TorRelayStream<S>(pub(crate) S);

impl<S: TimedStream> Read for TorRelayStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<S: TimedStream> Write for TorRelayStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<S: TimedStream> RelayStream for TorRelayStream<S> {
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
    use std::sync::mpsc;

    #[test]
    fn onion_names_are_told_apart_from_other_hosts() {
        let onion = format!("{}.onion", "a".repeat(56));
        for host in [onion.as_str(), "x.onion", "X.ONION", "x.Onion.", "x.onion..", "onion"] {
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
        let shared = Shared::<u32>::new(Duration::ZERO);
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

    /// `NeedsUpdate` is its own state and its own error text; within the
    /// pause every call fails at once with that text and starts nothing; a
    /// call after the pause tries again.
    #[test]
    fn a_start_that_needs_an_update_says_so() {
        let paused = Shared::<u32>::new(Duration::from_secs(3600));
        let e = paused.get_or_start(|| Err(TransportError::NeedsUpdate)).err().unwrap();
        assert_eq!(paused.state(), TorState::NeedsUpdate);
        assert!(
            matches!(&e, CoreError::Network { msg } if msg.starts_with("Tor needs an app update")),
            "{e}"
        );
        let again = paused.get_or_start(|| panic!("started within the pause")).err().unwrap();
        assert_eq!(again.to_string(), e.to_string());
        assert_eq!(paused.state(), TorState::NeedsUpdate);

        let unpaused = Shared::<u32>::new(Duration::ZERO);
        let _ = unpaused.get_or_start(|| Err(TransportError::NeedsUpdate));
        assert_eq!(*unpaused.get_or_start(|| Ok(3)).unwrap(), 3);
        assert_eq!(unpaused.state(), TorState::Running);
    }

    /// The process's client waits 60 s after a failed start before it tries
    /// again (the tests above use their own pauses).
    #[test]
    fn the_process_client_pauses_60_s_after_a_failed_start() {
        assert_eq!(RETRY_AFTER, Duration::from_secs(60));
        assert_eq!(PROCESS_TOR.retry_after, RETRY_AFTER);
    }

    /// A failed start is `Failed`; within the pause every call fails at once
    /// with its error and starts nothing; after it, a call starts again.
    #[test]
    fn after_a_failed_start_calls_fail_at_once_until_the_pause_ends() {
        let paused = Shared::<u32>::new(Duration::from_secs(3600));
        let failing = || Err(TransportError::Bootstrap("no network".into()));
        let e = paused.get_or_start(failing).err().unwrap();
        assert_eq!(paused.state(), TorState::Failed);
        assert!(matches!(&e, CoreError::Network { msg } if msg.contains("no network")), "{e}");
        let again = paused.get_or_start(|| panic!("started within the pause")).err().unwrap();
        assert_eq!(again.to_string(), e.to_string());
        assert_eq!(paused.state(), TorState::Failed);

        let unpaused = Shared::<u32>::new(Duration::ZERO);
        let _ = unpaused.get_or_start(failing);
        assert_eq!(*unpaused.get_or_start(|| Ok(4)).unwrap(), 4);
    }

    /// `state` answers at once while a start runs, and says `Starting`; a
    /// caller that comes meanwhile waits for that start and does not start
    /// another when it fails.
    #[test]
    fn the_state_never_waits_for_a_start_and_a_failing_start_runs_once() {
        let shared = Arc::new(Shared::<u32>::new(Duration::from_secs(3600)));
        let starts = Arc::new(AtomicU32::new(0));
        let (release, released) = mpsc::channel::<()>();
        let first = {
            let (shared, starts) = (Arc::clone(&shared), Arc::clone(&starts));
            std::thread::spawn(move || {
                shared.get_or_start(|| {
                    starts.fetch_add(1, SeqCst);
                    released.recv().unwrap();
                    Err(TransportError::Bootstrap("no network".into()))
                })
            })
        };
        let began = Instant::now();
        while shared.state() != TorState::Starting {
            assert!(began.elapsed() < Duration::from_secs(5), "the start did not begin");
            std::thread::sleep(Duration::from_millis(5));
        }
        let asked = Instant::now();
        assert_eq!(shared.state(), TorState::Starting);
        assert!(asked.elapsed() < Duration::from_secs(1), "state waited for the start");
        let second = {
            let (shared, starts) = (Arc::clone(&shared), Arc::clone(&starts));
            std::thread::spawn(move || {
                shared.get_or_start(|| {
                    starts.fetch_add(1, SeqCst);
                    Ok(1)
                })
            })
        };
        std::thread::sleep(Duration::from_millis(50));
        release.send(()).unwrap();
        assert!(first.join().unwrap().is_err());
        assert!(second.join().unwrap().is_err(), "the waiting caller started Tor again");
        assert_eq!((starts.load(SeqCst), shared.state()), (1, TorState::Failed));
    }

    /// A start that panics is a failed start: its error, `Failed` (not
    /// `Starting`), and the pause, within which nothing starts (Arcium 2
    /// R275-1); after the pause, a call starts again.
    #[test]
    fn a_start_that_panics_fails_and_pauses_like_any_failed_start() {
        let paused = Shared::<u32>::new(Duration::from_secs(3600));
        let e = paused.get_or_start(|| panic!("a start panicked")).err().unwrap();
        assert!(matches!(&e, CoreError::Network { msg } if msg == "Tor did not start: bootstrap failed: the start panicked"), "{e}");
        assert_eq!(paused.state(), TorState::Failed);
        let again = paused.get_or_start(|| panic!("started within the pause")).err().unwrap();
        assert_eq!(again.to_string(), e.to_string());
        assert_eq!(paused.state(), TorState::Failed);

        let unpaused = Shared::<u32>::new(Duration::ZERO);
        let _ = unpaused.get_or_start(|| panic!("a start panicked"));
        assert_eq!(*unpaused.get_or_start(|| Ok(5)).unwrap(), 5);
        assert_eq!(unpaused.state(), TorState::Running);
    }

    /// Stands in for a Tor client: records the timeout of each dial, and
    /// what is done to its stream: the timeouts it is given (`r`, `w`), each
    /// flush (`f`) and the bytes written to it. Each stream reads `pong`.
    struct StandIn {
        dials: Mutex<Vec<(String, Duration)>>,
        calls: Arc<Mutex<Vec<(char, Option<Duration>)>>>,
        written: Arc<Mutex<Vec<u8>>>,
    }

    struct StandInStream {
        calls: Arc<Mutex<Vec<(char, Option<Duration>)>>>,
        written: Arc<Mutex<Vec<u8>>>,
        unread: &'static [u8],
    }

    impl Read for StandInStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = buf.len().min(self.unread.len());
            buf[..n].copy_from_slice(&self.unread[..n]);
            self.unread = &self.unread[n..];
            Ok(n)
        }
    }

    impl Write for StandInStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.calls.lock().unwrap().push(('f', None));
            Ok(())
        }
    }

    impl TimedStream for StandInStream {
        fn set_read_timeout(&mut self, t: Option<Duration>) -> io::Result<()> {
            self.calls.lock().unwrap().push(('r', t));
            Ok(())
        }
        fn set_write_timeout(&mut self, t: Option<Duration>) -> io::Result<()> {
            self.calls.lock().unwrap().push(('w', t));
            Ok(())
        }
    }

    impl Dial for StandIn {
        type Stream = StandInStream;
        fn dial(&self, addr: &str, timeout: Duration) -> io::Result<StandInStream> {
            self.dials.lock().unwrap().push((addr.to_string(), timeout));
            Ok(StandInStream {
                calls: Arc::clone(&self.calls),
                written: Arc::clone(&self.written),
                unread: b"pong",
            })
        }
    }

    /// The connector waits up to 60 s for a stream (longer only if the
    /// connection's own timeout is longer), asks for the address as given,
    /// and passes every call on to the Tor stream: reads, writes, flushes,
    /// and every read and write timeout.
    #[test]
    fn over_tor_waits_60_s_for_a_stream_and_passes_every_call_on() {
        let tor = Arc::new(StandIn {
            dials: Mutex::new(Vec::new()),
            calls: Arc::new(Mutex::new(Vec::new())),
            written: Arc::new(Mutex::new(Vec::new())),
        });
        let connector = OverTor(Arc::clone(&tor));
        let mut stream = connector.connect("x.onion:443", Duration::from_secs(10)).unwrap();
        connector.connect("x.onion:443", Duration::from_secs(90)).unwrap();
        assert_eq!(
            *tor.dials.lock().unwrap(),
            vec![
                ("x.onion:443".to_string(), ONION_CONNECT_TIMEOUT),
                ("x.onion:443".to_string(), Duration::from_secs(90)),
            ]
        );
        assert_eq!(ONION_CONNECT_TIMEOUT, Duration::from_secs(60));
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(4))).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.flush().unwrap();
        stream.set_read_timeout(None).unwrap();
        let mut read = Vec::new();
        stream.read_to_end(&mut read).unwrap();
        assert_eq!(read, b"pong");
        assert_eq!(*tor.written.lock().unwrap(), b"ping");
        assert_eq!(
            *tor.calls.lock().unwrap(),
            vec![
                ('r', Some(Duration::from_secs(3))),
                ('w', Some(Duration::from_secs(4))),
                ('f', None),
                ('r', None),
            ]
        );
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
        let installed = rustls::crypto::CryptoProvider::get_default().expect("no provider installed");
        let ring = rustls::crypto::ring::default_provider();
        let suites = |p: &rustls::crypto::CryptoProvider| p.cipher_suites.iter().map(|s| s.suite()).collect::<Vec<_>>();
        assert_eq!(suites(installed), suites(&ring));
        assert_eq!(core.tor_dir, dir.path().join("tor"));
    }
}
