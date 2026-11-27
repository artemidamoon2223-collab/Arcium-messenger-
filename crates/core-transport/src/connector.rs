//! A blocking Tor connector for the relay client.
//!
//! The relay client (`relay::client`) is blocking. It runs over a stream on
//! which it sets a read timeout before every read and a write timeout before
//! every write and every flush (`relay::client::RelayStream`), and it opens
//! that stream with `relay::client::Connector::connect(addr, timeout)`.
//! [`TorConnector`] and [`TorStream`] have exactly that shape over arti's
//! async `DataStream`.
//!
//! This crate does not depend on `relay`: the app joins the two with a thin
//! wrapper. A transport crate should not pull in the relay server and its
//! SQLite build; and relay's rustls `ring` feature would join this crate's
//! own build, so CI's `cargo test -p core-transport` step would no longer
//! show that this crate turns `ring` on itself.

use std::future::Future;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arti_client::DataStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::runtime::Runtime;

use crate::{Start, TorTransport, TransportError, BOOTSTRAP_TIMEOUT};

/// Opens streams over Tor, on a multi-thread tokio runtime its Tor client
/// runs on. Every stream it opens shares that runtime, so after the
/// connector is dropped a stream's calls stay bounded and end with a result
/// or an error, not a panic (tested with a stand-in stream; whether arti's
/// stream still carries data without its client is not tested). Every
/// method blocks the calling thread, and none may be called from inside an
/// async context (tokio panics there); the last owner of the runtime must
/// not drop it there either.
pub struct TorConnector {
    transport: TorTransport,
    runtime: Arc<Runtime>,
}

impl TorConnector {
    /// Bootstraps a Tor client that keeps its state under `state_dir`,
    /// giving up after [`BOOTSTRAP_TIMEOUT`].
    pub fn bootstrap(state_dir: &Path) -> Result<Self, TransportError> {
        Self::start(state_dir, Start::Bootstrap(BOOTSTRAP_TIMEOUT))
    }

    fn start(state_dir: &Path, start: Start) -> Result<Self, TransportError> {
        let runtime = Arc::new(tokio::runtime::Builder::new_multi_thread().enable_all().build()?);
        let transport = runtime.block_on(TorTransport::create(state_dir, start))?;
        Ok(Self { transport, runtime })
    }

    /// Opens a stream to `addr`, `host:port` as written: a DNS name, a public
    /// IP address or an onion name. No name is looked up on this device; Tor
    /// does it (an exit relay for a DNS name, the onion service protocol for
    /// an onion name). A local or private address (`localhost`, `127.0.0.1`,
    /// `10.0.2.2`, `[::1]`, ...) is refused by arti at once, before anything
    /// is sent: Tor exits refuse those. Returns, with a stream or an error,
    /// within `timeout`; a timeout is `TimedOut`, a zero `timeout` is refused
    /// with `InvalidInput`, and arti's errors are `Other`.
    pub fn connect(&self, addr: &str, timeout: Duration) -> io::Result<TorStream> {
        let client = &self.transport.client;
        open(&self.runtime, timeout, async {
            client.connect(addr).await.map_err(io::Error::other)
        })
    }
}

/// Runs `connecting` for at most `timeout` and wraps the stream it opens.
fn open<S>(
    runtime: &Arc<Runtime>,
    timeout: Duration,
    connecting: impl Future<Output = io::Result<S>>,
) -> io::Result<TorStream<S>> {
    let timeout = checked(Some(timeout))?;
    let inner = runtime.block_on(within(timeout, connecting))?;
    Ok(TorStream::new(Arc::clone(runtime), inner))
}

/// A stream over Tor with the blocking interface the relay client uses:
/// [`Read`], [`Write`], and a read timeout it sets before each read and a
/// write timeout it sets before each write and each flush.
///
/// - A read waits at most the read timeout and a write at most the write
///   timeout, then fails with `TimedOut`.
/// - arti holds written bytes until a flush. A flush waits at most until the
///   write timeout set last runs out, counted from when it was set; then
///   `TimedOut`. A flush whose time has already run out still completes if
///   it has nothing to wait for.
/// - `None` means no bound. `Some(Duration::ZERO)` is refused with
///   `InvalidInput`, as `TcpStream` refuses it.
/// - After a timeout the stream's state is unknown; the relay client drops
///   the connection on any error.
///
/// Every method blocks the calling thread and may not be called from inside
/// an async context. A stream dropped after its connector may hold the last
/// share of the runtime: dropping it then shuts the runtime down, which
/// blocks the dropping thread until the runtime's threads stop and panics
/// inside an async context. `S` is arti's stream; the parameter exists for
/// tests.
pub struct TorStream<S = DataStream> {
    // Declared before `runtime`: dropped while the runtime still runs.
    inner: S,
    runtime: Arc<Runtime>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    /// When the write timeout set last runs out: the bound of a flush.
    flush_deadline: Option<Instant>,
}

impl<S> TorStream<S> {
    fn new(runtime: Arc<Runtime>, inner: S) -> Self {
        Self {
            inner,
            runtime,
            read_timeout: None,
            write_timeout: None,
            flush_deadline: None,
        }
    }

    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.read_timeout = checked(timeout)?;
        Ok(())
    }

    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.write_timeout = checked(timeout)?;
        // A timeout too long to add to now bounds no flush, as `None`.
        self.flush_deadline = self.write_timeout.and_then(|t| Instant::now().checked_add(t));
        Ok(())
    }
}

impl<S: AsyncRead + Unpin> Read for TorStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bound = self.read_timeout;
        let inner = &mut self.inner;
        self.runtime.block_on(within(bound, inner.read(buf)))
    }
}

impl<S: AsyncWrite + Unpin> Write for TorStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let bound = self.write_timeout;
        let inner = &mut self.inner;
        self.runtime.block_on(within(bound, inner.write(buf)))
    }

    fn flush(&mut self) -> io::Result<()> {
        let bound = self.flush_deadline.map(|d| d.saturating_duration_since(Instant::now()));
        let inner = &mut self.inner;
        self.runtime.block_on(within(bound, inner.flush()))
    }
}

/// `timeout`, unless it is `Some(Duration::ZERO)`, which never means "no
/// timeout".
fn checked(timeout: Option<Duration>) -> io::Result<Option<Duration>> {
    if timeout == Some(Duration::ZERO) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot set a 0 duration timeout",
        ));
    }
    Ok(timeout)
}

/// `io`, given at most `bound` (none for `None`), then `TimedOut`. A bound of
/// zero still polls `io` once.
async fn within<T>(
    bound: Option<Duration>,
    io: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    match bound {
        None => io.await,
        Some(bound) => tokio::time::timeout(bound, io).await.unwrap_or_else(|_| {
            Err(io::Error::new(io::ErrorKind::TimedOut, "Tor stream timed out"))
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    fn runtime() -> Arc<Runtime> {
        Arc::new(tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap())
    }

    fn timed_out<T: std::fmt::Debug>(r: io::Result<T>) -> bool {
        matches!(&r, Err(e) if e.kind() == io::ErrorKind::TimedOut)
    }

    /// Runs `f` on its own thread and gives its result with the time it
    /// took. A call with no bound fails the test after 10 s instead of
    /// hanging it.
    fn bounded<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> (T, Duration) {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let started = Instant::now();
            let out = f();
            let _ = tx.send((out, started.elapsed()));
        });
        rx.recv_timeout(Duration::from_secs(10))
            .expect("did not return within 10 s: the call has no bound")
    }

    /// The stream the relay client gets is `Send`, as `RelayStream` needs.
    #[test]
    fn a_tor_stream_over_arti_is_send() {
        fn send<T: Send>() {}
        send::<TorStream>();
    }

    /// Bytes written and flushed reach the other end, and its answer is read.
    #[test]
    fn bytes_pass_both_ways() {
        let rt = runtime();
        let (near, mut far) = tokio::io::duplex(64);
        rt.spawn(async move {
            let mut buf = [0u8; 5];
            far.read_exact(&mut buf).await.unwrap();
            far.write_all(&buf).await.unwrap();
        });
        let mut s = TorStream::new(Arc::clone(&rt), near);
        let (back, _) = bounded(move || {
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            s.write_all(b"hello").unwrap();
            s.flush().unwrap();
            let mut back = [0u8; 5];
            s.read_exact(&mut back).unwrap();
            back
        });
        assert_eq!(&back, b"hello");
    }

    /// A read with nothing to read fails at the read timeout.
    #[test]
    fn a_read_fails_at_the_read_timeout() {
        let rt = runtime();
        let (near, _far) = tokio::io::duplex(64);
        let mut s = TorStream::new(Arc::clone(&rt), near);
        s.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let (r, took) = bounded(move || s.read(&mut [0u8; 8]));
        assert!(timed_out(r));
        assert!(took >= Duration::from_millis(180) && took < Duration::from_secs(2), "took {took:?}");
    }

    /// A write that cannot proceed (the other end reads nothing and the
    /// buffer is full) fails at the write timeout.
    #[test]
    fn a_write_fails_at_the_write_timeout() {
        let rt = runtime();
        let (near, _far) = tokio::io::duplex(8);
        let mut s = TorStream::new(Arc::clone(&rt), near);
        s.set_write_timeout(Some(Duration::from_millis(200))).unwrap();
        let (r, took) = bounded(move || s.write_all(&[0u8; 64]));
        assert!(timed_out(r));
        assert!(took >= Duration::from_millis(180) && took < Duration::from_secs(2), "took {took:?}");
    }

    /// Takes every write; its flush never finishes, as a stream holding
    /// bytes it cannot send.
    struct StalledFlush;

    impl AsyncWrite for StalledFlush {
        fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A flush that cannot finish fails when the write timeout set last runs
    /// out, counted from when it was set, not from the start of the flush.
    #[test]
    fn a_flush_fails_when_the_write_timeout_set_last_runs_out() {
        let rt = runtime();
        let mut s = TorStream::new(Arc::clone(&rt), StalledFlush);
        let set = Instant::now();
        s.set_write_timeout(Some(Duration::from_millis(400))).unwrap();
        s.write_all(b"frame").unwrap();
        std::thread::sleep(Duration::from_millis(200));
        let (r, flush_took) = bounded(move || s.flush());
        assert!(timed_out(r));
        let since_set = set.elapsed();
        assert!(since_set >= Duration::from_millis(380), "since set {since_set:?}");
        assert!(flush_took < Duration::from_millis(350), "the flush took {flush_took:?}");
    }

    /// A zero timeout is refused, never taken as "no timeout".
    #[test]
    fn a_zero_timeout_is_refused() {
        let rt = runtime();
        let (near, _far) = tokio::io::duplex(8);
        let mut s = TorStream::new(Arc::clone(&rt), near);
        for r in [
            s.set_read_timeout(Some(Duration::ZERO)),
            s.set_write_timeout(Some(Duration::ZERO)),
        ] {
            assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }
        let r = open(&rt, Duration::ZERO, async { Ok(()) });
        assert_eq!(r.err().map(|e| e.kind()), Some(io::ErrorKind::InvalidInput));
    }

    /// A connect that never finishes fails at its timeout; one that finishes
    /// in time gives its stream.
    #[test]
    fn a_connect_returns_within_its_timeout() {
        let rt = runtime();
        let shared = Arc::clone(&rt);
        let (r, took) = bounded(move || {
            open(&shared, Duration::from_millis(200), std::future::pending::<io::Result<()>>()).map(|_| ())
        });
        assert!(timed_out(r));
        assert!(took >= Duration::from_millis(180) && took < Duration::from_secs(2), "took {took:?}");
        let (near, _far) = tokio::io::duplex(8);
        assert!(open(&rt, Duration::from_secs(2), async { Ok(near) }).is_ok());
    }

    /// A connector made as `bootstrap` makes one, over a client that never
    /// bootstraps: offline, no network is touched.
    fn unbootstrapped(state_dir: &Path) -> TorConnector {
        TorConnector::start(state_dir, Start::Unbootstrapped).unwrap()
    }

    /// arti's error comes back as an `io::Error` at once. Here: a client that
    /// may not bootstrap by itself refuses to connect.
    #[test]
    fn an_arti_error_is_an_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let connector = unbootstrapped(dir.path());
        let started = Instant::now();
        let err = connector.connect("relay.example.com:443", Duration::from_secs(5)).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::Other, "{err}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    /// The connector's runtime runs tasks while no call is blocking on it:
    /// arti's circuit and channel tasks must run between requests. On a
    /// current-thread runtime they would run only inside a call.
    #[test]
    fn background_tasks_run_between_calls() {
        use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
        let dir = tempfile::tempdir().unwrap();
        let connector = unbootstrapped(dir.path());
        let ran = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&ran);
        connector.runtime.spawn(async move { flag.store(true, SeqCst) });
        let started = Instant::now();
        while !ran.load(SeqCst) && started.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(ran.load(SeqCst), "a task did not run while no call was blocking");
    }

    /// A local or private address is refused at once, before anything is
    /// sent (arti's `allow_local_addrs` is off). The text is arti's: it tells
    /// this refusal apart from the one above.
    #[test]
    fn a_local_address_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let connector = unbootstrapped(dir.path());
        for addr in ["127.0.0.1:7700", "10.0.2.2:7700", "localhost:7700", "[::1]:7700"] {
            let started = Instant::now();
            let err = connector.connect(addr, Duration::from_secs(5)).err().unwrap();
            assert_eq!(err.kind(), io::ErrorKind::Other, "{addr}: {err}");
            assert!(err.to_string().contains("allow_local_addrs"), "{addr}: {err}");
            assert!(started.elapsed() < Duration::from_secs(2), "{addr}");
        }
    }

    /// A stream keeps the runtime it runs on: with every other owner of the
    /// runtime gone (the connector dropped), a read is still bounded and
    /// fails with an error, not a panic.
    #[test]
    fn a_stream_outlives_its_connector() {
        let rt = runtime();
        let (near, _far) = tokio::io::duplex(8);
        let mut s = TorStream::new(Arc::clone(&rt), near);
        drop(rt);
        s.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let (r, _) = bounded(move || s.read(&mut [0u8; 8]));
        assert!(timed_out(r));
    }

    /// A write timeout too long to add to now is accepted, as `TcpStream`
    /// accepts it, and bounds no flush.
    #[test]
    fn the_longest_write_timeout_is_accepted() {
        let rt = runtime();
        let (near, _far) = tokio::io::duplex(8);
        let mut s = TorStream::new(Arc::clone(&rt), near);
        s.set_write_timeout(Some(Duration::MAX)).unwrap();
        let (r, _) = bounded(move || s.flush());
        r.unwrap();
    }

    /// Every form of `host:port` a relay connection string gives (a lowercase
    /// DNS name, an IPv4 address, an IPv6 address in brackets, an onion name:
    /// `relay::address::RelayAddress::socket_addr`) is a Tor address as
    /// written, and only an IP address is taken as one.
    #[test]
    fn every_relay_address_form_is_a_tor_address() {
        use arti_client::IntoTorAddr;
        let onion = format!("{}.onion:443", "a".repeat(56));
        for (addr, ip) in [
            ("relay.example.com:443", false),
            ("203.0.113.7:8443", true),
            ("[2001:db8::1]:443", true),
            (onion.as_str(), false),
        ] {
            let tor = addr.into_tor_addr().unwrap();
            assert_eq!(tor.to_string(), addr);
            assert_eq!(tor.is_ip_address(), ip, "{addr}");
        }
    }
}
