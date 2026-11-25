//! A blocking client for one relay connection: `RELAY_PROTOCOL_V1` over plain
//! TCP ([`Connection::connect`], for development and tests only), or
//! `RELAY_PROTOCOL_V2` over TLS 1.3 with the relay's pinned key
//! ([`Connection::connect_v2`]) and mailbox authentication
//! ([`Connection::authenticate`]). The operations are the same on both.
//!
//! Both run over plain TCP ([`TcpConnector`]) unless the caller passes
//! another [`Connector`] ([`Connection::connect_with`],
//! [`Connection::connect_v2_with`]); the protocol and TLS above the stream
//! are the same whichever opened it.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use rustls::{ClientConnection, StreamOwned};
use zeroize::Zeroizing;

use crate::address::RelayAddress;
use crate::auth::{auth_tag, AUTH_LEN, EXPORTER_LABEL};
use crate::protocol::*;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The relay could not be reached or the connection broke. Whether the
    /// last request took effect is unknown.
    #[error("relay unreachable or connection lost: {0}")]
    Network(#[from] io::Error),
    #[error("relay protocol: {0}")]
    Protocol(ProtocolError),
    #[error("relay refused the request: {0:?}")]
    Refused(ErrorCode),
    #[error("unexpected relay response")]
    Unexpected,
    /// V2: the TLS handshake failed. Among other causes: the relay's key is
    /// not the pinned one.
    #[error("relay TLS handshake failed: {0}")]
    Tls(rustls::Error),
    /// V2: this connection cannot authenticate; nothing was sent.
    #[error("cannot authenticate to the relay: {0}")]
    Auth(&'static str),
}

impl From<ProtocolError> for ClientError {
    fn from(e: ProtocolError) -> Self {
        match e {
            ProtocolError::Io(e) => ClientError::Network(e),
            e => ClientError::Protocol(e),
        }
    }
}

/// Longest time one request may take, from writing it to reading the whole
/// response. The connection's timeout bounds each read, write and flush; this
/// bounds their sum, so a relay that trickles bytes cannot hold a request open.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(30);

pub struct Connection {
    transport: Transport,
    /// Bound of every request as a whole ([`REQUEST_DEADLINE`] by default).
    request_deadline: Duration,
    /// V2 only: what AUTH binds to.
    session: Option<Session>,
}

/// What a V2 connection's AUTH is computed from.
struct Session {
    auth_pk: Key,
    challenge: [u8; CHALLENGE_LEN],
    exporter: Zeroizing<[u8; AUTH_LEN]>,
}

/// The stream: every read, write and flush waits at most for what is left of
/// `deadline` (and at most `idle`), and fails with `TimedOut` once nothing is
/// left. Under TLS this bounds every socket read, write and flush rustls makes,
/// so a relay that trickles TLS records cannot hold a request open either.
struct Socket {
    stream: Box<dyn RelayStream>,
    /// Bound of every single read, write and flush.
    idle: Duration,
    /// End of the current request (or of the V2 handshake).
    deadline: Instant,
}

impl Socket {
    fn remaining(&self) -> io::Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "relay request deadline passed"));
        }
        Ok(left.min(self.idle))
    }
}

impl Read for Socket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let wait = self.remaining()?;
        self.stream.set_read_timeout(Some(wait))?;
        self.stream.read(buf)
    }
}

impl Write for Socket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let wait = self.remaining()?;
        self.stream.set_write_timeout(Some(wait))?;
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let wait = self.remaining()?;
        self.stream.set_write_timeout(Some(wait))?;
        self.stream.flush()
    }
}

enum Transport {
    Plain(Socket),
    Tls(Box<StreamOwned<ClientConnection, Socket>>),
}

impl Transport {
    fn socket(&mut self) -> &mut Socket {
        match self {
            Transport::Plain(s) => s,
            Transport::Tls(t) => &mut t.sock,
        }
    }
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Transport::Plain(s) => s.read(buf),
            Transport::Tls(t) => t.read(buf),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Transport::Plain(s) => s.write(buf),
            Transport::Tls(t) => t.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Transport::Plain(s) => s.flush(),
            Transport::Tls(t) => t.flush(),
        }
    }
}

/// The byte stream a [`Connection`] runs on, as a [`Connector`] opens it.
/// Before every read the connection sets the read timeout, and before every
/// write and every flush the write timeout, to what is left of the current
/// deadline (at most the connection's `timeout`); a read, write or flush that
/// runs out of that time must fail, or the deadline does not hold. A stream
/// that holds written bytes until a flush must finish that flush, or fail,
/// within the write timeout set just before it.
///
/// A timeout of `Some(Duration::ZERO)` reaches the stream only when the
/// connection's `timeout` is zero. It never means "no timeout": refuse it
/// with an error or fail at once (`TcpStream` refuses it).
pub trait RelayStream: Read + Write + Send {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()>;
}

impl RelayStream for TcpStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_write_timeout(self, timeout)
    }
}

/// Opens the stream to a relay. `addr` is `host:port` as the caller gave it
/// (for V2, [`RelayAddress::socket_addr`]), not resolved: a connector that
/// must not resolve a name on this device, such as one that reaches an
/// onion address over Tor, passes it on as it is. An error here is
/// [`ClientError::Network`].
///
/// `timeout` is the connection's timeout. The client sets no deadline on
/// `connect` and starts the first one only after it returns, so a connector
/// should return, with a stream or an error, within `timeout`.
/// [`TcpConnector`] does not fully: its name lookup has no bound (tracker
/// R-4).
pub trait Connector {
    fn connect(&self, addr: &str, timeout: Duration) -> io::Result<Box<dyn RelayStream>>;
}

/// Plain TCP, the connector of [`Connection::connect`] and
/// [`Connection::connect_v2`]: resolves `addr` on this device, connects to
/// its first address within `timeout`, bounds every read and write by
/// `timeout`, and turns off Nagle's algorithm. It hands the host name to
/// this device's resolver, so it is not for an onion address.
pub struct TcpConnector;

impl Connector for TcpConnector {
    fn connect(&self, addr: &str, timeout: Duration) -> io::Result<Box<dyn RelayStream>> {
        let target = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address"))?;
        let tcp = TcpStream::connect_timeout(&target, timeout)?;
        tcp.set_read_timeout(Some(timeout))?;
        tcp.set_write_timeout(Some(timeout))?;
        tcp.set_nodelay(true)?;
        Ok(Box::new(tcp))
    }
}

/// The stream `connector` opens to `addr`, with every read and write bounded
/// by `timeout`, and a first deadline [`REQUEST_DEADLINE`] from now.
fn open(connector: &dyn Connector, addr: &str, timeout: Duration) -> Result<Socket, ClientError> {
    let stream = connector.connect(addr, timeout)?;
    Ok(Socket {
        stream,
        idle: timeout,
        deadline: Instant::now() + REQUEST_DEADLINE,
    })
}

/// A TLS failure as [`ClientError::Tls`], anything else as a network error.
fn tls_error(e: io::Error) -> ClientError {
    match e.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()) {
        Some(tls) => ClientError::Tls(tls.clone()),
        None => ClientError::Network(e),
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "relay closed the connection")
}

impl Connection {
    /// Connects to `addr` (`host:port`) with `RELAY_PROTOCOL_V1`: plain TCP,
    /// for development and tests only. Every read and write times out after
    /// `timeout`, and every request as a whole after [`REQUEST_DEADLINE`].
    pub fn connect(addr: &str, timeout: Duration) -> Result<Self, ClientError> {
        Self::connect_with(&TcpConnector, addr, timeout)
    }

    /// As [`Self::connect`], over the stream `connector` opens to `addr`.
    pub fn connect_with(
        connector: &dyn Connector,
        addr: &str,
        timeout: Duration,
    ) -> Result<Self, ClientError> {
        Ok(Self {
            transport: Transport::Plain(open(connector, addr, timeout)?),
            request_deadline: REQUEST_DEADLINE,
            session: None,
        })
    }

    /// Connects to the relay of `addr` with `RELAY_PROTOCOL_V2`: a TLS 1.3
    /// handshake that succeeds only if the relay presents the key `addr`
    /// pins, then the relay's HELLO. Every read and write times out after
    /// `timeout`; the handshake and HELLO together, and later every request
    /// as a whole, after [`REQUEST_DEADLINE`]. A handshake failure, a wrong
    /// key included, is [`ClientError::Tls`].
    pub fn connect_v2(addr: &RelayAddress, timeout: Duration) -> Result<Self, ClientError> {
        Self::connect_v2_with(&TcpConnector, addr, timeout)
    }

    /// As [`Self::connect_v2`], over the stream `connector` opens to
    /// [`RelayAddress::socket_addr`]. The TLS handshake, the pinned key and
    /// HELLO are the same whichever connector opened the stream.
    pub fn connect_v2_with(
        connector: &dyn Connector,
        addr: &RelayAddress,
        timeout: Duration,
    ) -> Result<Self, ClientError> {
        let socket = open(connector, &addr.socket_addr(), timeout)?;
        let config = crate::tls::client_config(*addr.tls_pin()).map_err(ClientError::Tls)?;
        let conn = ClientConnection::new(config, crate::tls::server_name()).map_err(ClientError::Tls)?;
        let mut stream = StreamOwned::new(conn, socket);
        while stream.conn.is_handshaking() {
            stream.conn.complete_io(&mut stream.sock).map_err(tls_error)?;
        }
        let hello = read_frame(&mut stream)?.ok_or_else(closed)?;
        let challenge = decode_hello(&hello)?;
        let exporter = stream
            .conn
            .export_keying_material(Zeroizing::new([0u8; AUTH_LEN]), EXPORTER_LABEL, None)
            .map_err(ClientError::Tls)?;
        Ok(Self {
            transport: Transport::Tls(Box::new(stream)),
            request_deadline: REQUEST_DEADLINE,
            session: Some(Session {
                auth_pk: *addr.auth_pk(),
                challenge,
                exporter,
            }),
        })
    }

    /// Bounds every later request as a whole by `deadline` instead of
    /// [`REQUEST_DEADLINE`].
    pub fn set_request_deadline(&mut self, deadline: Duration) {
        self.request_deadline = deadline;
    }

    fn call(&mut self, req: &Request) -> Result<Response, ClientError> {
        self.transport.socket().deadline = Instant::now() + self.request_deadline;
        write_frame(&mut self.transport, &req.encode())?;
        let body = read_frame(&mut self.transport)?.ok_or_else(closed)?;
        match Response::decode(req, &body)? {
            Response::Error(code) => Err(ClientError::Refused(code)),
            r => Ok(r),
        }
    }

    /// V2: proves to the relay that this connection acts for `owner`, an
    /// X25519 identity public key. Its secret stays with the caller: `dh` is
    /// given the relay's auth public key and writes `DH(id_sk, auth_pk)` into
    /// the second argument, a buffer this method owns and wipes, so the
    /// output is never returned by value and left behind as a copy.
    ///
    /// Afterwards FETCH, FETCH_AFTER, DELETE and PUT_BUNDLE are answered for
    /// `owner` only, and SEND only for an envelope that names `owner` as its
    /// sender ([`ENVELOPE_SENDER`](crate::protocol::ENVELOPE_SENDER)); without
    /// AUTH a V2 relay stores no SEND. The relay checks one AUTH per connection: a wrong tag,
    /// and any AUTH after the first, is [`ClientError::Refused`] with
    /// [`ErrorCode::Unauthorized`]. [`ClientError::Auth`], with nothing sent,
    /// on a V1 connection or if `dh` leaves the buffer all zeros (as it
    /// starts).
    pub fn authenticate(
        &mut self,
        owner: Key,
        dh: impl FnOnce(&[u8; 32], &mut [u8; 32]),
    ) -> Result<(), ClientError> {
        let session = self.session.as_ref().ok_or(ClientError::Auth("not a V2 connection"))?;
        let mut shared = Zeroizing::new([0u8; 32]);
        dh(&session.auth_pk, &mut shared);
        let tag = auth_tag(&shared, &session.challenge, &session.exporter, &owner)
            .ok_or(ClientError::Auth("the DH output is all zeros"))?;
        self.send_auth(owner, tag)
    }

    /// Sends AUTH with `tag` as it is.
    pub(crate) fn send_auth(&mut self, owner: Key, tag: [u8; AUTH_LEN]) -> Result<(), ClientError> {
        match self.call(&Request::Auth { owner, tag })? {
            Response::Ok => Ok(()),
            _ => Err(ClientError::Unexpected),
        }
    }

    /// Test aid: this connection's challenge and TLS exporter.
    #[cfg(test)]
    pub(crate) fn binding(&self) -> ([u8; AUTH_LEN], [u8; AUTH_LEN]) {
        let s = self.session.as_ref().expect("a V2 connection");
        (s.challenge, *s.exporter)
    }

    /// Test aid: the tag [`Connection::authenticate`] would send for `owner`
    /// on this connection, from `shared`.
    #[cfg(test)]
    pub(crate) fn tag_for(&self, owner: &Key, shared: &[u8; 32]) -> [u8; AUTH_LEN] {
        let s = self.session.as_ref().expect("a V2 connection");
        auth_tag(shared, &s.challenge, &s.exporter, owner).expect("a nonzero shared secret")
    }

    pub fn put_bundle(&mut self, owner: Key, bundle: Vec<u8>) -> Result<(), ClientError> {
        match self.call(&Request::PutBundle { owner, bundle })? {
            Response::Ok => Ok(()),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub fn get_bundle(&mut self, owner: Key) -> Result<Option<Vec<u8>>, ClientError> {
        match self.call(&Request::GetBundle { owner })? {
            Response::Bundle(b) => Ok(Some(b)),
            Response::NotFound => Ok(None),
            _ => Err(ClientError::Unexpected),
        }
    }

    /// Stores `envelope` for `recipient`; the relay's sequence number for it.
    /// This is transport acceptance only, not delivery.
    pub fn send(&mut self, recipient: Key, envelope: Vec<u8>) -> Result<u64, ClientError> {
        match self.call(&Request::Send {
            recipient,
            envelope,
        })? {
            Response::Accepted { seq } => Ok(seq),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub fn fetch(&mut self, recipient: Key, max: u16) -> Result<Vec<(u64, Vec<u8>)>, ClientError> {
        match self.call(&Request::Fetch { recipient, max })? {
            Response::Items(items) => Ok(items),
            _ => Err(ClientError::Unexpected),
        }
    }

    /// The envelopes after sequence number `after`, in ascending order, at
    /// most `max` (FETCH_AFTER). As returned by the relay, which is not
    /// trusted to honour the order or the bound; callers check both.
    pub fn fetch_after(
        &mut self,
        recipient: Key,
        after: u64,
        max: u16,
    ) -> Result<Vec<(u64, Vec<u8>)>, ClientError> {
        match self.call(&Request::FetchAfter {
            recipient,
            after,
            max,
        })? {
            Response::Items(items) => Ok(items),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub fn delete(&mut self, recipient: Key, seqs: Vec<u64>) -> Result<(), ClientError> {
        match self.call(&Request::Delete { recipient, seqs })? {
            Response::Ok => Ok(()),
            _ => Err(ClientError::Unexpected),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// A server that reads one request, then answers with `header` and one
    /// byte of body every `every`.
    fn trickling(every: Duration) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for mut s in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let _ = read_frame(&mut s);
                    let _ = s.write_all(&(MAX_FRAME as u32).to_be_bytes());
                    while s.write_all(&[0]).is_ok() {
                        std::thread::sleep(every);
                    }
                });
            }
        });
        addr
    }

    /// Every read succeeds well within the idle timeout, so only the request
    /// deadline ends the request.
    #[test]
    fn a_trickled_response_fails_at_the_request_deadline() {
        let addr = trickling(Duration::from_millis(20));
        let mut conn = Connection::connect(&addr, Duration::from_millis(500)).unwrap();
        conn.set_request_deadline(Duration::from_millis(400));
        let started = Instant::now();
        let err = conn.fetch_after([1; 32], 0, 1).unwrap_err();
        let took = started.elapsed();
        assert!(matches!(err, ClientError::Network(_)), "{err:?}");
        assert!(took >= Duration::from_millis(350) && took < Duration::from_secs(2), "took {took:?}");
    }

    /// The same under TLS: the relay answers with a whole TLS record, sent
    /// one byte every 20 ms. rustls reads until the record is complete, and
    /// every one of its socket reads is bounded by what is left of the
    /// deadline, so the request ends there, not after the ~20 s the record
    /// takes.
    #[test]
    fn a_trickled_tls_response_fails_at_the_request_deadline() {
        use crate::auth::RelayKeys;
        use rustls::ServerConnection;
        let keys = RelayKeys::generate().unwrap();
        let config =
            crate::tls::server_config(crate::tls::signing_key(keys.tls_seed()).unwrap()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            let mut tls = StreamOwned::new(ServerConnection::new(config).unwrap(), s);
            while tls.conn.is_handshaking() {
                tls.conn.complete_io(&mut tls.sock).unwrap();
            }
            write_frame(&mut tls, &encode_hello(&[0; 32])).unwrap();
            let _ = read_frame(&mut tls);
            // A 1000-byte bundle: status 0, then the bundle.
            let body = [vec![0u8], vec![7u8; 1000]].concat();
            let frame = [(body.len() as u32).to_be_bytes().to_vec(), body].concat();
            tls.conn.writer().write_all(&frame).unwrap();
            let mut wire = Vec::new();
            while tls.conn.wants_write() {
                tls.conn.write_tls(&mut wire).unwrap();
            }
            for b in wire {
                if tls.sock.write_all(&[b]).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let addr = keys.address("127.0.0.1", port).unwrap();
        let mut conn = Connection::connect_v2(&addr, Duration::from_millis(500)).unwrap();
        conn.set_request_deadline(Duration::from_millis(400));
        let started = Instant::now();
        let err = conn.get_bundle([1; 32]).unwrap_err();
        let took = started.elapsed();
        assert!(matches!(err, ClientError::Network(_)), "{err:?}");
        assert!(took >= Duration::from_millis(350) && took < Duration::from_secs(2), "took {took:?}");
    }

    /// A slow answer that completes within the deadline is read normally.
    #[test]
    fn a_slow_answer_within_the_deadline_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let _ = read_frame(&mut s);
            std::thread::sleep(Duration::from_millis(200));
            write_frame(&mut s, &[1]).unwrap(); // NOT_FOUND
        });
        let mut conn = Connection::connect(&addr, Duration::from_secs(1)).unwrap();
        conn.set_request_deadline(Duration::from_secs(2));
        assert_eq!(conn.get_bundle([1; 32]).unwrap(), None);
    }

    #[test]
    fn the_default_request_deadline_is_thirty_seconds() {
        assert_eq!(REQUEST_DEADLINE, Duration::from_secs(30));
    }

    /// AUTH needs a V2 connection; on V1 nothing is sent.
    #[test]
    fn a_v1_connection_cannot_authenticate() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let mut conn = Connection::connect(&addr, Duration::from_secs(1)).unwrap();
        let mut called = false;
        let err = conn
            .authenticate([1; 32], |_, out| {
                called = true;
                *out = [1; 32];
            })
            .unwrap_err();
        assert!(matches!(err, ClientError::Auth(_)), "{err:?}");
        assert!(!called, "the DH closure was not used");
    }

    // Connectors ——————————————————————————————————————————————————————————

    /// A connector that records each address and timeout it is given, then
    /// opens a plain TCP stream (`open`), counting the bytes read and
    /// written through it, or refuses.
    struct Recording {
        calls: std::sync::Mutex<Vec<(String, Duration)>>,
        open: bool,
        bytes: std::sync::Arc<[std::sync::atomic::AtomicUsize; 2]>,
    }

    impl Recording {
        fn new(open: bool) -> Self {
            Self {
                calls: Default::default(),
                open,
                bytes: Default::default(),
            }
        }

        fn calls(&self) -> Vec<(String, Duration)> {
            self.calls.lock().unwrap().clone()
        }

        /// Bytes read and written through the streams it opened.
        fn bytes(&self) -> (usize, usize) {
            use std::sync::atomic::Ordering::SeqCst;
            (self.bytes[0].load(SeqCst), self.bytes[1].load(SeqCst))
        }
    }

    impl Connector for Recording {
        fn connect(&self, addr: &str, timeout: Duration) -> io::Result<Box<dyn RelayStream>> {
            self.calls.lock().unwrap().push((addr.to_string(), timeout));
            if self.open {
                Ok(Box::new(Counting {
                    inner: TcpConnector.connect(addr, timeout)?,
                    bytes: std::sync::Arc::clone(&self.bytes),
                }))
            } else {
                Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused by the test connector"))
            }
        }
    }

    /// A stream that passes everything to `inner` and counts the bytes read
    /// (`bytes[0]`) and written (`bytes[1]`).
    struct Counting {
        inner: Box<dyn RelayStream>,
        bytes: std::sync::Arc<[std::sync::atomic::AtomicUsize; 2]>,
    }

    impl Read for Counting {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.bytes[0].fetch_add(n, std::sync::atomic::Ordering::SeqCst);
            Ok(n)
        }
    }

    impl Write for Counting {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let n = self.inner.write(buf)?;
            self.bytes[1].fetch_add(n, std::sync::atomic::Ordering::SeqCst);
            Ok(n)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }

    impl RelayStream for Counting {
        fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
            self.inner.set_read_timeout(timeout)
        }

        fn set_write_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
            self.inner.set_write_timeout(timeout)
        }
    }

    /// The connector is given exactly the address string the caller wrote,
    /// an onion name included, and the connection's timeout. A connector's
    /// error is a network error.
    #[test]
    fn a_connector_gets_the_address_as_given_and_its_error_is_a_network_error() {
        let timeout = Duration::from_millis(700);
        let refusing = Recording::new(false);
        let Err(err) = Connection::connect_with(&refusing, "relayexample.onion:443", timeout) else {
            panic!("the refusing connector gave a connection");
        };
        assert!(matches!(err, ClientError::Network(_)), "{err:?}");
        let keys = crate::auth::RelayKeys::generate().unwrap();
        let addr = keys.address("relayexample.onion", 8443).unwrap();
        let Err(err) = Connection::connect_v2_with(&refusing, &addr, timeout) else {
            panic!("the refusing connector gave a connection");
        };
        assert!(matches!(err, ClientError::Network(_)), "{err:?}");
        assert_eq!(
            refusing.calls(),
            [
                ("relayexample.onion:443".to_string(), timeout),
                ("relayexample.onion:8443".to_string(), timeout),
            ]
        );
    }

    /// A V2 connection makes its TLS handshake, reads HELLO and sends its
    /// requests over the stream its connector opened, and over no other.
    #[test]
    fn a_v2_connection_runs_over_the_stream_its_connector_opens() {
        use crate::server::{serve_v2, RelayConfig};
        let keys = crate::auth::RelayKeys::generate().unwrap();
        let relay =
            serve_v2(TcpListener::bind("127.0.0.1:0").unwrap(), RelayConfig::default(), &keys).unwrap();
        let addr = keys.address("127.0.0.1", relay.addr().port()).unwrap();
        let recording = Recording::new(true);
        let mut conn = Connection::connect_v2_with(&recording, &addr, Duration::from_secs(5)).unwrap();
        let before = recording.bytes();
        assert!(before.0 > 0 && before.1 > 0, "the handshake and HELLO went through it: {before:?}");
        assert_eq!(conn.get_bundle([1; 32]).unwrap(), None);
        let after = recording.bytes();
        assert!(after.0 > before.0 && after.1 > before.1, "the request went through it: {after:?}");
        assert_eq!(recording.calls(), [(addr.socket_addr(), Duration::from_secs(5))]);
    }

    type Events = std::sync::Arc<std::sync::Mutex<Vec<(&'static str, Option<Duration>)>>>;

    /// A stream that is not a socket: every write is taken whole, reads
    /// return `reply`, and every call is recorded in order.
    struct Scripted {
        reply: io::Cursor<Vec<u8>>,
        events: Events,
    }

    impl Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.events.lock().unwrap().push(("read", None));
            self.reply.read(buf)
        }
    }

    impl Write for Scripted {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.events.lock().unwrap().push(("write", None));
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.events.lock().unwrap().push(("flush", None));
            Ok(())
        }
    }

    impl RelayStream for Scripted {
        fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
            self.events.lock().unwrap().push(("set_read_timeout", timeout));
            Ok(())
        }

        fn set_write_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
            self.events.lock().unwrap().push(("set_write_timeout", timeout));
            Ok(())
        }
    }

    struct ScriptedConnector {
        reply: Vec<u8>,
        events: Events,
    }

    impl Connector for ScriptedConnector {
        fn connect(&self, _addr: &str, _timeout: Duration) -> io::Result<Box<dyn RelayStream>> {
            Ok(Box::new(Scripted {
                reply: io::Cursor::new(self.reply.clone()),
                events: std::sync::Arc::clone(&self.events),
            }))
        }
    }

    /// A connection runs over any stream its connector opens, not only a
    /// socket, and bounds every read, write and flush on it: each comes right
    /// after the matching timeout was set (the write timeout for a flush), to
    /// a time that is not zero and not longer than the connection's timeout.
    /// The request is flushed after its writes and before the answer is read.
    #[test]
    fn a_connection_bounds_each_read_and_write_on_a_connectors_stream() {
        let events = Events::default();
        // One frame: length 1, status 1 (NOT_FOUND).
        let connector = ScriptedConnector {
            reply: vec![0, 0, 0, 1, 1],
            events: std::sync::Arc::clone(&events),
        };
        let timeout = Duration::from_millis(800);
        let mut conn = Connection::connect_with(&connector, "scripted.invalid:1", timeout).unwrap();
        assert_eq!(conn.get_bundle([1; 32]).unwrap(), None);
        let events = events.lock().unwrap().clone();
        for (i, (call, _)) in events.iter().enumerate() {
            let setter = match *call {
                "read" => "set_read_timeout",
                "write" | "flush" => "set_write_timeout",
                _ => continue,
            };
            let (before, set) = events[..i].last().copied().expect("a timeout first");
            assert_eq!(before, setter, "{events:?}");
            let set = set.expect("a bound, not none");
            assert!(!set.is_zero() && set <= timeout, "{events:?}");
        }
        let first_read = events.iter().position(|(c, _)| *c == "read").expect("a read");
        let last_write = events[..first_read].iter().rposition(|(c, _)| *c == "write").expect("a write");
        assert!(
            events[last_write..first_read].iter().any(|(c, _)| *c == "flush"),
            "{events:?}"
        );
    }

    /// The write timeout set before a flush is what is left of the request
    /// deadline, not the connection's longer timeout: with a 5 s timeout and
    /// a 300 ms request deadline, no flush may wait longer than 300 ms.
    #[test]
    fn a_flush_waits_at_most_for_what_is_left_of_the_request_deadline() {
        let events = Events::default();
        let connector = ScriptedConnector {
            reply: vec![0, 0, 0, 1, 1],
            events: std::sync::Arc::clone(&events),
        };
        let deadline = Duration::from_millis(300);
        let mut conn = Connection::connect_with(&connector, "scripted.invalid:1", Duration::from_secs(5)).unwrap();
        conn.set_request_deadline(deadline);
        assert_eq!(conn.get_bundle([1; 32]).unwrap(), None);
        let events = events.lock().unwrap().clone();
        let mut flushes = 0;
        for (i, (call, _)) in events.iter().enumerate() {
            if *call != "flush" {
                continue;
            }
            flushes += 1;
            let (before, set) = events[..i].last().copied().expect("a timeout first");
            assert_eq!(before, "set_write_timeout", "{events:?}");
            let set = set.expect("a bound, not none");
            assert!(!set.is_zero() && set <= deadline, "{events:?}");
        }
        assert!(flushes > 0, "{events:?}");
    }
}
