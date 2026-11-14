//! A blocking client for one relay connection: `RELAY_PROTOCOL_V1` over plain
//! TCP ([`Connection::connect`], for development and tests only), or
//! `RELAY_PROTOCOL_V2` over TLS 1.3 with the relay's pinned key
//! ([`Connection::connect_v2`]) and mailbox authentication
//! ([`Connection::authenticate`]). The operations are the same on both.

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
/// response. The connection's timeout bounds each read and write; this bounds
/// their sum, so a relay that trickles bytes cannot hold a request open.
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

/// The TCP stream: every read and write waits at most for what is left of
/// `deadline` (and at most `idle`), and fails with `TimedOut` once nothing is
/// left. Under TLS this bounds every socket read and write rustls makes, so a
/// relay that trickles TLS records cannot hold a request open either.
struct Socket {
    tcp: TcpStream,
    /// Bound of every single read and write.
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
        self.tcp.set_read_timeout(Some(wait))?;
        self.tcp.read(buf)
    }
}

impl Write for Socket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let wait = self.remaining()?;
        self.tcp.set_write_timeout(Some(wait))?;
        self.tcp.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
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

/// A TCP connection to `addr` with every read and write bounded by
/// `timeout`, and a first deadline [`REQUEST_DEADLINE`] from now.
fn tcp(addr: &str, timeout: Duration) -> Result<Socket, ClientError> {
    let target = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address"))?;
    let tcp = TcpStream::connect_timeout(&target, timeout)?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;
    tcp.set_nodelay(true)?;
    Ok(Socket {
        tcp,
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
        Ok(Self {
            transport: Transport::Plain(tcp(addr, timeout)?),
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
        let socket = tcp(&addr.socket_addr(), timeout)?;
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
    /// `owner` only. The relay checks one AUTH per connection: a wrong tag,
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
}
