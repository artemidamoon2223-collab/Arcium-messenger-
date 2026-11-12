//! A blocking client for one relay connection.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

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
    stream: TcpStream,
    /// Bound of every single read and write.
    idle: Duration,
    /// Bound of every request as a whole ([`REQUEST_DEADLINE`] by default).
    request_deadline: Duration,
}

/// The stream as seen by one request: every read and write waits at most
/// for what is left of the request's deadline (and at most `idle`), and
/// fails with `TimedOut` once nothing is left.
struct Bounded<'a> {
    stream: &'a mut TcpStream,
    idle: Duration,
    deadline: Instant,
}

impl Bounded<'_> {
    fn remaining(&self) -> io::Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "relay request deadline passed"));
        }
        Ok(left.min(self.idle))
    }
}

impl Read for Bounded<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let wait = self.remaining()?;
        self.stream.set_read_timeout(Some(wait))?;
        self.stream.read(buf)
    }
}

impl Write for Bounded<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let wait = self.remaining()?;
        self.stream.set_write_timeout(Some(wait))?;
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl Connection {
    /// Connects to `addr` (`host:port`). Every read and write times out after
    /// `timeout`, and every request as a whole after [`REQUEST_DEADLINE`].
    pub fn connect(addr: &str, timeout: Duration) -> Result<Self, ClientError> {
        let target = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address"))?;
        let stream = TcpStream::connect_timeout(&target, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.set_nodelay(true)?;
        Ok(Self {
            stream,
            idle: timeout,
            request_deadline: REQUEST_DEADLINE,
        })
    }

    /// Bounds every later request as a whole by `deadline` instead of
    /// [`REQUEST_DEADLINE`].
    pub fn set_request_deadline(&mut self, deadline: Duration) {
        self.request_deadline = deadline;
    }

    fn call(&mut self, req: &Request) -> Result<Response, ClientError> {
        let mut io = Bounded {
            stream: &mut self.stream,
            idle: self.idle,
            deadline: Instant::now() + self.request_deadline,
        };
        write_frame(&mut io, &req.encode())?;
        let body = read_frame(&mut io)?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "relay closed the connection")
        })?;
        match Response::decode(req, &body)? {
            Response::Error(code) => Err(ClientError::Refused(code)),
            r => Ok(r),
        }
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
}
