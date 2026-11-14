//! `RELAY_PROTOCOL_V1` and `RELAY_PROTOCOL_V2`: length-prefixed binary frames
//! over TCP (V1) or inside TLS 1.3 (V2).
//!
//! Every frame is `len(u32 BE) || body`, with `len <= MAX_FRAME`. A request
//! body starts with an operation byte, a response body with a status byte.
//! Integers are big-endian. Decoding is exact: trailing or missing bytes are an
//! error, never ignored.
//!
//! ```text
//! request                                   response
//! 1 PUT_BUNDLE owner(32) bundle             0 OK
//! 2 GET_BUNDLE owner(32)                    0 OK bundle | 1 NOT_FOUND
//! 3 SEND recipient(32) envelope             0 OK seq(8)
//! 4 FETCH recipient(32) max(2)              0 OK count(2) {seq(8) len(4) envelope}*
//! 5 DELETE recipient(32) count(2) seq(8)*   0 OK
//! 6 FETCH_AFTER recipient(32) after(8) max(2)
//!                                           0 OK count(2) {seq(8) len(4) envelope}*
//! 7 AUTH owner(32) tag(32)        (V2 only) 0 OK
//!                                           2 BAD_REQUEST | 3 TOO_LARGE | 4 FULL
//!                                           5 UNAUTHORIZED (V2 only)
//! ```
//!
//! FETCH returns the first `max` (at most [`MAX_FETCH`]) envelopes of the
//! mailbox in ascending sequence order, fewer if they would not fit in one
//! frame (never fewer than [`MIN_PAGE`] while more follow). FETCH_AFTER
//! returns, in the same order and under the same limits, only envelopes whose
//! sequence number is greater than `after`: a reader pages forward through a
//! mailbox whose first entries it leaves in place by passing the last sequence
//! number it received.
//! Entries deleted or expired between requests are simply absent, and entries
//! appended meanwhile have larger numbers. FETCH is FETCH_AFTER with
//! `after = 0`.
//!
//! Sequence numbers are assigned by one relay, start at 1 and only grow; a
//! relay that has used `u64::MAX` refuses further SENDs with FULL rather than
//! wrap. They are transport positions only: they say nothing about who sent
//! an envelope, whether it is authentic, or whether it was delivered.
//!
//! FETCH_AFTER was added after FETCH. A relay that predates it answers it
//! with BAD_REQUEST, as it answers every operation byte it does not know;
//! there is no fallback in the client.
//!
//! # V1
//!
//! Plain TCP, nothing authenticated: anyone who reaches the relay can read or
//! delete any mailbox and replace any bundle, and a network observer sees
//! every key and envelope. A V1 relay answers AUTH with BAD_REQUEST, as an
//! operation it does not know. V1 is for development builds and tests only
//! (the failure-injection tests inspect plaintext frames); release builds of
//! the app accept only V2.
//!
//! # V2
//!
//! The same frames inside a TLS 1.3 connection (`crate::tls`): the client
//! pins the relay's TLS key by the SHA-256 of its `SubjectPublicKeyInfo`,
//! which the relay presents as an RFC 7250 raw public key. Right after the
//! handshake, before any request, the relay sends one frame:
//!
//! ```text
//! HELLO = 0x02 (version) || challenge(32)
//! ```
//!
//! `challenge` is fresh from the relay's operating-system random number
//! generator for every connection. Requests and responses then follow as in
//! V1, with these rules:
//!
//! - AUTH proves that the connection acts for `owner`: `tag` is
//!   `HMAC-SHA256(k, challenge || exporter || owner)`, with `k` derived from
//!   the X25519 DH of the owner's identity key and the relay's auth key, and
//!   `exporter` 32 bytes of this TLS connection's exported keying material
//!   (`crate::auth`). A tag is therefore valid on one connection only.
//! - AUTH is checked at most once per connection. A valid tag is answered OK,
//!   and the connection acts for `owner` until it closes. A wrong tag is
//!   answered UNAUTHORIZED. Either way, every later AUTH on that connection is
//!   answered UNAUTHORIZED and changes nothing.
//! - FETCH, FETCH_AFTER and DELETE are answered only for `recipient` equal to
//!   the authenticated owner, PUT_BUNDLE only for `owner` equal to it.
//!   Otherwise, and on a connection without a valid AUTH, they are answered
//!   UNAUTHORIZED, and nothing is read or changed.
//! - SEND and GET_BUNDLE need no AUTH: first contact needs both, and an
//!   envelope names its sender anyway.
//!
//! What V2 does not hide: the relay operator still sees every key, envelope,
//! size and time, and can read or delete any mailbox. A network observer
//! sees that a connection exists, its sizes and its timing.
//!
//! In both versions the relay is untrusted, and every envelope it carries is
//! end-to-end encrypted by the endpoints.

use std::io::{self, Read, Write};

/// Largest frame accepted in either direction.
pub const MAX_FRAME: usize = 1 << 20;
/// Largest envelope a relay stores.
pub const MAX_ENVELOPE: usize = 64 * 1024;
/// Fewest envelopes a FETCH or FETCH_AFTER page holds when more follow: a page
/// stops before the envelope that would not fit in one frame, and that many of
/// the largest envelopes always fit.
pub const MIN_PAGE: usize = (MAX_FRAME - 3) / (12 + MAX_ENVELOPE);
const _: () = assert!(MIN_PAGE >= 1);
/// Largest prekey bundle a relay stores.
pub const MAX_BUNDLE: usize = 1024;
/// Most envelopes one FETCH or FETCH_AFTER returns.
pub const MAX_FETCH: u16 = 256;
/// Most envelopes a mailbox of this repository's relay holds: the default and
/// the largest supported `RelayConfig::max_mailbox`. Readers size their paging
/// budget from it.
pub const DEFAULT_MAX_MAILBOX: usize = 4096;

/// A mailbox or bundle owner: an X25519 identity public key.
pub type Key = [u8; 32];

/// The version byte of the V2 HELLO frame.
pub const PROTOCOL_V2: u8 = 2;
/// Length of the V2 HELLO challenge and of an AUTH tag.
pub const CHALLENGE_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    PutBundle {
        owner: Key,
        bundle: Vec<u8>,
    },
    GetBundle {
        owner: Key,
    },
    Send {
        recipient: Key,
        envelope: Vec<u8>,
    },
    Fetch {
        recipient: Key,
        max: u16,
    },
    Delete {
        recipient: Key,
        seqs: Vec<u64>,
    },
    FetchAfter {
        recipient: Key,
        after: u64,
        max: u16,
    },
    /// V2 only.
    Auth {
        owner: Key,
        tag: [u8; CHALLENGE_LEN],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    BadRequest,
    TooLarge,
    Full,
    /// V2 only: the connection has not proved that it acts for that key.
    Unauthorized,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Ok,
    Bundle(Vec<u8>),
    NotFound,
    Accepted { seq: u64 },
    Items(Vec<(u64, Vec<u8>)>),
    Error(ErrorCode),
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("malformed frame")]
    Malformed,
    #[error("frame of {0} bytes exceeds the limit")]
    TooLarge(usize),
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

pub fn write_frame(w: &mut impl Write, body: &[u8]) -> Result<(), ProtocolError> {
    if body.len() > MAX_FRAME {
        return Err(ProtocolError::TooLarge(body.len()));
    }
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(body)?;
    w.flush()?;
    Ok(())
}

/// Reads one frame. `Ok(None)` if the peer closed the connection cleanly
/// before a new frame began.
pub fn read_frame(r: &mut impl Read) -> Result<Option<Vec<u8>>, ProtocolError> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(ProtocolError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

/// A cursor that fails on any read past the end.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtocolError> {
        if self.0.len() < n {
            return Err(ProtocolError::Malformed);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ProtocolError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }
    fn u32(&mut self) -> Result<u32, ProtocolError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }
    fn u64(&mut self) -> Result<u64, ProtocolError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }
    fn key(&mut self) -> Result<Key, ProtocolError> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }
    fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.0)
    }
    fn end(&self) -> Result<(), ProtocolError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(ProtocolError::Malformed)
        }
    }
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Request::PutBundle { owner, bundle } => {
                out.push(1);
                out.extend_from_slice(owner);
                out.extend_from_slice(bundle);
            }
            Request::GetBundle { owner } => {
                out.push(2);
                out.extend_from_slice(owner);
            }
            Request::Send {
                recipient,
                envelope,
            } => {
                out.push(3);
                out.extend_from_slice(recipient);
                out.extend_from_slice(envelope);
            }
            Request::Fetch { recipient, max } => {
                out.push(4);
                out.extend_from_slice(recipient);
                out.extend_from_slice(&max.to_be_bytes());
            }
            Request::Delete { recipient, seqs } => {
                out.push(5);
                out.extend_from_slice(recipient);
                out.extend_from_slice(&(seqs.len() as u16).to_be_bytes());
                for s in seqs {
                    out.extend_from_slice(&s.to_be_bytes());
                }
            }
            Request::FetchAfter {
                recipient,
                after,
                max,
            } => {
                out.push(6);
                out.extend_from_slice(recipient);
                out.extend_from_slice(&after.to_be_bytes());
                out.extend_from_slice(&max.to_be_bytes());
            }
            Request::Auth { owner, tag } => {
                out.push(7);
                out.extend_from_slice(owner);
                out.extend_from_slice(tag);
            }
        }
        out
    }

    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut c = Cursor(body);
        let req = match c.u8()? {
            1 => Request::PutBundle {
                owner: c.key()?,
                bundle: c.rest().to_vec(),
            },
            2 => Request::GetBundle { owner: c.key()? },
            3 => Request::Send {
                recipient: c.key()?,
                envelope: c.rest().to_vec(),
            },
            4 => Request::Fetch {
                recipient: c.key()?,
                max: c.u16()?,
            },
            5 => {
                let recipient = c.key()?;
                let n = c.u16()?;
                let seqs = (0..n).map(|_| c.u64()).collect::<Result<_, _>>()?;
                Request::Delete { recipient, seqs }
            }
            6 => Request::FetchAfter {
                recipient: c.key()?,
                after: c.u64()?,
                max: c.u16()?,
            },
            7 => Request::Auth {
                owner: c.key()?,
                tag: c.key()?,
            },
            _ => return Err(ProtocolError::Malformed),
        };
        c.end()?;
        Ok(req)
    }
}

impl Response {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Response::Ok => out.push(0),
            Response::Bundle(b) => {
                out.push(0);
                out.extend_from_slice(b);
            }
            Response::NotFound => out.push(1),
            Response::Accepted { seq } => {
                out.push(0);
                out.extend_from_slice(&seq.to_be_bytes());
            }
            Response::Items(items) => {
                out.push(0);
                out.extend_from_slice(&(items.len() as u16).to_be_bytes());
                for (seq, env) in items {
                    out.extend_from_slice(&seq.to_be_bytes());
                    out.extend_from_slice(&(env.len() as u32).to_be_bytes());
                    out.extend_from_slice(env);
                }
            }
            Response::Error(code) => out.push(match code {
                ErrorCode::BadRequest => 2,
                ErrorCode::TooLarge => 3,
                ErrorCode::Full => 4,
                ErrorCode::Unauthorized => 5,
            }),
        }
        out
    }

    /// Decodes the response to `req`; the operation decides the layout.
    pub fn decode(req: &Request, body: &[u8]) -> Result<Self, ProtocolError> {
        let mut c = Cursor(body);
        let resp = match c.u8()? {
            0 => match req {
                Request::PutBundle { .. } | Request::Delete { .. } | Request::Auth { .. } => {
                    Response::Ok
                }
                Request::GetBundle { .. } => Response::Bundle(c.rest().to_vec()),
                Request::Send { .. } => Response::Accepted { seq: c.u64()? },
                Request::Fetch { .. } | Request::FetchAfter { .. } => {
                    let n = c.u16()?;
                    let mut items = Vec::with_capacity(n as usize);
                    for _ in 0..n {
                        let seq = c.u64()?;
                        let len = c.u32()? as usize;
                        items.push((seq, c.take(len)?.to_vec()));
                    }
                    Response::Items(items)
                }
            },
            1 if matches!(req, Request::GetBundle { .. }) => Response::NotFound,
            2 => Response::Error(ErrorCode::BadRequest),
            3 => Response::Error(ErrorCode::TooLarge),
            4 => Response::Error(ErrorCode::Full),
            5 => Response::Error(ErrorCode::Unauthorized),
            _ => return Err(ProtocolError::Malformed),
        };
        c.end()?;
        Ok(resp)
    }
}

/// The body of the V2 HELLO frame.
pub fn encode_hello(challenge: &[u8; CHALLENGE_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + CHALLENGE_LEN);
    out.push(PROTOCOL_V2);
    out.extend_from_slice(challenge);
    out
}

/// The challenge of a V2 HELLO frame body. Any other version or length is
/// malformed.
pub fn decode_hello(body: &[u8]) -> Result<[u8; CHALLENGE_LEN], ProtocolError> {
    let mut c = Cursor(body);
    if c.u8()? != PROTOCOL_V2 {
        return Err(ProtocolError::Malformed);
    }
    let challenge = c.key()?;
    c.end()?;
    Ok(challenge)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_and_responses_round_trip() {
        let reqs = [
            Request::PutBundle {
                owner: [1; 32],
                bundle: vec![9; 204],
            },
            Request::GetBundle { owner: [2; 32] },
            Request::Send {
                recipient: [3; 32],
                envelope: vec![7; 100],
            },
            Request::Fetch {
                recipient: [4; 32],
                max: 10,
            },
            Request::Delete {
                recipient: [5; 32],
                seqs: vec![1, 2, u64::MAX],
            },
            Request::FetchAfter {
                recipient: [6; 32],
                after: u64::MAX - 1,
                max: 3,
            },
            Request::Auth {
                owner: [7; 32],
                tag: [8; 32],
            },
        ];
        for r in &reqs {
            assert_eq!(&Request::decode(&r.encode()).unwrap(), r);
        }
        assert_eq!(reqs[6].encode(), [vec![7], vec![7; 32], vec![8; 32]].concat());
        assert_eq!(Response::decode(&reqs[6], &[0]).unwrap(), Response::Ok);
        let unauthorized = Response::Error(ErrorCode::Unauthorized);
        assert_eq!(unauthorized.encode(), vec![5]);
        for r in &reqs {
            assert_eq!(Response::decode(r, &[5]).unwrap(), unauthorized);
        }
        let hello = encode_hello(&[9; 32]);
        assert_eq!(hello, [vec![2], vec![9; 32]].concat());
        assert_eq!(decode_hello(&hello).unwrap(), [9; 32]);
        let fetch = &reqs[3];
        let items = Response::Items(vec![(1, vec![1, 2]), (9, vec![])]);
        assert_eq!(Response::decode(fetch, &items.encode()).unwrap(), items);
        assert_eq!(Response::decode(&reqs[5], &items.encode()).unwrap(), items);
        let acc = Response::Accepted { seq: 42 };
        assert_eq!(Response::decode(&reqs[2], &acc.encode()).unwrap(), acc);
        assert_eq!(
            Response::decode(&reqs[1], &Response::NotFound.encode()).unwrap(),
            Response::NotFound
        );
    }

    #[test]
    fn malformed_bodies_are_refused() {
        for body in [
            vec![],
            vec![9],
            vec![2; 10],                                                // short key
            [vec![2], vec![0; 33]].concat(),                            // trailing byte
            [vec![5], vec![0; 32], vec![0, 2], vec![0; 8]].concat(),    // missing seq
            [vec![6], vec![0; 32], vec![0; 8], vec![0]].concat(),       // short max
            [vec![6], vec![0; 32], vec![0; 8], vec![0, 1, 0]].concat(), // trailing byte
            [vec![6], vec![0; 32], vec![0; 7]].concat(),                // short cursor
            [vec![7], vec![0; 63]].concat(),                            // short tag
            [vec![7], vec![0; 65]].concat(),                            // trailing byte
            vec![8],                                                    // unknown op
        ] {
            assert!(Request::decode(&body).is_err(), "{body:?}");
        }
        let fetch = Request::Fetch {
            recipient: [0; 32],
            max: 1,
        };
        // An item longer than the frame.
        let bad = [vec![0, 0, 1], vec![0; 8], vec![0, 0, 0, 9], vec![1]].concat();
        assert!(Response::decode(&fetch, &bad).is_err());
        // An AUTH answer carries nothing after OK.
        let auth = Request::Auth {
            owner: [0; 32],
            tag: [0; 32],
        };
        assert!(Response::decode(&auth, &[0, 0]).is_err());
        for hello in [
            vec![],
            vec![2],
            [vec![1], vec![0; 32]].concat(),
            [vec![3], vec![0; 32]].concat(),
            [vec![2], vec![0; 31]].concat(),
            [vec![2], vec![0; 33]].concat(),
        ] {
            assert!(decode_hello(&hello).is_err(), "{hello:?}");
        }
    }

    #[test]
    fn oversized_frames_are_refused_both_ways() {
        let big = vec![0u8; MAX_FRAME + 1];
        assert!(matches!(
            write_frame(&mut Vec::new(), &big),
            Err(ProtocolError::TooLarge(_))
        ));
        let mut wire = ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec();
        wire.extend_from_slice(&[0; 8]);
        assert!(matches!(
            read_frame(&mut wire.as_slice()),
            Err(ProtocolError::TooLarge(_))
        ));
        assert!(read_frame(&mut [].as_slice()).unwrap().is_none());
    }
}
