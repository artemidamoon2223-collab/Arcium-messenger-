//! `RELAY_PROTOCOL_V1`: length-prefixed binary frames over TCP.
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
//!                                           2 BAD_REQUEST | 3 TOO_LARGE | 4 FULL
//! ```
//!
//! Nothing here is secret or authenticated: the relay is untrusted, and every
//! envelope it carries is end-to-end encrypted by the endpoints.

use std::io::{self, Read, Write};

/// Largest frame accepted in either direction.
pub const MAX_FRAME: usize = 1 << 20;
/// Largest envelope a relay stores.
pub const MAX_ENVELOPE: usize = 64 * 1024;
/// Largest prekey bundle a relay stores.
pub const MAX_BUNDLE: usize = 1024;
/// Most envelopes one FETCH returns.
pub const MAX_FETCH: u16 = 256;

/// A mailbox or bundle owner: an X25519 identity public key.
pub type Key = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    PutBundle { owner: Key, bundle: Vec<u8> },
    GetBundle { owner: Key },
    Send { recipient: Key, envelope: Vec<u8> },
    Fetch { recipient: Key, max: u16 },
    Delete { recipient: Key, seqs: Vec<u64> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    BadRequest,
    TooLarge,
    Full,
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
            }),
        }
        out
    }

    /// Decodes the response to `req`; the operation decides the layout.
    pub fn decode(req: &Request, body: &[u8]) -> Result<Self, ProtocolError> {
        let mut c = Cursor(body);
        let resp = match c.u8()? {
            0 => match req {
                Request::PutBundle { .. } | Request::Delete { .. } => Response::Ok,
                Request::GetBundle { .. } => Response::Bundle(c.rest().to_vec()),
                Request::Send { .. } => Response::Accepted { seq: c.u64()? },
                Request::Fetch { .. } => {
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
            _ => return Err(ProtocolError::Malformed),
        };
        c.end()?;
        Ok(resp)
    }
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
        ];
        for r in &reqs {
            assert_eq!(&Request::decode(&r.encode()).unwrap(), r);
        }
        let fetch = &reqs[3];
        let items = Response::Items(vec![(1, vec![1, 2]), (9, vec![])]);
        assert_eq!(Response::decode(fetch, &items.encode()).unwrap(), items);
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
            vec![2; 10],                                             // short key
            [vec![2], vec![0; 33]].concat(),                         // trailing byte
            [vec![5], vec![0; 32], vec![0, 2], vec![0; 8]].concat(), // missing seq
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
