//! A blocking client for one relay connection.

use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

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

pub struct Connection {
    stream: TcpStream,
}

impl Connection {
    /// Connects to `addr` (`host:port`). Every read and write times out after
    /// `timeout`.
    pub fn connect(addr: &str, timeout: Duration) -> Result<Self, ClientError> {
        let target = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address"))?;
        let stream = TcpStream::connect_timeout(&target, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.set_nodelay(true)?;
        Ok(Self { stream })
    }

    fn call(&mut self, req: &Request) -> Result<Response, ClientError> {
        write_frame(&mut self.stream, &req.encode())?;
        let body = read_frame(&mut self.stream)?.ok_or_else(|| {
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

    pub fn delete(&mut self, recipient: Key, seqs: Vec<u64>) -> Result<(), ClientError> {
        match self.call(&Request::Delete { recipient, seqs })? {
            Response::Ok => Ok(()),
            _ => Err(ClientError::Unexpected),
        }
    }
}
