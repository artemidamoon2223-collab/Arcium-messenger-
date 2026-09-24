//! The two layouts the network layer adds. Neither changes the X3DH
//! handshake or the Double Ratchet message format; both wrap them.
//!
//! `ENVELOPE_V1` is what the relay stores, and is visible to it:
//!
//! ```text
//! "ARN1"(4) kind(1) sender_identity_dh_pk(32) body
//!   kind 1: body = INITIATOR_HANDSHAKE_V1 (84 bytes)
//!   kind 2: body = header(40) || ciphertext   (the unchanged message format)
//! ```
//!
//! `PAYLOAD_V1` is the plaintext inside a ratchet message, so the relay never
//! sees it:
//!
//! ```text
//! type(1) = 1 TEXT     rest = application bytes
//! type(1) = 2 RECEIPT  count(2) {message_id(32)}*   (count >= 1)
//! type(1) = 3 OPEN     nothing else
//! ```
//!
//! The sender field is not authenticated by the envelope. It only selects the
//! session; a message decrypts only under the session whose keys (and AD,
//! which binds both identity keys) produced it.

use zeroize::Zeroizing;

pub const MAGIC: &[u8; 4] = b"ARN1";
const KIND_HANDSHAKE: u8 = 1;
const KIND_MESSAGE: u8 = 2;

const TYPE_TEXT: u8 = 1;
const TYPE_RECEIPT: u8 = 2;
const TYPE_OPEN: u8 = 3;

/// Receipts listed in one receipt message at most.
pub const MAX_RECEIPT_IDS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Envelope {
    Handshake {
        sender: [u8; 32],
        handshake: Vec<u8>,
    },
    Message {
        sender: [u8; 32],
        wire: Vec<u8>,
    },
}

impl Envelope {
    pub fn sender(&self) -> [u8; 32] {
        match self {
            Envelope::Handshake { sender, .. } | Envelope::Message { sender, .. } => *sender,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let (kind, sender, body) = match self {
            Envelope::Handshake { sender, handshake } => (KIND_HANDSHAKE, sender, handshake),
            Envelope::Message { sender, wire } => (KIND_MESSAGE, sender, wire),
        };
        let mut out = Vec::with_capacity(37 + body.len());
        out.extend_from_slice(MAGIC);
        out.push(kind);
        out.extend_from_slice(sender);
        out.extend_from_slice(body);
        out
    }

    /// `None` for anything that is not a well-formed `ENVELOPE_V1`.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 37 || &bytes[..4] != MAGIC {
            return None;
        }
        let sender: [u8; 32] = bytes[5..37].try_into().expect("32 bytes");
        let body = bytes[37..].to_vec();
        match bytes[4] {
            KIND_HANDSHAKE => Some(Envelope::Handshake {
                sender,
                handshake: body,
            }),
            KIND_MESSAGE => Some(Envelope::Message { sender, wire: body }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    Text(Zeroizing<Vec<u8>>),
    Receipt(Vec<[u8; 32]>),
    Open,
}

impl Payload {
    /// Zeroized on drop: for a text this is the application's plaintext.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(match self {
            Payload::Text(t) => [&[TYPE_TEXT][..], t].concat(),
            Payload::Receipt(ids) => {
                let mut out = vec![TYPE_RECEIPT];
                out.extend_from_slice(&(ids.len() as u16).to_be_bytes());
                for id in ids {
                    out.extend_from_slice(id);
                }
                out
            }
            Payload::Open => vec![TYPE_OPEN],
        })
    }

    /// `None` for an unknown type or a malformed receipt.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        match *bytes.first()? {
            TYPE_TEXT => Some(Payload::Text(Zeroizing::new(bytes[1..].to_vec()))),
            TYPE_RECEIPT => {
                let count = u16::from_be_bytes(bytes.get(1..3)?.try_into().ok()?) as usize;
                let ids = bytes.get(3..)?;
                if count == 0 || count > MAX_RECEIPT_IDS || ids.len() != count * 32 {
                    return None;
                }
                Some(Payload::Receipt(
                    ids.chunks(32)
                        .map(|c| c.try_into().expect("32 bytes"))
                        .collect(),
                ))
            }
            TYPE_OPEN if bytes.len() == 1 => Some(Payload::Open),
            _ => None,
        }
    }
}

/// Client message ids of what the network layer sends through the durable
/// outbox. The first byte keeps the three kinds apart; the application's own
/// id follows `b't'`.
pub mod client_id {
    pub const TEXT: u8 = b't';
    pub const RECEIPT: u8 = b'r';
    pub const OPEN: &[u8] = b"o";

    pub fn text(app_id: &[u8]) -> Vec<u8> {
        [&[TEXT][..], app_id].concat()
    }

    /// The receipt for `id`. `round` > 0 names a later receipt for the same
    /// message, sent because the peer sent the message again.
    pub fn receipt(id: &[u8; 32], round: u64) -> Vec<u8> {
        let mut out = vec![RECEIPT];
        out.extend_from_slice(id);
        if round > 0 {
            out.extend_from_slice(&round.to_be_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelopes_and_payloads_round_trip_and_reject_malformed_bytes() {
        for e in [
            Envelope::Handshake {
                sender: [1; 32],
                handshake: vec![2; 84],
            },
            Envelope::Message {
                sender: [3; 32],
                wire: vec![4; 60],
            },
        ] {
            assert_eq!(Envelope::decode(&e.encode()), Some(e));
        }
        assert_eq!(Envelope::decode(b"ARN1"), None);
        assert_eq!(
            Envelope::decode(&[b"XXXX".as_slice(), &[1; 40]].concat()),
            None
        );
        assert_eq!(
            Envelope::decode(&[b"ARN1".as_slice(), &[9; 40]].concat()),
            None
        );

        for p in [
            Payload::Text(Zeroizing::new(b"hi".to_vec())),
            Payload::Text(Zeroizing::new(vec![])),
            Payload::Receipt(vec![[7; 32], [8; 32]]),
            Payload::Open,
        ] {
            assert_eq!(Payload::decode(&p.encode()), Some(p));
        }
        for bad in [
            &[][..],
            &[9],
            &[2, 0, 0],       // zero receipts
            &[2, 0, 1, 1, 2], // truncated id
            &[3, 0],          // OPEN with a body
        ] {
            assert_eq!(Payload::decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn client_ids_fit_the_durable_outbox_limit() {
        assert!(client_id::receipt(&[0; 32], 7).len() <= 64);
        assert_eq!(client_id::receipt(&[0; 32], 0).len(), 33);
        assert_eq!(client_id::text(b"x"), b"tx");
    }
}
