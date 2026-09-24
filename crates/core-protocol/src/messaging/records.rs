//! Store keys and the fixed-layout records of [`super`]: handle, outbox,
//! inbox, send-id and seen entries.
//!
//! Only the `outbox:` and `inbox:` namespaces are ever listed, and they hold
//! only pending entries; everything kept after an acknowledgement lives in
//! `seen:` and `sendid:`, which are read by exact key only. So the cost of
//! listing pending messages does not grow with acknowledged history.

use zeroize::Zeroizing;

use super::{message_id, IncomingMessage, MessageId, MessagingError, OutgoingMessage};

// ── Store keys ────────────────────────────────────────────────────────────────

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(super) fn handle_key(handle: u64) -> String {
    format!("handle:v1/{handle:016x}")
}

pub(super) fn handshake_key(peer: &[u8; 32]) -> String {
    format!("hsout:v1/{}", hex(peer))
}

pub(super) const OUTBOX_NAMESPACE: &str = "outbox:";
pub(super) const INBOX_NAMESPACE: &str = "inbox:";

pub(super) fn outbox_prefix(peer: &[u8; 32]) -> String {
    format!("{OUTBOX_NAMESPACE}v1/{}/", hex(peer))
}

pub(super) fn inbox_prefix(peer: &[u8; 32]) -> String {
    format!("{INBOX_NAMESPACE}v1/{}/", hex(peer))
}

pub(super) fn outbox_key(peer: &[u8; 32], id: &MessageId) -> String {
    format!("{}{}", outbox_prefix(peer), hex(id))
}

pub(super) fn inbox_key(peer: &[u8; 32], id: &MessageId) -> String {
    format!("{}{}", inbox_prefix(peer), hex(id))
}

/// The tombstone of an incoming message that was acknowledged.
pub(super) fn seen_key(peer: &[u8; 32], id: &MessageId) -> String {
    format!("seen:v1/{}/{}", hex(peer), hex(id))
}

/// Maps a caller's logical message id to the message it produced.
pub(super) fn sendid_key(peer: &[u8; 32], client_id: &[u8]) -> String {
    format!("sendid:v1/{}/{}", hex(peer), hex(client_id))
}

// ── Records ───────────────────────────────────────────────────────────────────
//
// Fixed layouts, integers big-endian. Never transmitted; confidentiality and
// integrity come from the encrypted store.

pub(super) const HANDLE_MAGIC: &[u8; 7] = b"ARCHNDL";
pub(super) const OUTBOX_MAGIC: &[u8; 7] = b"ARCOUTB";
pub(super) const INBOX_MAGIC: &[u8; 7] = b"ARCINBX";
pub(super) const SEEN_MAGIC: &[u8; 7] = b"ARCSEEN";
pub(super) const SENDID_MAGIC: &[u8; 7] = b"ARCSNDI";
/// A send-id record whose message the caller abandoned.
pub(super) const ABANDONED_MAGIC: &[u8; 7] = b"ARCSNDX";

/// Longest caller-supplied logical message id, in bytes.
pub const MAX_CLIENT_MESSAGE_ID_LEN: usize = 64;
pub(super) const RECORD_VERSION: u8 = 1;

/// `HANDLE_RECORD_V1`: magic(7) version(1) peer_identity_pk(32).
pub(super) fn encode_handle(peer: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(40));
    out.extend_from_slice(HANDLE_MAGIC);
    out.push(RECORD_VERSION);
    out.extend_from_slice(peer);
    out
}

pub(super) fn decode_handle(bytes: &[u8]) -> Result<[u8; 32], MessagingError> {
    if bytes.len() != 40 || &bytes[..7] != HANDLE_MAGIC || bytes[7] != RECORD_VERSION {
        return Err(MessagingError::InvalidRecord("handle"));
    }
    Ok(bytes[8..40].try_into().expect("32 bytes"))
}

/// `OUTBOX_RECORD_V1`: magic(7) version(1) generation(8) id(32)
/// client_id_len(1) client_id wire_len(4) wire.
pub(super) fn encode_outbox(
    generation: u64,
    id: &MessageId,
    client_id: &[u8],
    wire: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(53 + client_id.len() + wire.len()));
    out.extend_from_slice(OUTBOX_MAGIC);
    out.push(RECORD_VERSION);
    out.extend_from_slice(&generation.to_be_bytes());
    out.extend_from_slice(id);
    // Bounded by MAX_CLIENT_MESSAGE_ID_LEN, checked by the caller.
    out.push(client_id.len() as u8);
    out.extend_from_slice(client_id);
    out.extend_from_slice(&(wire.len() as u32).to_be_bytes());
    out.extend_from_slice(wire);
    out
}

pub(super) fn decode_outbox(bytes: &[u8]) -> Result<OutgoingMessage, MessagingError> {
    let bad = || MessagingError::InvalidRecord("outbox");
    if bytes.len() < 53 || &bytes[..7] != OUTBOX_MAGIC || bytes[7] != RECORD_VERSION {
        return Err(bad());
    }
    let generation = u64::from_be_bytes(bytes[8..16].try_into().expect("8 bytes"));
    let id: MessageId = bytes[16..48].try_into().expect("32 bytes");
    let client_len = bytes[48] as usize;
    let rest = &bytes[49..];
    if client_len == 0 || client_len > MAX_CLIENT_MESSAGE_ID_LEN || rest.len() < client_len + 4 {
        return Err(bad());
    }
    let (client_id, rest) = rest.split_at(client_len);
    let wire_len = u32::from_be_bytes(rest[..4].try_into().expect("4 bytes")) as usize;
    let wire = &rest[4..];
    if wire.len() != wire_len || message_id(wire) != id {
        return Err(bad());
    }
    Ok(OutgoingMessage {
        message_id: id,
        client_message_id: client_id.to_vec(),
        generation,
        wire: wire.to_vec(),
    })
}

/// `INBOX_RECORD_V1`: magic(7) version(1) generation(8) id(32) len(4)
/// plaintext. Present only while the message is undelivered.
pub(super) fn encode_inbox(
    generation: u64,
    id: &MessageId,
    plaintext: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(52 + plaintext.len()));
    out.extend_from_slice(INBOX_MAGIC);
    out.push(RECORD_VERSION);
    out.extend_from_slice(&generation.to_be_bytes());
    out.extend_from_slice(id);
    out.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
    out.extend_from_slice(plaintext);
    out
}

pub(super) fn decode_inbox(bytes: &[u8]) -> Result<IncomingMessage, MessagingError> {
    let bad = MessagingError::InvalidRecord("inbox");
    if bytes.len() < 52 || &bytes[..7] != INBOX_MAGIC || bytes[7] != RECORD_VERSION {
        return Err(bad);
    }
    let generation = u64::from_be_bytes(bytes[8..16].try_into().expect("8 bytes"));
    let id: MessageId = bytes[16..48].try_into().expect("32 bytes");
    let len = u32::from_be_bytes(bytes[48..52].try_into().expect("4 bytes")) as usize;
    if bytes.len() != 52 + len {
        return Err(bad);
    }
    Ok(IncomingMessage {
        message_id: id,
        generation,
        plaintext: Zeroizing::new(bytes[52..].to_vec()),
    })
}

/// `SEEN_RECORD_V1` and `SENDID_RECORD_V1` (sent or abandoned): magic(7)
/// version(1) id(32).
pub(super) fn encode_id_record(magic: &[u8; 7], id: &MessageId) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(40));
    out.extend_from_slice(magic);
    out.push(RECORD_VERSION);
    out.extend_from_slice(id);
    out
}

pub(super) fn decode_id_record(
    magic: &[u8; 7],
    bytes: &[u8],
    what: &'static str,
) -> Result<MessageId, MessagingError> {
    if bytes.len() != 40 || &bytes[..7] != magic || bytes[7] != RECORD_VERSION {
        return Err(MessagingError::InvalidRecord(what));
    }
    Ok(bytes[8..40].try_into().expect("32 bytes"))
}
