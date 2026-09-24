//! Store keys and the fixed-layout records of [`super`]: handle, outbox and
//! inbox entries.

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

// ── Records ───────────────────────────────────────────────────────────────────
//
// Fixed layouts, integers big-endian. Never transmitted; confidentiality and
// integrity come from the encrypted store.

pub(super) const HANDLE_MAGIC: &[u8; 7] = b"ARCHNDL";
pub(super) const OUTBOX_MAGIC: &[u8; 7] = b"ARCOUTB";
pub(super) const INBOX_MAGIC: &[u8; 7] = b"ARCINBX";
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

/// `OUTBOX_RECORD_V1`: magic(7) version(1) generation(8) id(32) len(4) wire.
pub(super) fn encode_outbox(generation: u64, id: &MessageId, wire: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(52 + wire.len()));
    out.extend_from_slice(OUTBOX_MAGIC);
    out.push(RECORD_VERSION);
    out.extend_from_slice(&generation.to_be_bytes());
    out.extend_from_slice(id);
    out.extend_from_slice(&(wire.len() as u32).to_be_bytes());
    out.extend_from_slice(wire);
    out
}

pub(super) fn decode_outbox(bytes: &[u8]) -> Result<OutgoingMessage, MessagingError> {
    let bad = MessagingError::InvalidRecord("outbox");
    if bytes.len() < 52 || &bytes[..7] != OUTBOX_MAGIC || bytes[7] != RECORD_VERSION {
        return Err(bad);
    }
    let generation = u64::from_be_bytes(bytes[8..16].try_into().expect("8 bytes"));
    let id: MessageId = bytes[16..48].try_into().expect("32 bytes");
    let len = u32::from_be_bytes(bytes[48..52].try_into().expect("4 bytes")) as usize;
    if bytes.len() != 52 + len {
        return Err(bad);
    }
    let wire = bytes[52..].to_vec();
    if message_id(&wire) != id {
        return Err(bad);
    }
    Ok(OutgoingMessage {
        message_id: id,
        generation,
        wire,
    })
}

pub(super) const INBOX_PENDING: u8 = 0;
pub(super) const INBOX_ACKNOWLEDGED: u8 = 1;

/// `INBOX_RECORD_V1`: magic(7) version(1) state(1) generation(8) id(32)
/// len(4) plaintext. An acknowledged record keeps no plaintext.
pub(super) fn encode_inbox(
    state: u8,
    generation: u64,
    id: &MessageId,
    plaintext: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(53 + plaintext.len()));
    out.extend_from_slice(INBOX_MAGIC);
    out.push(RECORD_VERSION);
    out.push(state);
    out.extend_from_slice(&generation.to_be_bytes());
    out.extend_from_slice(id);
    out.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
    out.extend_from_slice(plaintext);
    out
}

pub(super) struct InboxRecord {
    pub(super) acknowledged: bool,
    pub(super) message: IncomingMessage,
}

pub(super) fn decode_inbox(bytes: &[u8]) -> Result<InboxRecord, MessagingError> {
    let bad = MessagingError::InvalidRecord("inbox");
    if bytes.len() < 53 || &bytes[..7] != INBOX_MAGIC || bytes[7] != RECORD_VERSION {
        return Err(bad);
    }
    let acknowledged = match bytes[8] {
        INBOX_PENDING => false,
        INBOX_ACKNOWLEDGED => true,
        _ => return Err(bad),
    };
    let generation = u64::from_be_bytes(bytes[9..17].try_into().expect("8 bytes"));
    let id: MessageId = bytes[17..49].try_into().expect("32 bytes");
    let len = u32::from_be_bytes(bytes[49..53].try_into().expect("4 bytes")) as usize;
    if bytes.len() != 53 + len || (acknowledged && len != 0) {
        return Err(bad);
    }
    Ok(InboxRecord {
        acknowledged,
        message: IncomingMessage {
            message_id: id,
            generation,
            plaintext: Zeroizing::new(bytes[53..].to_vec()),
        },
    })
}
