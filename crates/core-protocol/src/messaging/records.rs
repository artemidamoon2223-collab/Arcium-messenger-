//! Store keys and the fixed-layout records of [`super`]: handle, provisional
//! handshake, outbox, inbox, send-id and seen entries.
//!
//! Only the `outbox:` and `inbox:` namespaces are ever listed, and they hold
//! only pending entries; everything kept after an acknowledgement lives in
//! `seen:` and `sendid:`, which are read by exact key only. So the cost of
//! listing pending messages does not grow with acknowledged history.

use zeroize::Zeroizing;

use super::{
    message_id, IncomingMessage, MessageId, MessagingError, OutgoingMessage, ProvisionalHandshake,
};

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

/// The handshake a responder received for `handle` and has not yet seen
/// authenticated.
pub(super) fn provisional_key(handle: u64) -> String {
    format!("hsin:v1/{handle:016x}")
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
pub(super) const PROVISIONAL_MAGIC: &[u8; 7] = b"ARCHSIN";
pub(super) const OUTBOX_MAGIC: &[u8; 7] = b"ARCOUTB";
pub(super) const INBOX_MAGIC: &[u8; 7] = b"ARCINBX";
pub(super) const SEEN_MAGIC: &[u8; 7] = b"ARCSEEN";
pub(super) const SENDID_MAGIC: &[u8; 7] = b"ARCSNDI";
/// A send-id record whose message the caller abandoned.
pub(super) const ABANDONED_MAGIC: &[u8; 7] = b"ARCSNDX";

/// Longest handshake a provisional record holds, in bytes.
pub const MAX_PROVISIONAL_HANDSHAKE_LEN: usize = 1024;
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

/// `PROVISIONAL_HANDSHAKE_RECORD_V1`: magic(7) version(1) peer_identity_pk(32)
/// len(2) handshake. The handshake bytes are opaque here and public.
pub(super) fn encode_provisional(
    p: &ProvisionalHandshake,
) -> Result<Zeroizing<Vec<u8>>, MessagingError> {
    if p.handshake.is_empty() || p.handshake.len() > MAX_PROVISIONAL_HANDSHAKE_LEN {
        return Err(MessagingError::InvalidRecord("provisional handshake"));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(42 + p.handshake.len()));
    out.extend_from_slice(PROVISIONAL_MAGIC);
    out.push(RECORD_VERSION);
    out.extend_from_slice(&p.peer_identity_pk);
    out.extend_from_slice(&(p.handshake.len() as u16).to_be_bytes());
    out.extend_from_slice(&p.handshake);
    Ok(out)
}

pub(super) fn decode_provisional(bytes: &[u8]) -> Result<ProvisionalHandshake, MessagingError> {
    let bad = MessagingError::InvalidRecord("provisional handshake");
    if bytes.len() < 42 || &bytes[..7] != PROVISIONAL_MAGIC || bytes[7] != RECORD_VERSION {
        return Err(bad);
    }
    let len = u16::from_be_bytes([bytes[40], bytes[41]]) as usize;
    if len == 0 || len > MAX_PROVISIONAL_HANDSHAKE_LEN || bytes.len() != 42 + len {
        return Err(bad);
    }
    Ok(ProvisionalHandshake {
        peer_identity_pk: bytes[8..40].try_into().expect("32 bytes"),
        handshake: bytes[42..].to_vec(),
    })
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

#[cfg(test)]
mod tests {
    //! Each stored-record decoder refuses every way a record can be wrong,
    //! each on its own, and accepts the exact bounds. The records are
    //! encrypted by the store, so a wrong one comes from a bug or an older
    //! format, never from a peer; these pin that it is refused, not misread.
    use super::*;

    fn with(base: &[u8], i: usize, v: u8) -> Vec<u8> {
        let mut b = base.to_vec();
        b[i] = v;
        b
    }

    #[test]
    fn handle_and_id_records_refuse_each_defect_alone() {
        let peer = [7u8; 32];
        let good = encode_handle(&peer).to_vec();
        assert_eq!(decode_handle(&good).unwrap(), peer);
        assert!(decode_handle(&with(&good, 0, b'X')).is_err(), "magic");
        assert!(decode_handle(&with(&good, 7, 2)).is_err(), "version");
        assert!(decode_handle(&good[..39]).is_err(), "short");
        assert!(decode_handle(&[&good[..], &[0]].concat()).is_err(), "long");

        let id = [9u8; 32];
        let good = encode_id_record(SEEN_MAGIC, &id).to_vec();
        assert_eq!(decode_id_record(SEEN_MAGIC, &good, "seen").unwrap(), id);
        assert!(decode_id_record(SENDID_MAGIC, &good, "seen").is_err(), "magic");
        assert!(decode_id_record(SEEN_MAGIC, &with(&good, 7, 2), "seen").is_err(), "version");
        assert!(decode_id_record(SEEN_MAGIC, &good[..39], "seen").is_err(), "short");
        assert!(decode_id_record(SEEN_MAGIC, &[&good[..], &[0]].concat(), "seen").is_err(), "long");
    }

    #[test]
    fn provisional_records_refuse_each_defect_alone_and_accept_the_bounds() {
        let p = |len: usize| ProvisionalHandshake {
            peer_identity_pk: [3u8; 32],
            handshake: vec![4u8; len],
        };
        for len in [1, MAX_PROVISIONAL_HANDSHAKE_LEN] {
            let good = encode_provisional(&p(len)).unwrap().to_vec();
            assert_eq!(decode_provisional(&good).unwrap(), p(len), "len {len}");
        }
        assert!(encode_provisional(&p(0)).is_err(), "empty handshake");
        assert!(encode_provisional(&p(MAX_PROVISIONAL_HANDSHAKE_LEN + 1)).is_err(), "too long");

        let good = encode_provisional(&p(84)).unwrap().to_vec();
        assert!(decode_provisional(&with(&good, 0, b'X')).is_err(), "magic");
        assert!(decode_provisional(&with(&good, 7, 2)).is_err(), "version");
        assert!(decode_provisional(&good[..20]).is_err(), "shorter than the fixed part");
        assert!(decode_provisional(&good[..41]).is_err(), "one byte short of the fixed part");
        assert!(decode_provisional(&good[..good.len() - 1]).is_err(), "length mismatch");
        let mut zero = good[..42].to_vec();
        zero[40..42].copy_from_slice(&0u16.to_be_bytes());
        assert!(decode_provisional(&zero).is_err(), "declared length 0");
        let over = MAX_PROVISIONAL_HANDSHAKE_LEN + 1;
        let mut long = good[..42].to_vec();
        long[40..42].copy_from_slice(&(over as u16).to_be_bytes());
        long.extend(vec![4u8; over]);
        assert!(decode_provisional(&long).is_err(), "declared length over the limit");
    }

    #[test]
    fn outbox_records_refuse_each_defect_alone_and_accept_the_bounds() {
        let enc = |client: &[u8], wire: &[u8]| encode_outbox(5, &message_id(wire), client, wire).to_vec();
        // Bounds: an empty wire, a one-byte and a longest client id.
        for (client, wire) in [
            (vec![1u8], vec![]),
            (vec![1u8], vec![2u8; 30]),
            (vec![1u8; MAX_CLIENT_MESSAGE_ID_LEN], vec![2u8; 3]),
        ] {
            let m = decode_outbox(&enc(&client, &wire)).unwrap();
            assert_eq!((m.generation, m.client_message_id, m.wire), (5, client, wire));
        }
        let good = enc(&[1u8], &[2u8; 30]);
        assert!(decode_outbox(&with(&good, 0, b'X')).is_err(), "magic");
        assert!(decode_outbox(&with(&good, 7, 2)).is_err(), "version");
        assert!(decode_outbox(&good[..20]).is_err(), "shorter than the fixed part");
        assert!(decode_outbox(&good[..52]).is_err(), "one byte short of the fixed part");
        // Well-formed but for one rule each: the decoder alone must refuse.
        assert!(decode_outbox(&enc(&[], &[2u8; 5])).is_err(), "client id length 0");
        let too_long = vec![1u8; MAX_CLIENT_MESSAGE_ID_LEN + 1];
        assert!(decode_outbox(&enc(&too_long, &[2u8; 3])).is_err(), "client id length over the limit");
        // A client id that leaves fewer than four bytes for the wire length.
        let short = enc(&[1u8], &[]);
        assert!(decode_outbox(&short[..short.len() - 1]).is_err(), "no room for the wire length");
        assert!(decode_outbox(&good[..good.len() - 1]).is_err(), "wire length mismatch");
        assert!(decode_outbox(&[&good[..], &[0]].concat()).is_err(), "trailing byte");
        assert!(decode_outbox(&with(&good, 16, good[16] ^ 1)).is_err(), "id is not the wire's");
    }

    #[test]
    fn inbox_records_refuse_each_defect_alone_and_accept_the_bounds() {
        for text in [&b""[..], b"hello"] {
            let good = encode_inbox(3, &[8u8; 32], text).to_vec();
            let m = decode_inbox(&good).unwrap();
            assert_eq!((m.generation, &**m.plaintext), (3, text));
        }
        let good = encode_inbox(3, &[8u8; 32], b"hello").to_vec();
        assert!(decode_inbox(&with(&good, 0, b'X')).is_err(), "magic");
        assert!(decode_inbox(&with(&good, 7, 2)).is_err(), "version");
        assert!(decode_inbox(&good[..20]).is_err(), "shorter than the fixed part");
        assert!(decode_inbox(&good[..51]).is_err(), "one byte short of the fixed part");
        assert!(decode_inbox(&good[..good.len() - 1]).is_err(), "length mismatch");
        assert!(decode_inbox(&[&good[..], &[0]].concat()).is_err(), "trailing byte");
    }
}
