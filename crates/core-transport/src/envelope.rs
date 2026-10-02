//! `TRANSPORT_ENVELOPE_V1` — the fixed 24-byte frame that wraps every byte this
//! project puts on a transport.
//!
//! A Tor `DataStream` is a byte stream with no message boundaries, so something
//! has to say where one message ends and the next begins. That is this module's
//! whole job, and it is deliberately the *only* job it has: it encodes and parses
//! bytes, and it neither opens connections nor decides what a message means.
//!
//! ```text
//! off  len  field              encoding
//!   0    1  envelope_version   u8, must be 0x01
//!   1    1  message_type       u8, one of four values
//!   2    2  reserved           u16 big-endian, must be 0x0000
//!   4   16  routing_tag        opaque bytes
//!  20    4  payload_length     u32 big-endian
//!  24    N  payload
//! ```
//!
//! Every integer is big-endian, matching `ARCIUM_X3DH_FORMAT_V1`. The header is a
//! constant 24 bytes for every message type, and all offsets are multiples of
//! four, so a reader can take the header before it knows anything else.
//!
//! # What this module is not
//!
//! - **Not a transport.** Nothing here reads a socket, opens a circuit or touches
//!   arti. The frozen X3DH structures are not parsed either — this layer only
//!   checks that a payload claiming to be one of them has that structure's length.
//! - **Not routing.** [`EnvelopeHeader::routing_tag`] is carried and shape-checked;
//!   how the tag is *derived* from an identity key, and how a receiver maps one to
//!   a session, are a later change and appear nowhere in this file.
//! - **Not authentication.** Parsing successfully means the bytes are well-formed,
//!   nothing more. A well-formed envelope from an attacker parses exactly as
//!   cleanly as one from the peer.
//!
//! # Errors stay local
//!
//! Every [`EnvelopeError`] below is for this process. **None of them may be sent
//! to a remote peer**, and the protocol has no `ERROR` message type for that
//! reason: telling a stranger apart "unknown routing tag" from "bad version" from
//! "wrong length" hands them an oracle for probing who this device has sessions
//! with. The only correct reaction to any invalid input is to close the
//! connection without explaining. The variants are distinct so *tests and logs*
//! can tell the cases apart, not so a peer can.
//!
//! # Allocation
//!
//! `payload_length` is attacker-controlled, so it is validated against
//! [`MAX_PAYLOAD_LEN`] inside [`parse_header`] — from the 24 header bytes alone,
//! with no payload in hand. A streaming reader must therefore parse the header,
//! let this module reject it, and only then allocate a buffer of the declared
//! size. Reserving capacity from an unvalidated length is the bug this ordering
//! exists to prevent.
//!
//! # Forward requirement: the header will be authenticated (decision D4)
//!
//! A later change binds the **complete 24-byte header, `payload_length`
//! included**, into the Double Ratchet AEAD associated data for
//! [`MessageType::RatchetMessage`]. Two consequences are already visible here:
//!
//! 1. **One canonical serialization.** [`EnvelopeHeader::to_bytes`] is the single
//!    place header bytes are produced. Nothing else in this crate may lay out
//!    those 24 bytes, because two encoders that agree today are two encoders that
//!    can disagree later, and the disagreement would surface only as an
//!    unexplained authentication failure on a real device.
//! 2. **Receivers keep the bytes they received.** [`ReceivedHeader`] retains the
//!    exact 24 bytes it parsed and hands them back through
//!    [`ReceivedHeader::header_bytes`]. The AEAD check must use those, never a
//!    header re-serialized from the decoded fields. A test below pins that the
//!    two are identical today; the API still returns the received bytes so that
//!    correctness does not *depend* on that invariant surviving a future field.

use thiserror::Error;

/// The only envelope version this build speaks.
pub const ENVELOPE_VERSION_V1: u8 = 0x01;

/// Fixed header width, identical for every message type.
pub const ENVELOPE_HEADER_LEN: usize = 24;

/// Width of the routing tag field.
pub const ROUTING_TAG_LEN: usize = 16;

/// The one encoding of "this message carries no routing tag".
///
/// Checked rather than ignored: an unchecked 16-byte field that a sender may fill
/// freely is a covert channel, and it would also make "no tag" ambiguous with a
/// tag that happens to be zero.
pub const ABSENT_ROUTING_TAG: [u8; ROUTING_TAG_LEN] = [0u8; ROUTING_TAG_LEN];

/// Largest payload any envelope may declare or carry, in bytes.
///
/// 64 KiB is far above any real message and small enough to allocate on a phone
/// without thought. It is an absolute ceiling checked before the per-type rules,
/// so the allocation guard never depends on the message type being sensible.
pub const MAX_PAYLOAD_LEN: usize = 65_536;

/// Largest complete frame: header plus the largest permitted payload.
pub const MAX_ENVELOPE_LEN: usize = ENVELOPE_HEADER_LEN + MAX_PAYLOAD_LEN;

// ── Payload lengths of the frozen structures ────────────────────────────────
//
// These are local copies, on purpose. This crate must not grow a dependency on
// the crates that define the structures merely to name their sizes: the envelope
// is supposed to be a pure byte layer that can be reasoned about, tested and
// reviewed without pulling in X3DH or the ratchet.
//
// The cost of that independence is that these numbers can drift from the
// definitions they mirror, and nothing in this crate would notice. A later
// change MUST add a cross-layer regression test — in a crate that can see both
// sides — asserting that the lengths predicted here equal the lengths the real
// serializers emit. Until that test exists, treat every constant in this block
// as unproven against its source.

/// `PREKEY_BUNDLE_V1`, the payload of a [`MessageType::PrekeyResponse`].
pub const PREKEY_BUNDLE_V1_LEN: usize = 204;

/// `INITIATOR_HANDSHAKE_V1`, the payload of a [`MessageType::SessionInit`].
pub const INITIATOR_HANDSHAKE_V1_LEN: usize = 84;

/// Serialized Double Ratchet header: `dh(32) || pn(4) || n(4)`.
pub const RATCHET_HEADER_LEN: usize = 40;

/// XChaCha20-Poly1305 nonce, transmitted in front of the ciphertext.
pub const XCHACHA_NONCE_LEN: usize = 24;

/// Poly1305 authentication tag appended to the ciphertext.
pub const POLY1305_TAG_LEN: usize = 16;

/// Smallest possible [`MessageType::RatchetMessage`] payload: the framing
/// overhead around an empty plaintext.
///
/// Derived from its three parts rather than written as `80`, so the number cannot
/// drift away from the reason it has that value. XChaCha20-Poly1305 is a stream
/// cipher with a constant-size tag and no padding, so a payload carrying a
/// plaintext of `n` bytes is always exactly `RATCHET_MIN_PAYLOAD_LEN + n` long —
/// which is what makes `payload_length` computable before encryption, and so
/// bindable into the AEAD associated data.
pub const RATCHET_MIN_PAYLOAD_LEN: usize =
    RATCHET_HEADER_LEN + XCHACHA_NONCE_LEN + POLY1305_TAG_LEN;

// ── Field offsets ───────────────────────────────────────────────────────────

const OFF_VERSION: usize = 0;
const OFF_MESSAGE_TYPE: usize = 1;
const OFF_RESERVED: usize = 2;
const OFF_ROUTING_TAG: usize = 4;
const OFF_PAYLOAD_LENGTH: usize = 20;

/// What a frame carries. Four types, and no others: an `ACK`, `ERROR` or `PING`
/// would each need its own security argument, and the first milestone has no use
/// for one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Ask a peer for its prekey bundle. Empty payload.
    PrekeyRequest = 0x01,
    /// A peer's `PREKEY_BUNDLE_V1`, in answer to a request.
    PrekeyResponse = 0x02,
    /// An `INITIATOR_HANDSHAKE_V1` opening a session.
    SessionInit = 0x03,
    /// A Double Ratchet message on an established session.
    RatchetMessage = 0x04,
}

impl MessageType {
    /// The wire byte for this type.
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    /// Decodes a wire byte, rejecting anything outside the four defined values.
    pub fn from_byte(byte: u8) -> Result<Self, EnvelopeError> {
        match byte {
            0x01 => Ok(MessageType::PrekeyRequest),
            0x02 => Ok(MessageType::PrekeyResponse),
            0x03 => Ok(MessageType::SessionInit),
            0x04 => Ok(MessageType::RatchetMessage),
            other => Err(EnvelopeError::UnknownMessageType {
                message_type: other,
            }),
        }
    }

    /// Inclusive `(min, max)` payload length for this type.
    ///
    /// Three of the four are exact equalities, which is most of what separates the
    /// parsing domains. It is not all of it: see
    /// `length_alone_does_not_separate_session_init_from_a_ratchet_message`.
    fn payload_length_bounds(self) -> (u32, u32) {
        match self {
            MessageType::PrekeyRequest => (0, 0),
            MessageType::PrekeyResponse => {
                (PREKEY_BUNDLE_V1_LEN as u32, PREKEY_BUNDLE_V1_LEN as u32)
            }
            MessageType::SessionInit => (
                INITIATOR_HANDSHAKE_V1_LEN as u32,
                INITIATOR_HANDSHAKE_V1_LEN as u32,
            ),
            MessageType::RatchetMessage => (RATCHET_MIN_PAYLOAD_LEN as u32, MAX_PAYLOAD_LEN as u32),
        }
    }

    /// Whether this type names its sender with a routing tag.
    ///
    /// The two prekey types do not, and must carry [`ABSENT_ROUTING_TAG`]: a
    /// bundle request is answered before either side knows who is asking, and a
    /// tag there would announce the asker's identity earlier than the protocol
    /// intends.
    fn carries_routing_tag(self) -> bool {
        matches!(self, MessageType::SessionInit | MessageType::RatchetMessage)
    }
}

/// Why some bytes are not a valid envelope.
///
/// These never leave the process — see the module docs. Distinct variants exist
/// for tests and local diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EnvelopeError {
    /// Fewer bytes are available than the frame needs.
    #[error("truncated frame: needed {needed} bytes, have {available}")]
    TruncatedFrame { needed: usize, available: usize },

    /// The version byte is not [`ENVELOPE_VERSION_V1`].
    #[error("unsupported envelope version {version:#04x}")]
    UnsupportedEnvelopeVersion { version: u8 },

    /// The type byte is none of the four defined values.
    #[error("unknown message type {message_type:#04x}")]
    UnknownMessageType { message_type: u8 },

    /// The reserved field is not zero. Rejecting rather than ignoring keeps the
    /// slot usable: a future version can give it meaning knowing that no peer
    /// speaking this version ever set it.
    #[error("reserved field must be zero, got {reserved:#06x}")]
    ReservedNotZero { reserved: u16 },

    /// A type that must not name its sender carried a non-zero routing tag.
    #[error("{message_type:?} must carry an all-zero routing tag")]
    RoutingTagMustBeZero { message_type: MessageType },

    /// A type that must name its sender carried the all-zero routing tag.
    #[error("{message_type:?} must carry a non-zero routing tag")]
    RoutingTagMustBeSet { message_type: MessageType },

    /// The declared payload exceeds [`MAX_PAYLOAD_LEN`]. Checked before the
    /// per-type rules and before any allocation.
    #[error("payload of {declared} bytes exceeds the {MAX_PAYLOAD_LEN}-byte limit")]
    PayloadTooLarge { declared: u32 },

    /// The declared payload is outside the range this message type permits.
    #[error("{message_type:?} requires a payload of {min}..={max} bytes, got {declared}")]
    WrongPayloadLength {
        message_type: MessageType,
        declared: u32,
        min: u32,
        max: u32,
    },
}

/// A validated envelope header.
///
/// Constructing one is the only way to produce header bytes, and construction
/// enforces every rule a parser enforces, so a header that can be serialized is a
/// header that will parse back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeHeader {
    message_type: MessageType,
    routing_tag: [u8; ROUTING_TAG_LEN],
    payload_length: u32,
}

impl EnvelopeHeader {
    /// Builds a header, rejecting any combination a peer would reject.
    ///
    /// `payload_length` is passed rather than inferred from a buffer: a sender
    /// knows the length before it has the bytes — for a ratchet message, plaintext
    /// length plus [`RATCHET_MIN_PAYLOAD_LEN`] — and decision D4 requires the
    /// header to exist before the payload is encrypted.
    pub fn new(
        message_type: MessageType,
        routing_tag: [u8; ROUTING_TAG_LEN],
        payload_length: u32,
    ) -> Result<Self, EnvelopeError> {
        check_routing_tag(message_type, &routing_tag)?;
        check_payload_length(message_type, payload_length)?;
        Ok(Self {
            message_type,
            routing_tag,
            payload_length,
        })
    }

    /// The canonical 24 bytes for this header. **The only serializer in this
    /// crate** — see the module docs on decision D4.
    pub fn to_bytes(&self) -> [u8; ENVELOPE_HEADER_LEN] {
        let mut out = [0u8; ENVELOPE_HEADER_LEN];
        out[OFF_VERSION] = ENVELOPE_VERSION_V1;
        out[OFF_MESSAGE_TYPE] = self.message_type.as_byte();
        // reserved stays zero; written explicitly so the field is visible here.
        out[OFF_RESERVED..OFF_RESERVED + 2].copy_from_slice(&0u16.to_be_bytes());
        out[OFF_ROUTING_TAG..OFF_ROUTING_TAG + ROUTING_TAG_LEN].copy_from_slice(&self.routing_tag);
        out[OFF_PAYLOAD_LENGTH..OFF_PAYLOAD_LENGTH + 4]
            .copy_from_slice(&self.payload_length.to_be_bytes());
        out
    }

    pub fn message_type(&self) -> MessageType {
        self.message_type
    }

    pub fn routing_tag(&self) -> &[u8; ROUTING_TAG_LEN] {
        &self.routing_tag
    }

    pub fn payload_length(&self) -> u32 {
        self.payload_length
    }
}

/// A header that came off the wire, kept together with the exact bytes it was
/// parsed from.
///
/// The bytes are retained because decision D4 makes them associated data for the
/// AEAD check on a ratchet message, and that check must run against what the
/// sender actually sent. Re-serializing [`EnvelopeHeader`] would today produce
/// the same 24 bytes — a test pins it — but relying on that turns a future
/// encoding change into a silent authentication failure instead of a compile
/// error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceivedHeader {
    bytes: [u8; ENVELOPE_HEADER_LEN],
    header: EnvelopeHeader,
}

impl ReceivedHeader {
    /// The exact 24 bytes as received. **This is what the AEAD associated data
    /// must be built from.**
    pub fn header_bytes(&self) -> &[u8; ENVELOPE_HEADER_LEN] {
        &self.bytes
    }

    /// The decoded view of those bytes.
    pub fn header(&self) -> &EnvelopeHeader {
        &self.header
    }

    pub fn message_type(&self) -> MessageType {
        self.header.message_type
    }

    pub fn routing_tag(&self) -> &[u8; ROUTING_TAG_LEN] {
        &self.header.routing_tag
    }

    /// The payload length this header declares. Already checked against
    /// [`MAX_PAYLOAD_LEN`] and against the type's own bounds, so it is safe to
    /// allocate.
    pub fn payload_length(&self) -> u32 {
        self.header.payload_length
    }
}

/// Parses and validates the 24-byte header at the front of `bytes`.
///
/// Only the first [`ENVELOPE_HEADER_LEN`] bytes are read; anything after them is
/// the payload and is not inspected. A streaming reader should call this with
/// exactly the header it has read, precisely so an over-large declared length is
/// rejected before a payload buffer exists.
///
/// Checks run in wire order — version, type, reserved, routing tag, length — with
/// the absolute [`MAX_PAYLOAD_LEN`] ceiling applied before the per-type bounds.
pub fn parse_header(bytes: &[u8]) -> Result<ReceivedHeader, EnvelopeError> {
    if bytes.len() < ENVELOPE_HEADER_LEN {
        return Err(EnvelopeError::TruncatedFrame {
            needed: ENVELOPE_HEADER_LEN,
            available: bytes.len(),
        });
    }
    let raw: [u8; ENVELOPE_HEADER_LEN] = bytes[..ENVELOPE_HEADER_LEN]
        .try_into()
        .expect("slice is ENVELOPE_HEADER_LEN bytes");

    let version = raw[OFF_VERSION];
    if version != ENVELOPE_VERSION_V1 {
        return Err(EnvelopeError::UnsupportedEnvelopeVersion { version });
    }

    let message_type = MessageType::from_byte(raw[OFF_MESSAGE_TYPE])?;

    let reserved = u16::from_be_bytes([raw[OFF_RESERVED], raw[OFF_RESERVED + 1]]);
    if reserved != 0 {
        return Err(EnvelopeError::ReservedNotZero { reserved });
    }

    let routing_tag: [u8; ROUTING_TAG_LEN] = raw
        [OFF_ROUTING_TAG..OFF_ROUTING_TAG + ROUTING_TAG_LEN]
        .try_into()
        .expect("slice is ROUTING_TAG_LEN bytes");
    check_routing_tag(message_type, &routing_tag)?;

    let payload_length = u32::from_be_bytes(
        raw[OFF_PAYLOAD_LENGTH..OFF_PAYLOAD_LENGTH + 4]
            .try_into()
            .expect("slice is 4 bytes"),
    );
    check_payload_length(message_type, payload_length)?;

    Ok(ReceivedHeader {
        bytes: raw,
        header: EnvelopeHeader {
            message_type,
            routing_tag,
            payload_length,
        },
    })
}

/// Parses one complete frame from the front of `bytes`, returning the header and
/// a borrow of exactly its payload.
///
/// Bytes beyond the frame are left alone: on a stream they are the beginning of
/// the next frame, not an error.
pub fn parse_frame(bytes: &[u8]) -> Result<(ReceivedHeader, &[u8]), EnvelopeError> {
    let header = parse_header(bytes)?;
    let payload_length = header.payload_length() as usize;
    let frame_len = ENVELOPE_HEADER_LEN + payload_length;
    if bytes.len() < frame_len {
        return Err(EnvelopeError::TruncatedFrame {
            needed: frame_len,
            available: bytes.len(),
        });
    }
    Ok((header, &bytes[ENVELOPE_HEADER_LEN..frame_len]))
}

/// Builds a complete frame: the canonical header followed by `payload`.
///
/// Fails, rather than emitting something a peer would reject, if the payload does
/// not suit the message type.
pub fn encode(
    message_type: MessageType,
    routing_tag: [u8; ROUTING_TAG_LEN],
    payload: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    // Bound the length before narrowing it, so the cast below cannot wrap on a
    // caller-supplied buffer.
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(EnvelopeError::PayloadTooLarge {
            declared: u32::try_from(payload.len()).unwrap_or(u32::MAX),
        });
    }
    let header = EnvelopeHeader::new(message_type, routing_tag, payload.len() as u32)?;

    let mut out = Vec::with_capacity(ENVELOPE_HEADER_LEN + payload.len());
    out.extend_from_slice(&header.to_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn check_routing_tag(
    message_type: MessageType,
    routing_tag: &[u8; ROUTING_TAG_LEN],
) -> Result<(), EnvelopeError> {
    let is_absent = routing_tag == &ABSENT_ROUTING_TAG;
    match (message_type.carries_routing_tag(), is_absent) {
        (false, false) => Err(EnvelopeError::RoutingTagMustBeZero { message_type }),
        (true, true) => Err(EnvelopeError::RoutingTagMustBeSet { message_type }),
        _ => Ok(()),
    }
}

fn check_payload_length(
    message_type: MessageType,
    payload_length: u32,
) -> Result<(), EnvelopeError> {
    // Absolute ceiling first and independently of the type: this is the check the
    // allocation guard rests on, and it must not become conditional on the type
    // byte being one the per-type table happens to be generous about.
    if payload_length > MAX_PAYLOAD_LEN as u32 {
        return Err(EnvelopeError::PayloadTooLarge {
            declared: payload_length,
        });
    }
    let (min, max) = message_type.payload_length_bounds();
    if !(min..=max).contains(&payload_length) {
        return Err(EnvelopeError::WrongPayloadLength {
            message_type,
            declared: payload_length,
            min,
            max,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_TYPES: [MessageType; 4] = [
        MessageType::PrekeyRequest,
        MessageType::PrekeyResponse,
        MessageType::SessionInit,
        MessageType::RatchetMessage,
    ];

    fn tag(byte: u8) -> [u8; ROUTING_TAG_LEN] {
        [byte; ROUTING_TAG_LEN]
    }

    /// A valid payload of the shortest length each type accepts.
    fn minimal_payload(message_type: MessageType) -> Vec<u8> {
        let (min, _) = message_type.payload_length_bounds();
        vec![0xAB; min as usize]
    }

    fn tag_for(message_type: MessageType) -> [u8; ROUTING_TAG_LEN] {
        if message_type.carries_routing_tag() {
            tag(0x5C)
        } else {
            ABSENT_ROUTING_TAG
        }
    }

    fn valid_frame(message_type: MessageType) -> Vec<u8> {
        encode(
            message_type,
            tag_for(message_type),
            &minimal_payload(message_type),
        )
        .expect("fixture must be valid")
    }

    // ── Layout constants ────────────────────────────────────────────────────

    /// The header width is part of the wire contract and is about to become part
    /// of an AEAD input, so it is pinned rather than left to the offsets.
    #[test]
    fn header_is_exactly_twenty_four_bytes_and_fields_tile_it() {
        assert_eq!(ENVELOPE_HEADER_LEN, 24);
        assert_eq!(OFF_VERSION, 0);
        assert_eq!(OFF_MESSAGE_TYPE, 1);
        assert_eq!(OFF_RESERVED, 2);
        assert_eq!(OFF_ROUTING_TAG, 4);
        assert_eq!(OFF_PAYLOAD_LENGTH, 20);
        // The fields cover the header exactly, with no gap and no overlap.
        assert_eq!(OFF_PAYLOAD_LENGTH + 4, ENVELOPE_HEADER_LEN);
        assert_eq!(OFF_ROUTING_TAG + ROUTING_TAG_LEN, OFF_PAYLOAD_LENGTH);
    }

    /// The ratchet minimum must stay derived from its three parts. Asserting the
    /// sum *and* each part means a future edit that changes one component and
    /// patches the total back to 80 still fails here.
    #[test]
    fn ratchet_minimum_is_derived_from_its_parts() {
        assert_eq!(RATCHET_HEADER_LEN, 40, "dh(32) || pn(4) || n(4)");
        assert_eq!(XCHACHA_NONCE_LEN, 24);
        assert_eq!(POLY1305_TAG_LEN, 16);
        assert_eq!(
            RATCHET_MIN_PAYLOAD_LEN,
            RATCHET_HEADER_LEN + XCHACHA_NONCE_LEN + POLY1305_TAG_LEN
        );
        assert_eq!(RATCHET_MIN_PAYLOAD_LEN, 80, "current value of the sum");
    }

    /// These mirror definitions in other crates that this one deliberately cannot
    /// see. The test pins the values this crate assumes; it does **not** prove
    /// they match their sources, which needs the cross-layer test the module docs
    /// require.
    #[test]
    fn frozen_payload_lengths_are_the_assumed_values() {
        assert_eq!(PREKEY_BUNDLE_V1_LEN, 204);
        assert_eq!(INITIATOR_HANDSHAKE_V1_LEN, 84);
        assert_eq!(MAX_PAYLOAD_LEN, 65_536);
        assert_eq!(MAX_ENVELOPE_LEN, 24 + 65_536);
    }

    // ── Message types ───────────────────────────────────────────────────────

    #[test]
    fn message_type_bytes_round_trip() {
        for t in ALL_TYPES {
            assert_eq!(MessageType::from_byte(t.as_byte()), Ok(t));
        }
        assert_eq!(MessageType::PrekeyRequest.as_byte(), 0x01);
        assert_eq!(MessageType::PrekeyResponse.as_byte(), 0x02);
        assert_eq!(MessageType::SessionInit.as_byte(), 0x03);
        assert_eq!(MessageType::RatchetMessage.as_byte(), 0x04);
    }

    #[test]
    fn undefined_type_bytes_are_rejected() {
        for byte in [0x00u8, 0x05, 0x7f, 0x80, 0xff] {
            assert_eq!(
                MessageType::from_byte(byte),
                Err(EnvelopeError::UnknownMessageType { message_type: byte }),
                "byte {byte:#04x} must not decode to a message type"
            );
        }
    }

    // ── Round trip ──────────────────────────────────────────────────────────

    #[test]
    fn every_type_round_trips_through_encode_and_parse() {
        for t in ALL_TYPES {
            let payload = minimal_payload(t);
            let frame = encode(t, tag_for(t), &payload).unwrap();
            assert_eq!(frame.len(), ENVELOPE_HEADER_LEN + payload.len());

            let (received, parsed_payload) = parse_frame(&frame).unwrap();
            assert_eq!(received.message_type(), t);
            assert_eq!(received.routing_tag(), &tag_for(t));
            assert_eq!(received.payload_length() as usize, payload.len());
            assert_eq!(parsed_payload, &payload[..]);
        }
    }

    /// Decision D4 rests on there being one serialization. This pins that the
    /// decoded view re-serializes to the bytes it came from — which is why
    /// [`ReceivedHeader::header_bytes`] can be trusted to be canonical, and not a
    /// licence to rebuild the header instead of keeping it.
    #[test]
    fn re_serializing_a_parsed_header_reproduces_the_received_bytes() {
        for t in ALL_TYPES {
            let frame = valid_frame(t);
            let received = parse_header(&frame).unwrap();
            assert_eq!(
                received.header().to_bytes(),
                *received.header_bytes(),
                "{t:?}: canonical serialization must be the received bytes"
            );
            assert_eq!(&frame[..ENVELOPE_HEADER_LEN], received.header_bytes());
        }
    }

    /// The bytes handed to the AEAD must be the ones that arrived, so the
    /// accessor has to expose the *whole* fixed header, `payload_length`
    /// included — that inclusion is the correction decision D4 made.
    #[test]
    fn received_header_bytes_cover_the_complete_fixed_header() {
        let frame = valid_frame(MessageType::RatchetMessage);
        let received = parse_header(&frame).unwrap();
        let bytes = received.header_bytes();

        assert_eq!(bytes.len(), ENVELOPE_HEADER_LEN);
        assert_eq!(bytes[OFF_VERSION], ENVELOPE_VERSION_V1);
        assert_eq!(
            bytes[OFF_MESSAGE_TYPE],
            MessageType::RatchetMessage.as_byte()
        );
        assert_eq!(
            &bytes[OFF_ROUTING_TAG..OFF_ROUTING_TAG + ROUTING_TAG_LEN],
            &tag(0x5C)
        );
        assert_eq!(
            u32::from_be_bytes(bytes[OFF_PAYLOAD_LENGTH..].try_into().unwrap()),
            RATCHET_MIN_PAYLOAD_LEN as u32,
            "the length field is inside the authenticated span, so it must be readable there"
        );
    }

    // ── Big-endian encoding ─────────────────────────────────────────────────

    /// `payload_length` is big-endian. The vector is chosen so the two byte
    /// orders differ; a palindromic length would let a little-endian
    /// implementation pass this test.
    #[test]
    fn payload_length_is_big_endian() {
        let len: u32 = 0x0000_1234; // 4660 bytes, comfortably a valid ratchet payload
        let payload = vec![0u8; len as usize];
        let frame = encode(MessageType::RatchetMessage, tag(1), &payload).unwrap();

        assert_eq!(
            &frame[OFF_PAYLOAD_LENGTH..OFF_PAYLOAD_LENGTH + 4],
            &[0x00, 0x00, 0x12, 0x34],
            "length must be big-endian on the wire"
        );

        let on_wire: [u8; 4] = frame[OFF_PAYLOAD_LENGTH..OFF_PAYLOAD_LENGTH + 4]
            .try_into()
            .unwrap();
        assert_eq!(u32::from_be_bytes(on_wire), len);
        assert_ne!(
            u32::from_le_bytes(on_wire),
            len,
            "test vector must not be byte-order symmetric, or it proves nothing"
        );
    }

    #[test]
    fn reserved_is_written_as_two_zero_bytes() {
        let frame = valid_frame(MessageType::PrekeyRequest);
        assert_eq!(&frame[OFF_RESERVED..OFF_RESERVED + 2], &[0x00, 0x00]);
    }

    // ── Header field validation ─────────────────────────────────────────────

    #[test]
    fn a_foreign_envelope_version_is_rejected() {
        for version in [0x00u8, 0x02, 0xff] {
            let mut frame = valid_frame(MessageType::RatchetMessage);
            frame[OFF_VERSION] = version;
            assert_eq!(
                parse_header(&frame),
                Err(EnvelopeError::UnsupportedEnvelopeVersion { version })
            );
        }
    }

    #[test]
    fn an_unknown_message_type_is_rejected() {
        let mut frame = valid_frame(MessageType::RatchetMessage);
        frame[OFF_MESSAGE_TYPE] = 0x09;
        assert_eq!(
            parse_header(&frame),
            Err(EnvelopeError::UnknownMessageType { message_type: 0x09 })
        );
    }

    /// Rejected, not ignored: a peer that silently dropped this field could be
    /// downgraded by a future version that gives it meaning.
    #[test]
    fn a_non_zero_reserved_field_is_rejected_in_either_byte() {
        for (hi, lo, expected) in [(0x00u8, 0x01u8, 0x0001u16), (0x01, 0x00, 0x0100)] {
            let mut frame = valid_frame(MessageType::RatchetMessage);
            frame[OFF_RESERVED] = hi;
            frame[OFF_RESERVED + 1] = lo;
            assert_eq!(
                parse_header(&frame),
                Err(EnvelopeError::ReservedNotZero { reserved: expected })
            );
        }
    }

    /// The documented check order is observable, so it is pinned: a frame that
    /// is wrong in every field reports the *first* problem in wire order, and
    /// fixing that one reveals the next. Order matters because the length check
    /// — the one a reader's allocation depends on — must never be reached with a
    /// message type that was never validated.
    #[test]
    fn checks_run_in_wire_order() {
        let mut frame = valid_frame(MessageType::PrekeyRequest);
        frame[OFF_VERSION] = 0x02;
        frame[OFF_MESSAGE_TYPE] = 0x09;
        frame[OFF_RESERVED] = 0x01;
        frame[OFF_RESERVED + 1] = 0x01;
        frame[OFF_ROUTING_TAG] = 0x01;
        frame[OFF_PAYLOAD_LENGTH + 3] = 0x05;

        assert_eq!(
            parse_header(&frame),
            Err(EnvelopeError::UnsupportedEnvelopeVersion { version: 0x02 })
        );

        frame[OFF_VERSION] = ENVELOPE_VERSION_V1;
        assert_eq!(
            parse_header(&frame),
            Err(EnvelopeError::UnknownMessageType { message_type: 0x09 })
        );

        frame[OFF_MESSAGE_TYPE] = MessageType::PrekeyRequest.as_byte();
        assert_eq!(
            parse_header(&frame),
            Err(EnvelopeError::ReservedNotZero { reserved: 0x0101 })
        );

        frame[OFF_RESERVED] = 0x00;
        frame[OFF_RESERVED + 1] = 0x00;
        assert_eq!(
            parse_header(&frame),
            Err(EnvelopeError::RoutingTagMustBeZero {
                message_type: MessageType::PrekeyRequest
            })
        );

        frame[OFF_ROUTING_TAG] = 0x00;
        assert_eq!(
            parse_header(&frame),
            Err(EnvelopeError::WrongPayloadLength {
                message_type: MessageType::PrekeyRequest,
                declared: 5,
                min: 0,
                max: 0,
            })
        );

        frame[OFF_PAYLOAD_LENGTH + 3] = 0x00;
        assert!(parse_header(&frame).is_ok(), "every field is now valid");
    }

    // ── Routing tag rules ───────────────────────────────────────────────────

    /// A prekey exchange happens before either side knows who the other is, so a
    /// tag there would leak the asker early — and an unchecked 16-byte field is a
    /// covert channel regardless.
    #[test]
    fn prekey_messages_must_not_carry_a_routing_tag() {
        for t in [MessageType::PrekeyRequest, MessageType::PrekeyResponse] {
            assert_eq!(
                EnvelopeHeader::new(t, tag(1), minimal_payload(t).len() as u32),
                Err(EnvelopeError::RoutingTagMustBeZero { message_type: t })
            );

            let mut frame = valid_frame(t);
            frame[OFF_ROUTING_TAG] = 0x01;
            assert_eq!(
                parse_header(&frame),
                Err(EnvelopeError::RoutingTagMustBeZero { message_type: t })
            );
        }
    }

    /// The mirror rule, so that all-zero has exactly one meaning everywhere:
    /// "no tag". Without it, a session message with a zero tag would be ambiguous
    /// with an untagged one. A real derivation hits all-zero with probability
    /// 2^-128, so the rule costs nothing.
    #[test]
    fn session_messages_must_carry_a_non_zero_routing_tag() {
        for t in [MessageType::SessionInit, MessageType::RatchetMessage] {
            assert_eq!(
                EnvelopeHeader::new(t, ABSENT_ROUTING_TAG, minimal_payload(t).len() as u32),
                Err(EnvelopeError::RoutingTagMustBeSet { message_type: t })
            );

            let mut frame = valid_frame(t);
            frame[OFF_ROUTING_TAG..OFF_ROUTING_TAG + ROUTING_TAG_LEN]
                .copy_from_slice(&ABSENT_ROUTING_TAG);
            assert_eq!(
                parse_header(&frame),
                Err(EnvelopeError::RoutingTagMustBeSet { message_type: t })
            );
        }
    }

    /// A single non-zero byte anywhere in the field is enough to make it present;
    /// the check must not look at the first byte only.
    #[test]
    fn a_routing_tag_is_present_if_any_byte_is_set() {
        let mut last_byte_only = ABSENT_ROUTING_TAG;
        last_byte_only[ROUTING_TAG_LEN - 1] = 0x01;

        assert!(
            EnvelopeHeader::new(MessageType::RatchetMessage, last_byte_only, 80).is_ok(),
            "a tag set only in its last byte is still a tag"
        );
        assert_eq!(
            EnvelopeHeader::new(MessageType::PrekeyRequest, last_byte_only, 0),
            Err(EnvelopeError::RoutingTagMustBeZero {
                message_type: MessageType::PrekeyRequest
            })
        );
    }

    // ── Payload length rules ────────────────────────────────────────────────

    #[test]
    fn exact_length_types_reject_every_other_length() {
        let cases = [
            (MessageType::PrekeyRequest, 0u32),
            (MessageType::PrekeyResponse, PREKEY_BUNDLE_V1_LEN as u32),
            (MessageType::SessionInit, INITIATOR_HANDSHAKE_V1_LEN as u32),
        ];
        for (t, exact) in cases {
            assert!(EnvelopeHeader::new(t, tag_for(t), exact).is_ok());
            for wrong in [exact.wrapping_sub(1), exact + 1] {
                if wrong == exact || wrong > MAX_PAYLOAD_LEN as u32 {
                    continue; // 0u32 - 1 wraps; not a length this type could see
                }
                assert_eq!(
                    EnvelopeHeader::new(t, tag_for(t), wrong),
                    Err(EnvelopeError::WrongPayloadLength {
                        message_type: t,
                        declared: wrong,
                        min: exact,
                        max: exact,
                    }),
                    "{t:?} must require exactly {exact} bytes"
                );
            }
        }
    }

    #[test]
    fn ratchet_payload_bounds_are_inclusive_at_both_ends() {
        let t = MessageType::RatchetMessage;
        let min = RATCHET_MIN_PAYLOAD_LEN as u32;
        let max = MAX_PAYLOAD_LEN as u32;

        assert!(
            EnvelopeHeader::new(t, tag(1), min).is_ok(),
            "an empty plaintext is valid"
        );
        assert!(
            EnvelopeHeader::new(t, tag(1), max).is_ok(),
            "the ceiling itself is valid"
        );

        assert_eq!(
            EnvelopeHeader::new(t, tag(1), min - 1),
            Err(EnvelopeError::WrongPayloadLength {
                message_type: t,
                declared: min - 1,
                min,
                max,
            }),
            "79 bytes cannot hold a header, a nonce and a tag"
        );
        assert_eq!(
            EnvelopeHeader::new(t, tag(1), max + 1),
            Err(EnvelopeError::PayloadTooLarge { declared: max + 1 })
        );
    }

    /// The ceiling is absolute and is applied before the per-type table, so the
    /// allocation guard cannot be reached through a type whose bounds happen to
    /// be wide.
    #[test]
    fn the_absolute_ceiling_outranks_the_per_type_rule() {
        for t in ALL_TYPES {
            let huge = MAX_PAYLOAD_LEN as u32 + 1;
            assert_eq!(
                EnvelopeHeader::new(t, tag_for(t), huge),
                Err(EnvelopeError::PayloadTooLarge { declared: huge }),
                "{t:?}: the size limit must not be reported as a type-shape problem"
            );
        }
    }

    /// The guard that matters for memory: a header declaring a gigabyte is
    /// refused with nothing but those 24 bytes in hand, so a reader never sizes a
    /// buffer from an unvalidated number.
    #[test]
    fn an_oversized_length_is_rejected_from_the_header_alone() {
        let mut header = EnvelopeHeader::new(MessageType::RatchetMessage, tag(1), 80)
            .unwrap()
            .to_bytes();
        let declared: u32 = 1 << 30; // 1 GiB
        header[OFF_PAYLOAD_LENGTH..OFF_PAYLOAD_LENGTH + 4].copy_from_slice(&declared.to_be_bytes());

        // Exactly 24 bytes are available — no payload exists anywhere.
        assert_eq!(header.len(), ENVELOPE_HEADER_LEN);
        assert_eq!(
            parse_header(&header),
            Err(EnvelopeError::PayloadTooLarge { declared }),
            "the limit must be enforced before a payload buffer could be allocated"
        );
    }

    #[test]
    fn encode_refuses_an_oversized_payload_without_building_a_header() {
        let payload = vec![0u8; MAX_PAYLOAD_LEN + 1];
        assert_eq!(
            encode(MessageType::RatchetMessage, tag(1), &payload),
            Err(EnvelopeError::PayloadTooLarge {
                declared: MAX_PAYLOAD_LEN as u32 + 1
            })
        );
    }

    #[test]
    fn encode_refuses_a_payload_the_type_does_not_accept() {
        assert_eq!(
            encode(MessageType::SessionInit, tag(1), &[0u8; 83]),
            Err(EnvelopeError::WrongPayloadLength {
                message_type: MessageType::SessionInit,
                declared: 83,
                min: 84,
                max: 84,
            })
        );
    }

    // ── Framing ─────────────────────────────────────────────────────────────

    #[test]
    fn a_header_shorter_than_twenty_four_bytes_is_truncated() {
        let frame = valid_frame(MessageType::RatchetMessage);
        for available in [0usize, 1, 23] {
            assert_eq!(
                parse_header(&frame[..available]),
                Err(EnvelopeError::TruncatedFrame {
                    needed: ENVELOPE_HEADER_LEN,
                    available,
                })
            );
        }
    }

    #[test]
    fn a_payload_shorter_than_declared_is_truncated() {
        let frame = valid_frame(MessageType::SessionInit);
        let full = frame.len();
        assert_eq!(
            parse_frame(&frame[..full - 1]),
            Err(EnvelopeError::TruncatedFrame {
                needed: full,
                available: full - 1,
            })
        );
        // The header alone still parses: truncation is a framing fact, not a
        // reason to call the header malformed.
        assert!(parse_header(&frame[..full - 1]).is_ok());
    }

    /// On a stream the bytes after a frame are the next frame. The parser must
    /// take exactly what the header declares and leave the rest.
    #[test]
    fn trailing_bytes_are_the_next_frame_not_an_error() {
        let first = valid_frame(MessageType::SessionInit);
        let second = valid_frame(MessageType::RatchetMessage);
        let mut stream = first.clone();
        stream.extend_from_slice(&second);

        let (h1, p1) = parse_frame(&stream).unwrap();
        assert_eq!(h1.message_type(), MessageType::SessionInit);
        assert_eq!(p1.len(), INITIATOR_HANDSHAKE_V1_LEN);

        let consumed = ENVELOPE_HEADER_LEN + p1.len();
        assert_eq!(consumed, first.len());

        let (h2, p2) = parse_frame(&stream[consumed..]).unwrap();
        assert_eq!(h2.message_type(), MessageType::RatchetMessage);
        assert_eq!(p2.len(), RATCHET_MIN_PAYLOAD_LEN);
    }

    #[test]
    fn an_empty_payload_frame_is_exactly_the_header() {
        let frame = encode(MessageType::PrekeyRequest, ABSENT_ROUTING_TAG, &[]).unwrap();
        assert_eq!(frame.len(), ENVELOPE_HEADER_LEN);
        let (header, payload) = parse_frame(&frame).unwrap();
        assert_eq!(header.payload_length(), 0);
        assert!(payload.is_empty());
    }

    // ── Type confusion ──────────────────────────────────────────────────────

    /// The honest limit of length checking: an 84-byte `SESSION_INIT` payload is
    /// also a legal `RATCHET_MESSAGE` length, because 84 ≥ 80. Flipping the type
    /// byte therefore produces a header this parser accepts.
    ///
    /// Length does not separate these two domains, and this module does not claim
    /// it does. What separates them is dispatching on `message_type` before
    /// touching the payload — and, once decision D4 is implemented, the type byte
    /// being inside the authenticated span, which turns the substitution from
    /// improbable into structurally impossible.
    #[test]
    fn length_alone_does_not_separate_session_init_from_a_ratchet_message() {
        let mut frame = valid_frame(MessageType::SessionInit);
        assert_eq!(
            frame.len(),
            ENVELOPE_HEADER_LEN + INITIATOR_HANDSHAKE_V1_LEN
        );
        // A compile-time fact, not a runtime one: the overlap is a property of
        // the constants, so it cannot be arranged away by a test fixture.
        const { assert!(INITIATOR_HANDSHAKE_V1_LEN >= RATCHET_MIN_PAYLOAD_LEN) };

        frame[OFF_MESSAGE_TYPE] = MessageType::RatchetMessage.as_byte();
        let received = parse_header(&frame).expect("84 bytes is a legal ratchet length");
        assert_eq!(received.message_type(), MessageType::RatchetMessage);
    }

    /// The reverse substitution is caught, because a minimal ratchet payload is
    /// 80 bytes and `SESSION_INIT` demands exactly 84.
    #[test]
    fn a_minimal_ratchet_message_is_not_a_legal_session_init() {
        let mut frame = valid_frame(MessageType::RatchetMessage);
        frame[OFF_MESSAGE_TYPE] = MessageType::SessionInit.as_byte();
        assert_eq!(
            parse_header(&frame),
            Err(EnvelopeError::WrongPayloadLength {
                message_type: MessageType::SessionInit,
                declared: RATCHET_MIN_PAYLOAD_LEN as u32,
                min: INITIATOR_HANDSHAKE_V1_LEN as u32,
                max: INITIATOR_HANDSHAKE_V1_LEN as u32,
            })
        );
    }

    // ── Error surface ───────────────────────────────────────────────────────

    #[test]
    fn errors_name_the_offending_value() {
        assert_eq!(
            EnvelopeError::UnsupportedEnvelopeVersion { version: 0x02 }.to_string(),
            "unsupported envelope version 0x02"
        );
        assert_eq!(
            EnvelopeError::UnknownMessageType { message_type: 0x09 }.to_string(),
            "unknown message type 0x09"
        );
        assert_eq!(
            EnvelopeError::ReservedNotZero { reserved: 0x0100 }.to_string(),
            "reserved field must be zero, got 0x0100"
        );
        assert_eq!(
            EnvelopeError::TruncatedFrame {
                needed: 24,
                available: 5
            }
            .to_string(),
            "truncated frame: needed 24 bytes, have 5"
        );
        assert_eq!(
            EnvelopeError::PayloadTooLarge { declared: 70_000 }.to_string(),
            "payload of 70000 bytes exceeds the 65536-byte limit"
        );
    }
}
