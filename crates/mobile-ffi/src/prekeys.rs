//! The stored prekey record (`PERSISTED_PREKEY_RECORD_V2`/`V3`), its flags,
//! one-time and signed prekeys, rotation, and the related store keys.

use super::*;

// The prekey record. The key moved to `v2` when `ARCIUM_X3DH_FORMAT_V1` changed
// the record's contents: a v1 record cannot be reinterpreted, so it simply stops
// being found. The key did not move again for `PERSISTED_PREKEY_RECORD_V3`
// (tracker R-6): every writer, the one-time-prekey replacement of option B and
// the conditional writes name this one record, and the V2 value it may hold is
// read in place. The V2 parser cannot be aimed at as a downgrade: a V2 record
// reads as published long ago, so its only effect is a rotation at the next
// round (`plan_rotation`).
pub(crate) const PREKEYS_KEY: &str = "prekeys/v2";

/// The [`handshake_identity`] of the handshake this device's responder
/// session with the peer came from (32 bytes), written in the transaction
/// that stores the session (`accept_first_message`) and replaced by the
/// next one. The network layer reads it to tell the contact's late
/// retransmission of that handshake, which it never refuses, from a restart
/// it can no longer answer, which it does (option B; `docs/NET-MESSAGING.md`
/// section 10, "Reset"). Not removed with the session: an older value only
/// names a handshake whose session is gone. Removed with the contact.
pub(crate) fn accepted_handshake_key(peer: &[u8; 32]) -> String {
    let hex: String = peer.iter().map(|b| format!("{b:02x}")).collect();
    format!("hsacc:v1/{hex}")
}

/// What makes two initiator handshakes the same for [`accepted_handshake_key`]:
/// they derive the same keys here. Not the bytes: the ephemeral key has
/// encodings that X25519 reads as the same point (the ignored top bit), and
/// points that differ from it by a low-order point, which every clamped
/// scalar, so every DH this device makes with it, cancels. A relay can put
/// any of them in place of the initiator's, and the session made from it is
/// the initiator's session (review of option B). So the ephemeral key
/// enters as its X25519 with a fixed public scalar, which is equal for
/// exactly those keys; the other fields enter as they are, since the
/// parser and the pinned card fix their bytes. A fresh handshake has a
/// fresh ephemeral key, so it never matches.
pub(crate) fn handshake_identity(handshake: &InitiatorHandshakeV1) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let ephemeral = StaticSecret::from([1u8; 32]).diffie_hellman(&handshake.ephemeral_pk);
    let opk = handshake.opk_id.map_or([0u8; 9], |id| {
        let mut b = [1u8; 9];
        b[1..].copy_from_slice(&id.to_be_bytes());
        b
    });
    Sha256::new()
        .chain_update(b"ARCIUM-ACCEPTED-HANDSHAKE-V1")
        .chain_update(handshake.identity_pk.as_bytes())
        .chain_update(ephemeral.as_bytes())
        .chain_update(handshake.spk_id)
        .chain_update(opk)
        .finalize()
        .into()
}

/// The side write recording `handshake` as the one the responder session
/// with `peer` about to be stored came from ([`accepted_handshake_key`]). It
/// replaces the record of an earlier session only if that is still the
/// record read here. A record that cannot be read (damaged, or tampered
/// with) is deleted first and the new one inserted: until then late copies
/// of the handshake are refused, as for a session an older build stored.
pub(crate) fn accepted_handshake_write(
    store: &mut EncryptedStore,
    peer: &[u8; 32],
    handshake: &InitiatorHandshakeV1,
) -> Result<SideWrite, CoreError> {
    let key = accepted_handshake_key(peer);
    let value = Zeroizing::new(handshake_identity(handshake).to_vec());
    let write = match store.get(&key) {
        Ok(old) => SideWrite::replace(key, Zeroizing::new(old), value),
        Err(StorageError::NotFound) => SideWrite::insert(key, value),
        Err(StorageError::Decryption) => {
            store.delete(&key)?;
            SideWrite::insert(key, value)
        }
        Err(e) => return Err(e.into()),
    };
    write.map_err(|_| CoreError::Storage {
        msg: "accepted-handshake key is reserved".into(),
    })
}

/// Marks a store whose one-time prekey was replaced once for option B
/// ([`ArciumCore::replace_prekey_once`]).
pub(crate) const PREKEY_RENEWED_KEY: &str = "prekeys/renewed-b0";

/// `PERSISTED_PREKEY_RECORD_V2`, exactly 138 bytes. Never transmitted. Read,
/// no longer written: the first write of the record replaces it with V3.
///
/// ```text
///   0   1  record_version = 0x01
///   1  32  signed_prekey_sk
///  33  64  spk_signature
///  97   1  flags   bit0 = opk_present, bits 1..7 = 0
///  98   8  opk_id (u64 big-endian)   ┐ zero when opk_present = 0
/// 106  32  opk_sk                    ┘
/// ```
pub(crate) const PREKEY_RECORD_V2_LEN: usize = 138;
pub(crate) const RECORD_VERSION: u8 = 0x01;
/// `PERSISTED_PREKEY_RECORD_V3`, exactly 186 bytes. Never transmitted. Its
/// first 138 bytes have the V2 layout.
///
/// ```text
///   0   1  record_version = 0x02
///   1  32  signed_prekey_sk        the current signed prekey
///  33  64  spk_signature           of the current one, over SIGNED_PREKEY_OBJECT_V1
///  97   1  flags   bit0 = opk_present, bit1 = prev_present, bit2 = born_present,
///                  bits 3..7 = 0
///  98   8  opk_id (u64 big-endian)   ┐ zero when opk_present = 0
/// 106  32  opk_sk                    ┘
/// 138   8  published_at (u64 big-endian): Unix seconds of this device's clock
///          when the relay first accepted a bundle naming the current signed
///          prekey; 0 = not yet, 1 = long ago (read from V2)
/// 146   8  born_opk_id (u64 big-endian): the one-time prekey held when the
///          current signed prekey was made; zero when born_present = 0
/// 154  32  prev_signed_prekey_sk   zero when prev_present = 0
/// ```
///
/// A previous signed prekey is held only together with the one-time prekey
/// the current one was made with (prev_present requires opk_present,
/// born_present and born_opk_id = opk_id); any other record is corrupt. It
/// keeps no signature: it is never published again.
pub(crate) const PREKEY_RECORD_V3_LEN: usize = 186;
pub(crate) const RECORD_VERSION_V3: u8 = 0x02;
/// Bit 1 of a V3 record's flags: a previous signed prekey is held.
pub(crate) const FLAG_PREV: u8 = 0b0000_0010;
/// Bit 2 of a V3 record's flags: `born_opk_id` is set.
pub(crate) const FLAG_BORN: u8 = 0b0000_0100;
/// `published_at` of a signed prekey the relay has not accepted yet. It
/// never ages (`plan_rotation`).
pub(crate) const PUBLISHED_NOT_YET: u64 = 0;
/// `published_at` of a signed prekey read from a V2 record: published at
/// an unknown time, so due for rotation at once.
pub(crate) const PUBLISHED_LONG_AGO: u64 = 1;
/// How long a signed prekey stays current after the relay first accepted
/// it, and how long it then stays the previous one (tracker R-6): 7 days,
/// the relay's envelope lifetime.
pub(crate) const SIGNED_PREKEY_PERIOD_SECS: u64 = 7 * 24 * 60 * 60;

/// Bit 0 of a `flags` byte: "a one-time prekey is present / was used".
pub(crate) const FLAG_OTP: u8 = 0b0000_0001;

/// Rejects any flag bit this version does not define. Unknown bits are refused
/// rather than masked off so a future version cannot be silently downgraded into
/// this one by a peer that sets them.
pub(crate) fn check_flags(flags: u8, what: &str) -> Result<bool, CoreError> {
    if flags & !FLAG_OTP != 0 {
        return Err(match what {
            "bundle" => CoreError::InvalidPrekeyBundle {
                msg: format!("unknown flag bits set: {flags:#04x}"),
            },
            _ => CoreError::InvalidHandshake {
                msg: format!("unknown flag bits set: {flags:#04x}"),
            },
        });
    }
    Ok(flags & FLAG_OTP != 0)
}

/// Checks the version/suite header shared by both wire structures.
pub(crate) fn check_version_and_suite(version: u8, suite: u8) -> Result<(), CoreError> {
    if version != PROTOCOL_VERSION || suite != CIPHER_SUITE {
        return Err(CoreError::UnsupportedProtocolVersion { version, suite });
    }
    Ok(())
}

/// A freshly generated one-time prekey and its opaque identifier.
///
/// The identifier is random rather than a counter on purpose: a bundle is public,
/// so a monotonic value would publish how many sessions this device has accepted.
fn new_one_time_prekey() -> (u64, StaticSecret) {
    let mut id = [0u8; 8];
    OsRng.fill_bytes(&mut id);
    (u64::from_be_bytes(id), StaticSecret::random_from_rng(OsRng))
}

/// Which signed prekey of a [`PrekeyRecord`] answers a handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Spk {
    /// The one the published bundle names.
    Current,
    /// The one before it, kept for one period after a rotation.
    Previous,
}

/// A parsed prekey record (`PERSISTED_PREKEY_RECORD_V3`, or V2 read in
/// place). Every secret in it wipes itself on drop.
pub(crate) struct PrekeyRecord {
    pub(crate) signed_prekey_sk: StaticSecret,
    pub(crate) signature: Signature,
    /// The currently published one-time prekey, if any.
    pub(crate) opk: Option<(u64, StaticSecret)>,
    /// When the relay first accepted a bundle naming the current signed
    /// prekey ([`PUBLISHED_NOT_YET`], [`PUBLISHED_LONG_AGO`]).
    pub(crate) published_at: u64,
    /// The one-time prekey id held when the current signed prekey was made.
    pub(crate) born_opk: Option<u64>,
    /// The signed prekey before the current one.
    pub(crate) prev: Option<StaticSecret>,
}

impl PrekeyRecord {
    /// A new record for `identity`: a new signed prekey and a new one-time
    /// prekey, not yet published, no previous signed prekey.
    pub(crate) fn new(identity: &Identity) -> Self {
        let (signed_prekey_sk, signature) = new_signed_prekey(identity);
        let opk = new_one_time_prekey();
        Self {
            signed_prekey_sk,
            signature,
            born_opk: Some(opk.0),
            opk: Some(opk),
            published_at: PUBLISHED_NOT_YET,
            prev: None,
        }
    }

    /// This record's current signed-prekey public key.
    pub(crate) fn signed_prekey_pk(&self) -> PublicKey {
        PublicKey::from(&self.signed_prekey_sk)
    }

    /// The id of the one-time prekey held, if any.
    pub(crate) fn opk_id(&self) -> Option<u64> {
        self.opk.as_ref().map(|(id, _)| *id)
    }

    /// The secret of the signed prekey `which`.
    pub(crate) fn signed_prekey(&self, which: Spk) -> Result<&StaticSecret, CoreError> {
        match which {
            Spk::Current => Ok(&self.signed_prekey_sk),
            Spk::Previous => self.prev.as_ref().ok_or(CoreError::StaleSignedPrekey),
        }
    }

    /// Publishes a new one-time prekey in place of the one held. The
    /// previous signed prekey goes with it: it answers only together with
    /// the one-time prekey it was published with (`check_answerable`).
    pub(crate) fn renew_one_time_prekey(&mut self) {
        self.opk = Some(new_one_time_prekey());
        self.prev = None;
    }
}

/// A new signed prekey for `identity` and its signature over
/// `SIGNED_PREKEY_OBJECT_V1`.
fn new_signed_prekey(identity: &Identity) -> (StaticSecret, Signature) {
    let signed_prekey_sk = StaticSecret::random_from_rng(OsRng);
    let object = signed_prekey_object_v1(
        &PublicKey::from(&identity.dh_key),
        &identity.signing_key.verifying_key(),
        &PublicKey::from(&signed_prekey_sk),
    );
    let signature = identity.signing_key.sign(&object);
    (signed_prekey_sk, signature)
}

/// Serializes `record` as `PERSISTED_PREKEY_RECORD_V3`.
pub(crate) fn pack_prekeys(record: &PrekeyRecord) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![0u8; PREKEY_RECORD_V3_LEN]);
    out[0] = RECORD_VERSION_V3;
    out[1..33].copy_from_slice(record.signed_prekey_sk.as_bytes());
    out[33..97].copy_from_slice(&record.signature.to_bytes());
    let mut flags = 0;
    if let Some((id, sk)) = &record.opk {
        flags |= FLAG_OTP;
        out[98..106].copy_from_slice(&id.to_be_bytes());
        out[106..138].copy_from_slice(sk.as_bytes());
    }
    out[138..146].copy_from_slice(&record.published_at.to_be_bytes());
    if let Some(id) = record.born_opk {
        flags |= FLAG_BORN;
        out[146..154].copy_from_slice(&id.to_be_bytes());
    }
    if let Some(sk) = &record.prev {
        flags |= FLAG_PREV;
        out[154..186].copy_from_slice(sk.as_bytes());
    }
    out[97] = flags;
    // Absent regions stay zero from the initial fill.
    out
}

/// Parses a prekey record: V3, or V2 read as published long ago, born with
/// its one-time prekey and without a previous signed prekey.
pub(crate) fn unpack_prekeys(bytes: &[u8]) -> Result<PrekeyRecord, CoreError> {
    let corrupt = |msg: String| CoreError::Storage { msg };
    let (len, known_flags) = match bytes.first() {
        Some(&RECORD_VERSION) => (PREKEY_RECORD_V2_LEN, FLAG_OTP),
        Some(&RECORD_VERSION_V3) => (PREKEY_RECORD_V3_LEN, FLAG_OTP | FLAG_PREV | FLAG_BORN),
        Some(other) if [PREKEY_RECORD_V2_LEN, PREKEY_RECORD_V3_LEN].contains(&bytes.len()) => {
            return Err(corrupt(format!("unknown prekey record version {other:#04x}")));
        }
        _ => {
            return Err(corrupt(format!(
                "corrupt prekey record: {} bytes, expected {PREKEY_RECORD_V3_LEN}",
                bytes.len()
            )));
        }
    };
    if bytes.len() != len {
        return Err(corrupt(format!(
            "corrupt prekey record: {} bytes, expected {len} for version {:#04x}",
            bytes.len(),
            bytes[0]
        )));
    }
    let zero = |range: std::ops::Range<usize>, what: &str| {
        if bytes[range].iter().any(|b| *b != 0) {
            return Err(corrupt(format!(
                "corrupt prekey record: {what} absent but its bytes are not zero"
            )));
        }
        Ok(())
    };
    let u64_at = |at: usize| u64::from_be_bytes(bytes[at..at + 8].try_into().expect("checked length"));
    let secret_at = |at: usize| {
        let sk: Zeroizing<[u8; 32]> =
            Zeroizing::new(bytes[at..at + 32].try_into().expect("checked length"));
        StaticSecret::from(*sk)
    };

    let flags = bytes[97];
    if flags & !known_flags != 0 {
        return Err(corrupt(format!(
            "corrupt prekey record: unknown flag bits {flags:#04x}"
        )));
    }
    let sig_bytes: [u8; 64] = bytes[33..97].try_into().expect("checked length");
    let opk = if flags & FLAG_OTP != 0 {
        Some((u64_at(98), secret_at(106)))
    } else {
        zero(98..138, "one-time prekey")?;
        None
    };
    let opk_id = opk.as_ref().map(|(id, _)| *id);
    let (published_at, born_opk, prev) = if len == PREKEY_RECORD_V2_LEN {
        (PUBLISHED_LONG_AGO, opk_id, None)
    } else {
        let born_opk = if flags & FLAG_BORN != 0 {
            Some(u64_at(146))
        } else {
            zero(146..154, "birth one-time prekey")?;
            None
        };
        let prev = if flags & FLAG_PREV != 0 {
            if opk_id.is_none() || born_opk != opk_id {
                return Err(corrupt(
                    "corrupt prekey record: a previous signed prekey without the one-time prekey it was published with".into(),
                ));
            }
            Some(secret_at(154))
        } else {
            zero(154..186, "previous signed prekey")?;
            None
        };
        (u64_at(138), born_opk, prev)
    };
    Ok(PrekeyRecord {
        signed_prekey_sk: secret_at(1),
        signature: Signature::from_bytes(&sig_bytes),
        opk,
        published_at,
        born_opk,
        prev,
    })
}

/// A rotation of the signed prekey that is due ([`plan_rotation`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Rotation {
    /// Whether the current signed prekey becomes the previous one.
    pub(crate) keep_previous: bool,
}

/// Whether the signed prekey of `record` is due for rotation at `now`
/// (Unix seconds of this device's clock), and how (tracker R-6):
/// - (E) the one-time prekey changed since the current signed prekey was
///   made: rotate, and keep no previous key. Every bundle this device
///   published pairs a signed prekey with the one-time prekey held then,
///   and a handshake is answered only with the one-time prekey it names
///   (X-6), so no honest handshake can be answered under either key any
///   more.
/// - (T) the relay accepted the current one `SIGNED_PREKEY_PERIOD_SECS` or
///   more ago, in either direction of the clock: rotate, and keep the
///   current one as the previous one if the one-time prekey it was
///   published with is held. A key never accepted does not age.
pub(crate) fn plan_rotation(record: &PrekeyRecord, now: u64) -> Option<Rotation> {
    if record.opk_id() != record.born_opk {
        return Some(Rotation { keep_previous: false });
    }
    if record.published_at != PUBLISHED_NOT_YET
        && now.abs_diff(record.published_at) >= SIGNED_PREKEY_PERIOD_SECS
    {
        return Some(Rotation {
            keep_previous: record.opk.is_some(),
        });
    }
    None
}

/// Applies `rotation` to `record`: a new signed prekey made for
/// `identity`, not yet published, born with the one-time prekey held. The
/// old previous key is dropped (and wiped), and so is the old current one
/// unless it is kept as the previous one.
pub(crate) fn rotate_signed_prekey(record: &mut PrekeyRecord, identity: &Identity, rotation: Rotation) {
    let (signed_prekey_sk, signature) = new_signed_prekey(identity);
    let old = std::mem::replace(&mut record.signed_prekey_sk, signed_prekey_sk);
    record.signature = signature;
    record.prev = rotation.keep_previous.then_some(old);
    record.born_opk = record.opk_id();
    record.published_at = PUBLISHED_NOT_YET;
}
