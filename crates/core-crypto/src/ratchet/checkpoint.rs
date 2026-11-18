//! Versioned byte encoding of the complete `DoubleRatchet` state
//! (`RATCHET_STATE_V2`; `RATCHET_STATE_V1` is still read), and an
//! independent in-memory copy for staging.
//!
//! This module only serialises and reconstructs state. It does not change key
//! evolution, KDFs, AEAD, nonces or the message header, and nothing in the live
//! message path calls it.
//!
//! What a checkpoint is *not*: it is not encrypted or authenticated here.
//! Confidentiality, integrity and authenticity of a stored record come only
//! from the authenticated encrypted store it is kept in. Restoring a record
//! says nothing about whether it is the latest state that existed: an older
//! record decodes exactly as well as a newer one, so validation here is no
//! protection against a rolled-back database.
//!
//! # Internal interface
//!
//! [`DoubleRatchet::to_checkpoint`], [`DoubleRatchet::from_checkpoint`] and
//! [`DoubleRatchet::staged_copy`] are public only because `core-protocol`'s
//! durable sessions call them across the crate boundary. They are not a
//! general-purpose API. Rust visibility cannot restrict them to that caller:
//! any code holding a `DoubleRatchet`, or a record and the means to read it,
//! can make a second instance, and two instances of one state produce
//! competing ciphertexts under the same message key and counter. The durable
//! session enforces its transition rules only for state it owns; it cannot
//! prevent misuse of ratchets held elsewhere.
//!
//! # Layout (all integers big-endian)
//!
//! | offset | size | field                                              |
//! |-------:|-----:|----------------------------------------------------|
//! |      0 |    1 | version, `2` (`1` is still read)                   |
//! |      1 |    1 | presence flags: bit0 `dhr`, bit1 `cks`, bit2 `ckr` |
//! |      2 |   32 | `dhs` secret bytes                                 |
//! |     34 |   32 | `dhr` (all zero when absent)                       |
//! |     66 |   32 | `rk`                                               |
//! |     98 |   32 | `cks` (all zero when absent)                       |
//! |    130 |   32 | `ckr` (all zero when absent)                       |
//! |    162 |    4 | `ns`                                               |
//! |    166 |    4 | `nr`                                               |
//! |    170 |    4 | `pn`                                               |
//! |    174 |    4 | `max_skipped`, must equal [`MAX_SKIPPED_KEYS`]     |
//! |    178 |    4 | skipped-key count, at most [`MAX_SKIPPED_KEYS`]    |
//! |    182 | 68·n | skipped entries in `IndexMap` order: dh(32) n(4) mk(32) |
//! | 182+68·n |  1 | V2 only: earlier receiving chains `h`, at most [`MAX_PREV_CHAINS`] |
//! | 183+68·n | 36·h | V2 only: those chains, oldest first: dh(32) end(4) |
//!
//! A V2 record's length must be exactly `183 + 68·count + 36·h`. A V1 record
//! (written before tracker R-21's chain history) ends after the skipped
//! entries, at exactly `182 + 68·count`, and is read as a state that
//! remembers no earlier chain. Records are always written as V2.
//!
//! # Accepted states
//!
//! Decoding checks structural rules that every state produced by this ratchet
//! satisfies, and rejects a record that breaks any of them rather than
//! repairing it. The rules are necessary, not sufficient: a record that passes
//! them (for example, with arbitrary key bytes) is not thereby shown to have
//! been reached by legitimate ratchet evolution. That assurance, such as it
//! is, comes from the authenticated store.
//!
//! - `(dhr, cks, ckr)` presence is one of `(-, -, -)` (`init_bob`, before the
//!   first message), `(+, +, -)` (`init_alice`, before the first reply) or
//!   `(+, +, +)` (after any DH ratchet step). `DoubleRatchet::decrypt` rolls back
//!   on failure, so no other combination survives a call.
//! - Without `ckr`, `nr == 0`, `pn == 0` and there are no skipped keys:
//!   `pn` is only set, and keys are only skipped, once a receiving chain exists.
//! - In `(-, -, -)`, `ns == 0`: `encrypt` fails before advancing.
//! - At most [`MAX_SKIPPED_KEYS`] skipped keys, no duplicate `(dh, n)`.
//! - At most [`MAX_PREV_CHAINS`] earlier chains, none without a receiving
//!   chain, no peer key twice and none equal to `dhr`.
//! - `ns < u32::MAX` and `nr <= `[`MAX_RESUMABLE_NR`]. The ratchet increments
//!   both without an overflow check, which panics in a debug build and wraps
//!   to `0` in a release build:
//!   - `encrypt` adds one to `ns`, so `ns == u32::MAX` cannot send again.
//!   - `decrypt` first skips `nr` forward to the header's `n` (allowed while
//!     `n <= nr + MAX_SKIP`; `decrypt_far` allows more, but never past
//!     `MAX_RESUMABLE_NR`) and then adds one. A message with
//!     `n == u32::MAX` therefore overflows `nr` whenever
//!     `nr >= u32::MAX - MAX_SKIP` — before the message is authenticated, so
//!     a forged header is enough in a debug build, and in a release build an
//!     authentic one leaves a wrapped `nr` behind. Rejecting only
//!     `nr == u32::MAX` misses this. At `nr == MAX_RESUMABLE_NR` such a
//!     message fails the skip limit instead, and no accepted message can take
//!     `nr` past `u32::MAX`.
//!
//!   States beyond these bounds are refused on encode and decode
//!   (`CounterExhausted`). A receive that would move `nr` past
//!   [`MAX_RESUMABLE_NR`] still succeeds inside the ratchet; it is the
//!   checkpoint of the resulting state that is refused, so a durable session
//!   rejects that transition rather than persisting it. The limits are
//!   reachable only after about `2^32` messages in one chain. `pn` is only
//!   copied into headers and compared, never incremented, and has no limit.
//!   These checks cover checkpointed state only; the ratchet's own
//!   arithmetic is unchanged.
//!
//! `ckr` present with `dhr` absent is among the rejected combinations; the
//! ratchet's `skip_message_keys` relies on that never happening.

use indexmap::IndexMap;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use super::{DoubleRatchet, Zeroizing, MAX_PREV_CHAINS, MAX_SKIP};

/// Current ratchet checkpoint format version (`RATCHET_STATE_V2`).
pub const RATCHET_CHECKPOINT_VERSION: u8 = 2;
/// The format before the chain history (tracker R-21), still read.
const RATCHET_CHECKPOINT_V1: u8 = 1;

/// Skipped-key capacity every ratchet is created with (`max_skipped` in
/// `init_alice` / `init_bob`). A record carrying any other value is rejected.
pub const MAX_SKIPPED_KEYS: usize = 2000;

const FLAG_DHR: u8 = 0b001;
const FLAG_CKS: u8 = 0b010;
const FLAG_CKR: u8 = 0b100;
const KNOWN_FLAGS: u8 = FLAG_DHR | FLAG_CKS | FLAG_CKR;

const FIXED_LEN: usize = 182;
const ENTRY_LEN: usize = 32 + 4 + 32;
const CHAIN_LEN: usize = 32 + 4;

/// Largest receive counter a checkpointed state may hold. From here, no
/// message passes both the skip limit and the final increment of `nr`
/// without overflow; one more and a header with `n == u32::MAX` would.
pub const MAX_RESUMABLE_NR: u32 = u32::MAX - MAX_SKIP - 1;

/// Largest valid ratchet checkpoint record, in bytes.
pub const RATCHET_CHECKPOINT_MAX_LEN: usize =
    FIXED_LEN + ENTRY_LEN * MAX_SKIPPED_KEYS + 1 + CHAIN_LEN * MAX_PREV_CHAINS;

/// Why a ratchet checkpoint could not be written or read. No variant carries
/// key material.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CheckpointError {
    #[error("ratchet checkpoint is {actual} bytes; at least {FIXED_LEN} required")]
    Truncated { actual: usize },
    #[error("ratchet checkpoint is {actual} bytes; limit is {RATCHET_CHECKPOINT_MAX_LEN}")]
    Oversized { actual: usize },
    #[error("unsupported ratchet checkpoint version {0}")]
    UnsupportedVersion(u8),
    #[error("ratchet checkpoint length {actual} does not match {expected} implied by its skipped-key count")]
    LengthMismatch { expected: usize, actual: usize },
    #[error("ratchet checkpoint has unknown presence flags {0:#04x}")]
    UnknownFlags(u8),
    #[error("ratchet checkpoint max_skipped {0} does not match this implementation")]
    UnexpectedCapacity(u32),
    #[error("ratchet checkpoint holds {0} skipped keys; limit is {MAX_SKIPPED_KEYS}")]
    TooManySkippedKeys(u32),
    #[error("ratchet checkpoint lists the same skipped key twice")]
    DuplicateSkippedKey,
    #[error("ratchet checkpoint holds {0} earlier chains; limit is {MAX_PREV_CHAINS}")]
    TooManyChains(u8),
    #[error("ratchet checkpoint lists an earlier chain twice, or the current one")]
    DuplicateChain,
    #[error("ratchet checkpoint field {0} is marked absent but not zero")]
    AbsentFieldNotZero(&'static str),
    #[error("ratchet state violates a structural rule: {0}")]
    InconsistentState(&'static str),
    #[error("ratchet counter {0} is exhausted; the state cannot be resumed safely")]
    CounterExhausted(&'static str),
}

/// Checks the cross-field rules listed in the module docs. Shared by encode
/// and decode so neither side can accept what the other refuses.
fn check_state(
    has_dhr: bool,
    has_cks: bool,
    has_ckr: bool,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: usize,
) -> Result<(), CheckpointError> {
    match (has_dhr, has_cks, has_ckr) {
        (false, false, false) => {
            if ns != 0 {
                return Err(CheckpointError::InconsistentState(
                    "messages counted as sent before a sending chain exists",
                ));
            }
        }
        (true, true, false) | (true, true, true) => {}
        _ => {
            return Err(CheckpointError::InconsistentState(
                "impossible combination of peer key and chain keys",
            ))
        }
    }
    if !has_ckr && (nr != 0 || pn != 0 || skipped != 0) {
        return Err(CheckpointError::InconsistentState(
            "receive-side counters or skipped keys without a receiving chain",
        ));
    }
    if skipped > MAX_SKIPPED_KEYS {
        return Err(CheckpointError::TooManySkippedKeys(
            u32::try_from(skipped).unwrap_or(u32::MAX),
        ));
    }
    if ns == u32::MAX {
        return Err(CheckpointError::CounterExhausted("ns"));
    }
    if nr > MAX_RESUMABLE_NR {
        return Err(CheckpointError::CounterExhausted("nr"));
    }
    Ok(())
}

impl DoubleRatchet {
    /// Encodes the complete ratchet state as a `RATCHET_STATE_V2` record.
    ///
    /// Internal interface for `core-protocol`'s durable sessions; see the
    /// module documentation for what calling it outside them allows.
    ///
    /// The returned buffer holds secret keys and is wiped when dropped. It is
    /// allocated at its final size, so no partial copies are left behind by
    /// reallocation. A state that [`from_checkpoint`](Self::from_checkpoint)
    /// would refuse is refused here too, so nothing unreadable is produced.
    pub fn to_checkpoint(&self) -> Result<Zeroizing<Vec<u8>>, CheckpointError> {
        if self.max_skipped != MAX_SKIPPED_KEYS {
            return Err(CheckpointError::UnexpectedCapacity(
                u32::try_from(self.max_skipped).unwrap_or(u32::MAX),
            ));
        }
        check_state(
            self.dhr.is_some(),
            self.cks.is_some(),
            self.ckr.is_some(),
            self.ns,
            self.nr,
            self.pn,
            self.skipped.len(),
        )?;
        check_chains(
            &self.prev_chains,
            self.ckr.is_some(),
            self.dhr.as_ref().map(|pk| *pk.as_bytes()),
        )?;

        let len = FIXED_LEN + ENTRY_LEN * self.skipped.len() + 1 + CHAIN_LEN * self.prev_chains.len();
        let mut out = Zeroizing::new(Vec::with_capacity(len));
        let mut flags = 0u8;
        if self.dhr.is_some() {
            flags |= FLAG_DHR;
        }
        if self.cks.is_some() {
            flags |= FLAG_CKS;
        }
        if self.ckr.is_some() {
            flags |= FLAG_CKR;
        }
        out.push(RATCHET_CHECKPOINT_VERSION);
        out.push(flags);
        out.extend_from_slice(self.dhs.as_bytes());
        out.extend_from_slice(self.dhr.as_ref().map_or(&[0u8; 32], |pk| pk.as_bytes()));
        out.extend_from_slice(&*self.rk);
        out.extend_from_slice(self.cks.as_ref().map_or(&[0u8; 32], |k| &**k));
        out.extend_from_slice(self.ckr.as_ref().map_or(&[0u8; 32], |k| &**k));
        out.extend_from_slice(&self.ns.to_be_bytes());
        out.extend_from_slice(&self.nr.to_be_bytes());
        out.extend_from_slice(&self.pn.to_be_bytes());
        // Both fit in u32: checked against MAX_SKIPPED_KEYS above.
        out.extend_from_slice(&(self.max_skipped as u32).to_be_bytes());
        out.extend_from_slice(&(self.skipped.len() as u32).to_be_bytes());
        for ((dh, n), mk) in &self.skipped {
            out.extend_from_slice(dh);
            out.extend_from_slice(&n.to_be_bytes());
            out.extend_from_slice(&**mk);
        }
        // Fits in u8: checked against MAX_PREV_CHAINS above.
        out.push(self.prev_chains.len() as u8);
        for (dh, end) in &self.prev_chains {
            out.extend_from_slice(dh);
            out.extend_from_slice(&end.to_be_bytes());
        }
        debug_assert_eq!(out.len(), len);
        debug_assert_eq!(out.capacity(), len);
        Ok(out)
    }

    /// Rebuilds a ratchet from a `RATCHET_STATE_V2` record, or from a
    /// `RATCHET_STATE_V1` one, which remembers no earlier chain.
    ///
    /// Internal interface for `core-protocol`'s durable sessions; see the
    /// module documentation for what calling it outside them allows.
    ///
    /// Every field is taken as stored: nothing is regenerated, defaulted or
    /// corrected, and a record that fails any check is rejected as a whole.
    /// Skipped keys come back in the stored order, so eviction continues
    /// exactly where it left off.
    ///
    /// Success means the bytes pass the structural rules in the module docs.
    /// It does not mean the state was reached legitimately, is current,
    /// belongs to the session the caller expects, or was not rolled back.
    pub fn from_checkpoint(record: &[u8]) -> Result<Self, CheckpointError> {
        if record.len() > RATCHET_CHECKPOINT_MAX_LEN {
            return Err(CheckpointError::Oversized {
                actual: record.len(),
            });
        }
        if record.len() < FIXED_LEN {
            return Err(CheckpointError::Truncated {
                actual: record.len(),
            });
        }
        let v2 = match record[0] {
            RATCHET_CHECKPOINT_VERSION => true,
            RATCHET_CHECKPOINT_V1 => false,
            other => return Err(CheckpointError::UnsupportedVersion(other)),
        };
        let flags = record[1];
        if flags & !KNOWN_FLAGS != 0 {
            return Err(CheckpointError::UnknownFlags(flags));
        }
        let max_skipped = read_u32(record, 174);
        if max_skipped as usize != MAX_SKIPPED_KEYS {
            return Err(CheckpointError::UnexpectedCapacity(max_skipped));
        }
        let count = read_u32(record, 178);
        if count as usize > MAX_SKIPPED_KEYS {
            return Err(CheckpointError::TooManySkippedKeys(count));
        }
        let entries_end = FIXED_LEN + ENTRY_LEN * count as usize;
        let chains = if v2 {
            match record.get(entries_end) {
                Some(&h) if h as usize > MAX_PREV_CHAINS => {
                    return Err(CheckpointError::TooManyChains(h))
                }
                Some(&h) => h as usize,
                None => {
                    return Err(CheckpointError::LengthMismatch {
                        expected: entries_end + 1,
                        actual: record.len(),
                    })
                }
            }
        } else {
            0
        };
        let expected = if v2 { entries_end + 1 + CHAIN_LEN * chains } else { entries_end };
        if record.len() != expected {
            return Err(CheckpointError::LengthMismatch {
                expected,
                actual: record.len(),
            });
        }

        let has_dhr = flags & FLAG_DHR != 0;
        let has_cks = flags & FLAG_CKS != 0;
        let has_ckr = flags & FLAG_CKR != 0;
        let (ns, nr, pn) = (
            read_u32(record, 162),
            read_u32(record, 166),
            read_u32(record, 170),
        );
        check_state(has_dhr, has_cks, has_ckr, ns, nr, pn, count as usize)?;
        let prev_chains: Vec<([u8; 32], u32)> = if v2 {
            // As for the entries below: the exact-length check leaves no
            // partial chain record.
            let (records, partial) = record[entries_end + 1..].as_chunks::<CHAIN_LEN>();
            if !partial.is_empty() {
                return Err(CheckpointError::LengthMismatch {
                    expected,
                    actual: record.len(),
                });
            }
            records
                .iter()
                .map(|c| (read_32(c, 0), read_u32(c, 32)))
                .collect()
        } else {
            Vec::new()
        };
        check_chains(&prev_chains, has_ckr, has_dhr.then(|| read_32(record, 34)))?;
        for (present, off, name) in [
            (has_dhr, 34, "dhr"),
            (has_cks, 98, "cks"),
            (has_ckr, 130, "ckr"),
        ] {
            if !present && record[off..off + 32].iter().any(|&b| b != 0) {
                return Err(CheckpointError::AbsentFieldNotZero(name));
            }
        }

        // All structural checks are done; from here on secrets are copied into
        // the ratchet, whose fields wipe themselves if it is dropped because a
        // skipped-key check fails.
        let dhs_bytes = Zeroizing::new(read_32(record, 2));
        let dhs = StaticSecret::from(*dhs_bytes);
        let mut ratchet = DoubleRatchet {
            dhs,
            dhr: has_dhr.then(|| PublicKey::from(read_32(record, 34))),
            rk: Zeroizing::new(read_32(record, 66)),
            cks: has_cks.then(|| Zeroizing::new(read_32(record, 98))),
            ckr: has_ckr.then(|| Zeroizing::new(read_32(record, 130))),
            ns,
            nr,
            pn,
            // Room for every key, not just the `count` stored: a buffer that
            // grows later moves the keys and frees the old one unwiped (H-6).
            skipped: IndexMap::with_capacity(MAX_SKIPPED_KEYS),
            max_skipped: MAX_SKIPPED_KEYS,
            prev_chains,
        };
        // The exact-length check above leaves no partial entry; refuse one
        // anyway rather than drop it silently.
        let (entries, partial) = record[FIXED_LEN..entries_end].as_chunks::<ENTRY_LEN>();
        if !partial.is_empty() {
            return Err(CheckpointError::LengthMismatch {
                expected,
                actual: record.len(),
            });
        }
        for entry in entries {
            let dh = read_32(entry, 0);
            let n = read_u32(entry, 32);
            if ratchet.skipped.contains_key(&(dh, n)) {
                return Err(CheckpointError::DuplicateSkippedKey);
            }
            ratchet
                .skipped
                .insert((dh, n), Zeroizing::new(read_32(entry, 36)));
        }
        Ok(ratchet)
    }

    /// Returns an independent copy of the full ratchet state, for preparing a
    /// transition without touching the original.
    ///
    /// Internal interface for `core-protocol`'s durable sessions; see the
    /// module documentation for what calling it outside them allows.
    ///
    /// The copy derives the same keys as the original. Using both to send
    /// produces two messages under one message key and counter, so at most one
    /// of the two may ever be used for output that leaves the process; the
    /// other must be dropped. The copy wipes its secrets when dropped, like
    /// any `DoubleRatchet`.
    pub fn staged_copy(&self) -> DoubleRatchet {
        DoubleRatchet {
            dhs: self.dhs.clone(),
            dhr: self.dhr,
            rk: self.rk.clone(),
            cks: self.cks.clone(),
            ckr: self.ckr.clone(),
            ns: self.ns,
            nr: self.nr,
            pn: self.pn,
            skipped: super::copy_skipped(&self.skipped),
            max_skipped: self.max_skipped,
            prev_chains: self.prev_chains.clone(),
        }
    }
}

/// The earlier-chain rules of the module docs: at most [`MAX_PREV_CHAINS`],
/// none without a receiving chain, no peer key twice and none equal to the
/// current one (`dhr`). Shared by encode and decode, as `check_state` is.
fn check_chains(
    chains: &[([u8; 32], u32)],
    has_ckr: bool,
    dhr: Option<[u8; 32]>,
) -> Result<(), CheckpointError> {
    if chains.len() > MAX_PREV_CHAINS {
        return Err(CheckpointError::TooManyChains(u8::try_from(chains.len()).unwrap_or(u8::MAX)));
    }
    if !has_ckr && !chains.is_empty() {
        return Err(CheckpointError::InconsistentState(
            "earlier receiving chains without a receiving chain",
        ));
    }
    for (i, (dh, _)) in chains.iter().enumerate() {
        if Some(*dh) == dhr || chains[..i].iter().any(|(other, _)| other == dh) {
            return Err(CheckpointError::DuplicateChain);
        }
    }
    Ok(())
}

fn read_u32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(b[off..off + 4].try_into().expect("4-byte slice"))
}

fn read_32(b: &[u8], off: usize) -> [u8; 32] {
    b[off..off + 32].try_into().expect("32-byte slice")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratchet::{Header, RatchetError, HEADER_SIZE, NONCE_SIZE};
    use rand_core::OsRng;

    const AD: &[u8] = b"checkpoint-test-ad";

    fn pair() -> (DoubleRatchet, DoubleRatchet) {
        let root = [9u8; 32];
        let bob_spk = StaticSecret::random_from_rng(OsRng);
        let alice = DoubleRatchet::init_alice(&root, PublicKey::from(&bob_spk));
        let bob = DoubleRatchet::init_bob(&root, bob_spk);
        (alice, bob)
    }

    /// `DoubleRatchet` deliberately has no `Debug`, so `unwrap_err` is unavailable.
    fn decode_err(record: &[u8]) -> CheckpointError {
        match DoubleRatchet::from_checkpoint(record) {
            Ok(_) => panic!("record was accepted"),
            Err(e) => e,
        }
    }

    fn restore(r: &DoubleRatchet) -> DoubleRatchet {
        let rec = r.to_checkpoint().expect("encode");
        DoubleRatchet::from_checkpoint(&rec).expect("decode")
    }

    /// Field-by-field equality, including skipped-key order.
    fn assert_same_state(a: &DoubleRatchet, b: &DoubleRatchet) {
        assert_eq!(a.dhs.as_bytes(), b.dhs.as_bytes());
        assert_eq!(a.dhr.map(|k| k.to_bytes()), b.dhr.map(|k| k.to_bytes()));
        assert_eq!(a.rk, b.rk);
        assert_eq!(a.cks, b.cks);
        assert_eq!(a.ckr, b.ckr);
        assert_eq!((a.ns, a.nr, a.pn), (b.ns, b.nr, b.pn));
        assert_eq!(a.max_skipped, b.max_skipped);
        let ea: Vec<_> = a.skipped.iter().collect();
        let eb: Vec<_> = b.skipped.iter().collect();
        assert_eq!(ea, eb, "skipped keys and their order must match");
        assert_eq!(a.prev_chains, b.prev_chains, "earlier chains and their order must match");
    }

    /// The length of the V2 record of `r`.
    fn v2_len(r: &DoubleRatchet) -> usize {
        FIXED_LEN + ENTRY_LEN * r.skipped.len() + 1 + CHAIN_LEN * r.prev_chains.len()
    }

    fn with_skipped() -> (DoubleRatchet, DoubleRatchet, Vec<(Header, Vec<u8>)>) {
        let (mut alice, mut bob) = pair();
        let (h, c) = alice.encrypt(b"first", AD).unwrap();
        bob.decrypt(&h, &c, AD).unwrap();
        let (h, c) = bob.encrypt(b"reply", AD).unwrap();
        alice.decrypt(&h, &c, AD).unwrap();
        let held: Vec<_> = (0..4).map(|i| alice.encrypt(&[i], AD).unwrap()).collect();
        let (h, c) = alice.encrypt(b"latest", AD).unwrap();
        assert_eq!(*bob.decrypt(&h, &c, AD).unwrap(), b"latest");
        assert_eq!(bob.skipped.len(), 4);
        (alice, bob, held)
    }

    #[test]
    fn constructors_use_the_encoded_capacity() {
        let (alice, bob) = pair();
        assert_eq!(alice.max_skipped, MAX_SKIPPED_KEYS);
        assert_eq!(bob.max_skipped, MAX_SKIPPED_KEYS);
        // 182 + 68 * 2000 skipped keys + 1 + 36 * 4 earlier chains.
        assert_eq!(RATCHET_CHECKPOINT_MAX_LEN, 136_327);
    }

    #[test]
    fn round_trip_is_byte_exact_in_every_reachable_shape() {
        let (alice, bob) = pair();
        let (a2, b2, _) = with_skipped();
        for r in [&alice, &bob, &a2, &b2] {
            let rec = r.to_checkpoint().unwrap();
            assert_eq!(rec[0], 2);
            assert_eq!(rec.len(), v2_len(r));
            let back = DoubleRatchet::from_checkpoint(&rec).unwrap();
            assert_same_state(r, &back);
            assert_eq!(*back.to_checkpoint().unwrap(), *rec);
        }
    }

    #[test]
    fn restored_sides_continue_the_conversation_in_both_directions() {
        let (alice, bob, held) = with_skipped();
        let (mut alice, mut bob) = (restore(&alice), restore(&bob));

        // Late messages from before the checkpoint use the restored skipped keys.
        for (i, (h, c)) in held.iter().enumerate().rev() {
            assert_eq!(*bob.decrypt(h, c, AD).unwrap(), [i as u8]);
        }
        assert!(bob.skipped.is_empty());

        // Several DH steps after restoring, each side restored again midway.
        for round in 0u8..3 {
            let (h, c) = bob.encrypt(&[round], AD).unwrap();
            assert_eq!(*alice.decrypt(&h, &c, AD).unwrap(), [round]);
            alice = restore(&alice);
            let (h, c) = alice.encrypt(&[round, 1], AD).unwrap();
            assert_eq!(*bob.decrypt(&h, &c, AD).unwrap(), [round, 1]);
            bob = restore(&bob);
        }
    }

    #[test]
    fn responder_restored_before_first_message_still_receives_it() {
        let (mut alice, bob) = pair();
        let mut bob = restore(&bob);
        let (h, c) = alice.encrypt(b"hi", AD).unwrap();
        assert_eq!(*bob.decrypt(&h, &c, AD).unwrap(), b"hi");
    }

    #[test]
    fn restored_state_emits_the_unchanged_wire_format() {
        let (alice, mut bob) = pair();
        let mut alice = restore(&alice);
        let (h, c) = alice.encrypt(b"abc", AD).unwrap();
        assert_eq!(h.to_bytes().len(), HEADER_SIZE);
        assert_eq!(c.len(), NONCE_SIZE + 3 + 16);
        assert_eq!(h.n, 0);
        assert_eq!(h.dh, alice.our_dh_public().to_bytes());
        assert_eq!(*bob.decrypt(&h, &c, AD).unwrap(), b"abc");
    }

    #[test]
    fn restored_skipped_keys_evict_in_the_original_order() {
        let (_, mut original, _) = with_skipped();
        // Fill to capacity so the next insert evicts.
        let dh = [0x55u8; 32];
        for n in 0..(MAX_SKIPPED_KEYS - original.skipped.len()) as u32 {
            original
                .skipped
                .insert((dh, n), Zeroizing::new([n as u8; 32]));
        }
        let mut restored = restore(&original);
        assert_same_state(&original, &restored);
        for r in [&mut original, &mut restored] {
            r.skipped.insert(([0x66; 32], 0), Zeroizing::new([1; 32]));
            r.skipped.insert(([0x66; 32], 1), Zeroizing::new([2; 32]));
            r.trim_skipped();
        }
        assert_same_state(&original, &restored);
    }

    #[test]
    fn capacity_is_the_limit_for_encoding_and_decoding() {
        let (_, mut bob, _) = with_skipped();
        let dh = [0x77u8; 32];
        let mut n = 0u32;
        while bob.skipped.len() < MAX_SKIPPED_KEYS {
            bob.skipped.insert((dh, n), Zeroizing::new([1; 32]));
            n += 1;
        }
        let rec = bob.to_checkpoint().unwrap();
        assert_eq!(rec.len(), v2_len(&bob));
        assert_same_state(&bob, &DoubleRatchet::from_checkpoint(&rec).unwrap());

        bob.skipped.insert((dh, n), Zeroizing::new([1; 32]));
        assert_eq!(
            bob.to_checkpoint().unwrap_err(),
            CheckpointError::TooManySkippedKeys(MAX_SKIPPED_KEYS as u32 + 1)
        );
        // A count above the limit is refused before the length is considered.
        let mut forged = rec.to_vec();
        forged[178..182].copy_from_slice(&(MAX_SKIPPED_KEYS as u32 + 1).to_be_bytes());
        assert_eq!(
            decode_err(&forged),
            CheckpointError::TooManySkippedKeys(MAX_SKIPPED_KEYS as u32 + 1)
        );
        // A record longer than the largest valid one exceeds the size limit.
        let room = RATCHET_CHECKPOINT_MAX_LEN - forged.len();
        forged.extend(std::iter::repeat_n(2u8, room + 1));
        assert_eq!(
            decode_err(&forged),
            CheckpointError::Oversized {
                actual: RATCHET_CHECKPOINT_MAX_LEN + 1
            }
        );
    }

    #[test]
    fn every_truncation_and_any_extension_is_rejected() {
        let (_, bob, _) = with_skipped();
        let rec = bob.to_checkpoint().unwrap();
        for len in 0..rec.len() {
            assert!(
                DoubleRatchet::from_checkpoint(&rec[..len]).is_err(),
                "prefix {len}"
            );
        }
        let mut longer = rec.to_vec();
        longer.push(0);
        assert!(matches!(
            DoubleRatchet::from_checkpoint(&longer),
            Err(CheckpointError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn unsupported_version_and_flags_are_rejected() {
        let (alice, _) = pair();
        let rec = alice.to_checkpoint().unwrap();
        for v in [0u8, 3, 0xff] {
            let mut r = rec.to_vec();
            r[0] = v;
            assert_eq!(decode_err(&r), CheckpointError::UnsupportedVersion(v));
        }
        let mut r = rec.to_vec();
        r[1] |= 0b1000;
        assert!(matches!(
            DoubleRatchet::from_checkpoint(&r),
            Err(CheckpointError::UnknownFlags(_))
        ));
        let mut r = rec.to_vec();
        r[174..178].copy_from_slice(&1000u32.to_be_bytes());
        assert_eq!(decode_err(&r), CheckpointError::UnexpectedCapacity(1000));
    }

    #[test]
    fn unreachable_presence_combinations_are_rejected() {
        let (_, bob, _) = with_skipped(); // (+, +, +)
        let rec = bob.to_checkpoint().unwrap();
        let empty = {
            // Same state without skipped entries or earlier chains, so only
            // the flags differ.
            let mut r = rec[..FIXED_LEN].to_vec();
            r[178..182].copy_from_slice(&0u32.to_be_bytes());
            r.push(0);
            r
        };
        for flags in 0u8..8 {
            if matches!(flags, 0b000 | 0b011 | 0b111) {
                continue;
            }
            let mut r = empty.clone();
            r[1] = flags;
            // Zero every field the flags mark absent, so only the combination is wrong.
            for (bit, off) in [(FLAG_DHR, 34), (FLAG_CKS, 98), (FLAG_CKR, 130)] {
                if flags & bit == 0 {
                    r[off..off + 32].fill(0);
                }
            }
            r[166..174].fill(0); // nr, pn
            assert!(
                matches!(
                    DoubleRatchet::from_checkpoint(&r),
                    Err(CheckpointError::InconsistentState(_))
                ),
                "flags {flags:#05b}"
            );
        }
    }

    #[test]
    fn counters_and_skipped_keys_without_a_receiving_chain_are_rejected() {
        let (alice, bob) = pair();
        let a = alice.to_checkpoint().unwrap();
        let b = bob.to_checkpoint().unwrap();
        for (base, off) in [(&a, 166), (&a, 170), (&b, 162), (&b, 166), (&b, 170)] {
            let mut r = base.to_vec();
            r[off..off + 4].copy_from_slice(&1u32.to_be_bytes());
            assert!(
                matches!(
                    DoubleRatchet::from_checkpoint(&r),
                    Err(CheckpointError::InconsistentState(_))
                ),
                "offset {off}"
            );
        }
        let mut r = a[..FIXED_LEN].to_vec();
        r[178..182].copy_from_slice(&1u32.to_be_bytes());
        r.extend_from_slice(&[1u8; ENTRY_LEN]);
        r.push(0);
        assert!(matches!(
            DoubleRatchet::from_checkpoint(&r),
            Err(CheckpointError::InconsistentState(_))
        ));
        // An earlier chain without a receiving chain.
        let mut r = a.to_vec();
        *r.last_mut().unwrap() = 1;
        r.extend_from_slice(&[5u8; CHAIN_LEN]);
        assert!(matches!(
            DoubleRatchet::from_checkpoint(&r),
            Err(CheckpointError::InconsistentState(_))
        ));
    }

    /// R-21: the earlier chains a ratchet remembers round-trip in order, and
    /// a record that breaks their rules is refused on decode as the same
    /// state is on encode: more than `MAX_PREV_CHAINS`, a peer key twice, or
    /// the current one.
    #[test]
    fn earlier_chains_round_trip_and_their_rules_are_enforced() {
        let (_, mut bob, _) = with_skipped();
        assert_eq!(bob.prev_chains.len(), 1, "Bob left Alice's first chain");
        let rec = bob.to_checkpoint().unwrap();
        assert_same_state(&bob, &DoubleRatchet::from_checkpoint(&rec).unwrap());

        let dhr = *bob.dhr.unwrap().as_bytes();
        let base = rec[..rec.len() - 1 - CHAIN_LEN * bob.prev_chains.len()].to_vec();
        let with = |chains: &[([u8; 32], u32)]| {
            let mut r = base.clone();
            r.push(chains.len() as u8);
            for (dh, end) in chains {
                r.extend_from_slice(dh);
                r.extend_from_slice(&end.to_be_bytes());
            }
            r
        };
        let four: Vec<_> = (1..=4u8).map(|i| ([i; 32], u32::from(i))).collect();
        assert_eq!(DoubleRatchet::from_checkpoint(&with(&four)).unwrap().prev_chains, four);
        let mut five = four.clone();
        five.push(([9; 32], 9));
        assert_eq!(decode_err(&with(&five)), CheckpointError::TooManyChains(5));
        assert_eq!(
            decode_err(&with(&[([1; 32], 1), ([1; 32], 2)])),
            CheckpointError::DuplicateChain
        );
        assert_eq!(decode_err(&with(&[(dhr, 1)])), CheckpointError::DuplicateChain);

        bob.prev_chains = five;
        assert_eq!(bob.to_checkpoint().unwrap_err(), CheckpointError::TooManyChains(5));
        bob.prev_chains = vec![(dhr, 1)];
        assert_eq!(bob.to_checkpoint().unwrap_err(), CheckpointError::DuplicateChain);
    }

    /// A peer that repeats a ratchet key Bob remembers as an earlier chain:
    /// entering that chain again forgets its record, so the state still
    /// has distinct earlier chains, none equal to the current one, and
    /// round-trips through a checkpoint.
    #[test]
    fn entering_a_remembered_chain_again_keeps_the_state_storable() {
        let (_, mut bob, _) = with_skipped();
        let current = *bob.dhr.unwrap().as_bytes();
        bob.prev_chains = vec![([1; 32], 3), ([2; 32], 4)];
        bob.leave_chain(&[1; 32], 7);
        assert_eq!(bob.prev_chains, vec![([2; 32], 4), (current, 7)]);
        // As after the DH step into the repeated key.
        bob.dhr = Some(PublicKey::from([1; 32]));
        let rec = bob.to_checkpoint().unwrap();
        assert_same_state(&bob, &DoubleRatchet::from_checkpoint(&rec).unwrap());
    }

    #[test]
    fn absent_fields_must_be_zero() {
        let (alice, bob) = pair();
        for (rec, off, name) in [
            (alice.to_checkpoint().unwrap(), 130, "ckr"),
            (bob.to_checkpoint().unwrap(), 34, "dhr"),
            (bob.to_checkpoint().unwrap(), 98, "cks"),
        ] {
            let mut r = rec.to_vec();
            r[off + 31] = 1;
            assert_eq!(decode_err(&r), CheckpointError::AbsentFieldNotZero(name));
        }
    }

    #[test]
    fn duplicate_skipped_entries_are_rejected() {
        let (_, bob, _) = with_skipped();
        let mut r = bob.to_checkpoint().unwrap().to_vec();
        let (first, second) = (FIXED_LEN, FIXED_LEN + ENTRY_LEN);
        let key: Vec<u8> = r[first..first + 36].to_vec();
        r[second..second + 36].copy_from_slice(&key);
        assert_eq!(decode_err(&r), CheckpointError::DuplicateSkippedKey);
    }

    #[test]
    fn exhausted_counters_are_refused_on_encode_and_decode() {
        let (alice, _) = pair();
        let (_, bob, _) = with_skipped(); // (+, +, +)
        for (base, off, name, limit) in [
            (&alice, 162, "ns", u32::MAX - 1),
            (&bob, 162, "ns", u32::MAX - 1),
            (&bob, 166, "nr", MAX_RESUMABLE_NR),
        ] {
            let mut r = base.to_checkpoint().unwrap().to_vec();
            for bad in [limit + 1, u32::MAX] {
                r[off..off + 4].copy_from_slice(&bad.to_be_bytes());
                assert_eq!(decode_err(&r), CheckpointError::CounterExhausted(name));
            }
            r[off..off + 4].copy_from_slice(&limit.to_be_bytes());
            assert!(
                DoubleRatchet::from_checkpoint(&r).is_ok(),
                "{name} at its limit"
            );
        }
        assert_eq!(MAX_RESUMABLE_NR, u32::MAX - 1001);
        let mut exhausted = bob.staged_copy();
        exhausted.ns = u32::MAX;
        assert_eq!(
            exhausted.to_checkpoint().unwrap_err(),
            CheckpointError::CounterExhausted("ns")
        );
        let mut exhausted = bob.staged_copy();
        exhausted.nr = u32::MAX;
        assert_eq!(
            exhausted.to_checkpoint().unwrap_err(),
            CheckpointError::CounterExhausted("nr")
        );
        // pn has no arithmetic and no limit.
        let mut r = bob.to_checkpoint().unwrap().to_vec();
        r[170..174].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(DoubleRatchet::from_checkpoint(&r).is_ok());
    }

    /// A sender and receiver whose chains are in step with both counters at
    /// `at`, built from a real exchange; only the counters are moved.
    fn in_step_at(at: u32) -> (DoubleRatchet, DoubleRatchet) {
        let (mut alice, mut bob) = pair();
        let (h, c) = alice.encrypt(b"sync", AD).unwrap();
        bob.decrypt(&h, &c, AD).unwrap();
        alice.ns = at;
        bob.nr = at;
        (alice, bob)
    }

    /// F-1 regression. `b40c006` accepted `nr = u32::MAX - 2`; an authentic
    /// message with `n = u32::MAX` then wrapped `nr` to 0 in a release build
    /// and the wrapped state was accepted for checkpointing. Such a state is
    /// now refused when it is decoded.
    #[test]
    fn f1_receiver_state_that_could_wrap_nr_is_refused_on_decode() {
        let (_, bob) = in_step_at(u32::MAX - 2);
        let mut r = bob.staged_copy();
        r.nr = MAX_RESUMABLE_NR; // encodable
        let mut rec = r.to_checkpoint().unwrap().to_vec();
        rec[166..170].copy_from_slice(&(u32::MAX - 2).to_be_bytes());
        assert_eq!(decode_err(&rec), CheckpointError::CounterExhausted("nr"));
        for nr in [u32::MAX - MAX_SKIP, u32::MAX - 1] {
            rec[166..170].copy_from_slice(&nr.to_be_bytes());
            assert_eq!(decode_err(&rec), CheckpointError::CounterExhausted("nr"));
        }
    }

    /// R-14. A far skip never ends past `MAX_RESUMABLE_NR`, so the increment
    /// after it cannot overflow `nr`: from a resumed state within
    /// `MAX_FAR_SKIP` of the limit, a header beyond the limit fails the skip
    /// limit before any key is derived (no panic in a debug build). A state
    /// already past the limit is never resumed; there `decrypt_far` allows
    /// no more than `decrypt` (`limit` in `skip_message_keys`).
    #[test]
    fn a_far_skip_never_moves_nr_past_the_resumable_limit() {
        for at in [MAX_RESUMABLE_NR - 50_000, MAX_RESUMABLE_NR - 2_000] {
            let (alice, bob) = in_step_at(at);
            let mut bob = restore(&bob);
            for n in [MAX_RESUMABLE_NR + 1, u32::MAX] {
                let forged = Header {
                    dh: alice.our_dh_public().to_bytes(),
                    pn: 0,
                    n,
                };
                assert!(
                    matches!(bob.decrypt_far(&forged, &[0u8; 40], AD), Err(RatchetError::SkipLimit)),
                    "at {at}, n {n}"
                );
                assert_eq!(bob.nr, at, "state untouched");
            }
        }
    }

    /// At the limit, incoming `n = u32::MAX` fails the skip limit before any
    /// counter arithmetic (no panic in a debug build, no wrap in release),
    /// and `n = u32::MAX - 1` decrypts but its resulting state is refused
    /// for checkpointing: the rejection happens at the transition, not at
    /// decode.
    #[test]
    fn at_the_limit_top_message_numbers_cannot_produce_a_persistable_state() {
        let (mut alice, bob) = in_step_at(MAX_RESUMABLE_NR);
        let mut bob = restore(&bob); // the limit itself decodes

        let forged = Header {
            dh: alice.our_dh_public().to_bytes(),
            pn: 0,
            n: u32::MAX,
        };
        assert!(matches!(
            bob.decrypt(&forged, &[0u8; 40], AD),
            Err(RatchetError::SkipLimit)
        ));
        assert_eq!(bob.nr, MAX_RESUMABLE_NR, "state untouched");

        // Authentic n = u32::MAX - 1: the sender walks its chain up to it.
        let mut last = None;
        while alice.ns < u32::MAX {
            last = Some(alice.encrypt(b"top", AD).unwrap());
        }
        let (h, c) = last.unwrap();
        assert_eq!(h.n, u32::MAX - 1);
        assert_eq!(*bob.decrypt(&h, &c, AD).unwrap(), b"top");
        assert_eq!(bob.nr, u32::MAX);
        assert_eq!(
            bob.to_checkpoint().unwrap_err(),
            CheckpointError::CounterExhausted("nr")
        );
    }

    /// Below the limit, receiving continues and the results stay
    /// checkpointable up to the limit itself.
    #[test]
    fn states_below_the_limit_keep_receiving_and_round_trip() {
        let (mut alice, bob) = in_step_at(MAX_RESUMABLE_NR - 2);
        let mut bob = restore(&bob);
        for expected_nr in [MAX_RESUMABLE_NR - 1, MAX_RESUMABLE_NR] {
            let (h, c) = alice.encrypt(b"m", AD).unwrap();
            assert_eq!(*bob.decrypt(&h, &c, AD).unwrap(), b"m");
            assert_eq!(bob.nr, expected_nr);
            bob = restore(&bob);
        }
        // One more is a valid receive whose state can no longer be persisted.
        let (h, c) = alice.encrypt(b"m", AD).unwrap();
        assert_eq!(*bob.decrypt(&h, &c, AD).unwrap(), b"m");
        assert_eq!(
            bob.to_checkpoint().unwrap_err(),
            CheckpointError::CounterExhausted("nr")
        );
    }

    #[test]
    fn staged_copy_is_independent_of_the_original() {
        let (mut alice, mut bob) = pair();
        let before = alice.to_checkpoint().unwrap();
        let mut staged = alice.staged_copy();
        let (h_staged, _) = staged.encrypt(b"staged", AD).unwrap();
        assert_eq!(
            *alice.to_checkpoint().unwrap(),
            *before,
            "original untouched"
        );

        // Dropping the copy and using the original yields the same counter: the
        // copy never consumed anything in the original.
        drop(staged);
        let (h, c) = alice.encrypt(b"real", AD).unwrap();
        assert_eq!(h.n, h_staged.n);
        assert_eq!(*bob.decrypt(&h, &c, AD).unwrap(), b"real");
    }
}
