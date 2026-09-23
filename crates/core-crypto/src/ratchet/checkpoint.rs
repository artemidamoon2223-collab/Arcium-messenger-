//! Versioned byte encoding of the complete `DoubleRatchet` state
//! (`RATCHET_STATE_V1`), and an independent in-memory copy for staging.
//!
//! This module only serialises and reconstructs state. It does not change key
//! evolution, KDFs, AEAD, nonces or the message header, and nothing in the live
//! message path calls it.
//!
//! What a checkpoint is *not*: it is not encrypted or authenticated here (the
//! caller's store provides that), and restoring one says nothing about whether
//! it is the latest state that existed. An older record decodes exactly as well
//! as a newer one.
//!
//! # Layout (all integers big-endian)
//!
//! | offset | size | field                                              |
//! |-------:|-----:|----------------------------------------------------|
//! |      0 |    1 | version, `1`                                       |
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
//!
//! The record length must be exactly `182 + 68·count`.
//!
//! # Accepted states
//!
//! Decoding accepts only states the ratchet itself can reach, so a record that
//! could never have been written by this code is rejected rather than repaired:
//!
//! - `(dhr, cks, ckr)` presence is one of `(-, -, -)` (`init_bob`, before the
//!   first message), `(+, +, -)` (`init_alice`, before the first reply) or
//!   `(+, +, +)` (after any DH ratchet step). `DoubleRatchet::decrypt` rolls back
//!   on failure, so no other combination survives a call.
//! - Without `ckr`, `nr == 0`, `pn == 0` and there are no skipped keys:
//!   `pn` is only set, and keys are only skipped, once a receiving chain exists.
//! - In `(-, -, -)`, `ns == 0`: `encrypt` fails before advancing.
//! - At most [`MAX_SKIPPED_KEYS`] skipped keys, no duplicate `(dh, n)`.
//!
//! `ckr` present with `dhr` absent is among the rejected combinations; the
//! ratchet's `skip_message_keys` relies on that never happening.

use indexmap::IndexMap;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use super::DoubleRatchet;

/// Current `RATCHET_STATE_V1` format version.
pub const RATCHET_CHECKPOINT_VERSION: u8 = 1;

/// Skipped-key capacity every ratchet is created with (`max_skipped` in
/// `init_alice` / `init_bob`). A record carrying any other value is rejected.
pub const MAX_SKIPPED_KEYS: usize = 2000;

const FLAG_DHR: u8 = 0b001;
const FLAG_CKS: u8 = 0b010;
const FLAG_CKR: u8 = 0b100;
const KNOWN_FLAGS: u8 = FLAG_DHR | FLAG_CKS | FLAG_CKR;

const FIXED_LEN: usize = 182;
const ENTRY_LEN: usize = 32 + 4 + 32;

/// Largest valid `RATCHET_STATE_V1` record, in bytes.
pub const RATCHET_CHECKPOINT_MAX_LEN: usize = FIXED_LEN + ENTRY_LEN * MAX_SKIPPED_KEYS;

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
    #[error("ratchet checkpoint field {0} is marked absent but not zero")]
    AbsentFieldNotZero(&'static str),
    #[error("ratchet state is not one this implementation can reach: {0}")]
    InconsistentState(&'static str),
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
    Ok(())
}

impl DoubleRatchet {
    /// Encodes the complete ratchet state as a `RATCHET_STATE_V1` record.
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

        let len = FIXED_LEN + ENTRY_LEN * self.skipped.len();
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
        out.extend_from_slice(&self.rk);
        out.extend_from_slice(self.cks.as_ref().unwrap_or(&[0u8; 32]));
        out.extend_from_slice(self.ckr.as_ref().unwrap_or(&[0u8; 32]));
        out.extend_from_slice(&self.ns.to_be_bytes());
        out.extend_from_slice(&self.nr.to_be_bytes());
        out.extend_from_slice(&self.pn.to_be_bytes());
        // Both fit in u32: checked against MAX_SKIPPED_KEYS above.
        out.extend_from_slice(&(self.max_skipped as u32).to_be_bytes());
        out.extend_from_slice(&(self.skipped.len() as u32).to_be_bytes());
        for ((dh, n), mk) in &self.skipped {
            out.extend_from_slice(dh);
            out.extend_from_slice(&n.to_be_bytes());
            out.extend_from_slice(mk);
        }
        debug_assert_eq!(out.len(), len);
        debug_assert_eq!(out.capacity(), len);
        Ok(out)
    }

    /// Rebuilds a ratchet from a `RATCHET_STATE_V1` record.
    ///
    /// Every field is taken as stored: nothing is regenerated, defaulted or
    /// corrected, and a record that fails any check is rejected as a whole.
    /// Skipped keys come back in the stored order, so eviction continues
    /// exactly where it left off.
    ///
    /// Success means the bytes describe a reachable ratchet state. It does not
    /// mean the state is current, belongs to the session the caller expects,
    /// or was not rolled back; those are the caller's to establish.
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
        if record[0] != RATCHET_CHECKPOINT_VERSION {
            return Err(CheckpointError::UnsupportedVersion(record[0]));
        }
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
        let expected = FIXED_LEN + ENTRY_LEN * count as usize;
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
        // the ratchet, whose Drop wipes them if a skipped-key check fails.
        let mut dhs_bytes = read_32(record, 2);
        let dhs = StaticSecret::from(dhs_bytes);
        dhs_bytes.zeroize();
        let mut ratchet = DoubleRatchet {
            dhs,
            dhr: has_dhr.then(|| PublicKey::from(read_32(record, 34))),
            rk: read_32(record, 66),
            cks: has_cks.then(|| read_32(record, 98)),
            ckr: has_ckr.then(|| read_32(record, 130)),
            ns,
            nr,
            pn,
            skipped: IndexMap::with_capacity(count as usize),
            max_skipped: MAX_SKIPPED_KEYS,
        };
        for entry in record[FIXED_LEN..].chunks_exact(ENTRY_LEN) {
            let dh = read_32(entry, 0);
            let n = read_u32(entry, 32);
            if ratchet.skipped.contains_key(&(dh, n)) {
                return Err(CheckpointError::DuplicateSkippedKey);
            }
            ratchet.skipped.insert((dh, n), read_32(entry, 36));
        }
        Ok(ratchet)
    }

    /// Returns an independent copy of the full ratchet state, for preparing a
    /// transition without touching the original.
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
            rk: self.rk,
            cks: self.cks,
            ckr: self.ckr,
            ns: self.ns,
            nr: self.nr,
            pn: self.pn,
            skipped: self.skipped.clone(),
            max_skipped: self.max_skipped,
        }
    }
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
    use crate::ratchet::{Header, HEADER_SIZE, NONCE_SIZE};
    use rand_core::OsRng;

    const AD: &[u8] = b"checkpoint-test-ad";

    fn pair() -> (DoubleRatchet, DoubleRatchet) {
        let root = [9u8; 32];
        let bob_spk = StaticSecret::random_from_rng(OsRng);
        let alice = DoubleRatchet::init_alice(root, PublicKey::from(&bob_spk));
        let bob = DoubleRatchet::init_bob(root, bob_spk);
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
    }

    fn with_skipped() -> (DoubleRatchet, DoubleRatchet, Vec<(Header, Vec<u8>)>) {
        let (mut alice, mut bob) = pair();
        let (h, c) = alice.encrypt(b"first", AD).unwrap();
        bob.decrypt(&h, &c, AD).unwrap();
        let (h, c) = bob.encrypt(b"reply", AD).unwrap();
        alice.decrypt(&h, &c, AD).unwrap();
        let held: Vec<_> = (0..4).map(|i| alice.encrypt(&[i], AD).unwrap()).collect();
        let (h, c) = alice.encrypt(b"latest", AD).unwrap();
        assert_eq!(bob.decrypt(&h, &c, AD).unwrap(), b"latest");
        assert_eq!(bob.skipped.len(), 4);
        (alice, bob, held)
    }

    #[test]
    fn constructors_use_the_encoded_capacity() {
        let (alice, bob) = pair();
        assert_eq!(alice.max_skipped, MAX_SKIPPED_KEYS);
        assert_eq!(bob.max_skipped, MAX_SKIPPED_KEYS);
        assert_eq!(RATCHET_CHECKPOINT_MAX_LEN, 136_182);
    }

    #[test]
    fn round_trip_is_byte_exact_in_every_reachable_shape() {
        let (alice, bob) = pair();
        let (a2, b2, _) = with_skipped();
        for r in [&alice, &bob, &a2, &b2] {
            let rec = r.to_checkpoint().unwrap();
            assert_eq!(rec.len(), FIXED_LEN + ENTRY_LEN * r.skipped.len());
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
            assert_eq!(bob.decrypt(h, c, AD).unwrap(), [i as u8]);
        }
        assert!(bob.skipped.is_empty());

        // Several DH steps after restoring, each side restored again midway.
        for round in 0u8..3 {
            let (h, c) = bob.encrypt(&[round], AD).unwrap();
            assert_eq!(alice.decrypt(&h, &c, AD).unwrap(), [round]);
            alice = restore(&alice);
            let (h, c) = alice.encrypt(&[round, 1], AD).unwrap();
            assert_eq!(bob.decrypt(&h, &c, AD).unwrap(), [round, 1]);
            bob = restore(&bob);
        }
    }

    #[test]
    fn responder_restored_before_first_message_still_receives_it() {
        let (mut alice, bob) = pair();
        let mut bob = restore(&bob);
        let (h, c) = alice.encrypt(b"hi", AD).unwrap();
        assert_eq!(bob.decrypt(&h, &c, AD).unwrap(), b"hi");
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
        assert_eq!(bob.decrypt(&h, &c, AD).unwrap(), b"abc");
    }

    #[test]
    fn restored_skipped_keys_evict_in_the_original_order() {
        let (_, mut original, _) = with_skipped();
        // Fill to capacity so the next insert evicts.
        let dh = [0x55u8; 32];
        for n in 0..(MAX_SKIPPED_KEYS - original.skipped.len()) as u32 {
            original.skipped.insert((dh, n), [n as u8; 32]);
        }
        let mut restored = restore(&original);
        assert_same_state(&original, &restored);
        for r in [&mut original, &mut restored] {
            r.skipped.insert(([0x66; 32], 0), [1; 32]);
            r.skipped.insert(([0x66; 32], 1), [2; 32]);
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
            bob.skipped.insert((dh, n), [1; 32]);
            n += 1;
        }
        let rec = bob.to_checkpoint().unwrap();
        assert_eq!(rec.len(), RATCHET_CHECKPOINT_MAX_LEN);
        assert_same_state(&bob, &DoubleRatchet::from_checkpoint(&rec).unwrap());

        bob.skipped.insert((dh, n), [1; 32]);
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
        // A record with the 2001st entry appended exceeds the size limit.
        forged.extend_from_slice(&[2u8; ENTRY_LEN]);
        assert_eq!(
            decode_err(&forged),
            CheckpointError::Oversized {
                actual: RATCHET_CHECKPOINT_MAX_LEN + ENTRY_LEN
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
        for v in [0u8, 2, 0xff] {
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
            // Same state without skipped entries, so only the flags differ.
            let mut r = rec[..FIXED_LEN].to_vec();
            r[178..182].copy_from_slice(&0u32.to_be_bytes());
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
        let mut r = a.to_vec();
        r[178..182].copy_from_slice(&1u32.to_be_bytes());
        r.extend_from_slice(&[1u8; ENTRY_LEN]);
        assert!(matches!(
            DoubleRatchet::from_checkpoint(&r),
            Err(CheckpointError::InconsistentState(_))
        ));
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
        assert_eq!(bob.decrypt(&h, &c, AD).unwrap(), b"real");
    }
}
