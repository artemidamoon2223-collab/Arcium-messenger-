//! Double Ratchet implementation (Signal spec).
//!
//! Differences from the Python prototype this is based on:
//!   1. Chain keys after a DH ratchet step are derived correctly so that
//!      sender's CKs == receiver's CKr (the Python version used identical
//!      labels on both sides, which silently broke any cross-direction
//!      message after a DH step).
//!   2. Skipped message keys are indexed by `(their_dh_pk, n)`, so messages
//!      that arrive late after a chain switch can still be decrypted.
//!   3. The header (DH || PN || N) is bound to the ciphertext via AEAD AAD,
//!      preventing an active attacker from substituting headers.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use indexmap::IndexMap;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};
// Unit tests swap in a counting stand-in with the same behaviour; see `probe`.
#[cfg(test)]
use self::probe::Zeroizing;
#[cfg(not(test))]
use zeroize::Zeroizing;

mod checkpoint;
#[cfg(test)]
mod probe;
pub use checkpoint::{
    CheckpointError, MAX_SKIPPED_KEYS, RATCHET_CHECKPOINT_MAX_LEN, RATCHET_CHECKPOINT_VERSION,
};

/// Max number of message keys that may be skipped within a single receiving chain.
pub const MAX_SKIP: u32 = 1000;
/// Header is: DH public key (32) || PN (4) || N (4).
pub const HEADER_SIZE: usize = 32 + 4 + 4;
/// XChaCha20Poly1305 nonce size.
pub const NONCE_SIZE: usize = 24;

// Secret 32-byte keys are held in `Zeroizing`, so each one is wiped when its
// owner is dropped: at the end of the operation for a temporary, when it is
// replaced or evicted for a live one, and on unwinding. `Zeroizing` is not
// `Copy`, so a copy of a key is always spelled out (`clone`) and a borrow is
// the default.
type ChainKey = Zeroizing<[u8; 32]>;
type MessageKey = Zeroizing<[u8; 32]>;
type RootKey = Zeroizing<[u8; 32]>;

#[derive(Debug, Error)]
pub enum RatchetError {
    #[error("AEAD decryption failed")]
    Decryption,
    #[error("skip limit ({MAX_SKIP}) exceeded in receive chain")]
    SkipLimit,
    #[error("malformed header")]
    InvalidHeader,
    #[error("chain not yet initialized; bob must receive first message before sending")]
    NotInitialized,
}

#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub dh: [u8; 32],
    pub pn: u32,
    pub n: u32,
}

impl Header {
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[0..32].copy_from_slice(&self.dh);
        out[32..36].copy_from_slice(&self.pn.to_be_bytes());
        out[36..40].copy_from_slice(&self.n.to_be_bytes());
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, RatchetError> {
        if b.len() < HEADER_SIZE {
            return Err(RatchetError::InvalidHeader);
        }
        let mut dh = [0u8; 32];
        dh.copy_from_slice(&b[0..32]);
        let pn = u32::from_be_bytes(b[32..36].try_into().unwrap());
        let n = u32::from_be_bytes(b[36..40].try_into().unwrap());
        Ok(Self { dh, pn, n })
    }
}

/// Every secret field is a wiping type (`StaticSecret`, `Zeroizing`), so
/// dropping a ratchet wipes its keys with no `Drop` code of its own; the
/// `ZeroizeOnDrop` marker below states that and `tests::secret_fields_wipe_on_drop`
/// pins it field by field. A ratchet is long-lived state: nothing here is wiped
/// before it is replaced.
pub struct DoubleRatchet {
    dhs: StaticSecret,           // our current DH secret
    dhr: Option<PublicKey>,      // their last seen DH public
    rk: RootKey,
    cks: Option<ChainKey>,       // sending chain key
    ckr: Option<ChainKey>,       // receiving chain key
    ns: u32,                     // messages sent in current sending chain
    nr: u32,                     // messages received in current receiving chain
    pn: u32,                     // messages sent in previous sending chain (sent in header so peer can skip)
    skipped: IndexMap<([u8; 32], u32), MessageKey>,
    max_skipped: usize,
}

impl DoubleRatchet {
    /// Alice's side: she already knows Bob's initial DH public key (his signed prekey),
    /// so she can derive the first sending chain immediately.
    pub fn init_alice(sk: &[u8; 32], their_initial_dh: PublicKey) -> Self {
        let dhs = StaticSecret::random_from_rng(OsRng);
        let dh_out = dhs.diffie_hellman(&their_initial_dh);
        let (rk, cks) = kdf_rk(sk, dh_out.as_bytes());
        Self {
            dhs,
            dhr: Some(their_initial_dh),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: IndexMap::new(),
            max_skipped: 2000,
        }
    }

    /// Bob's side: he keeps his existing DH keypair (the one tied to his signed prekey),
    /// and only sets up sending/receiving chains when Alice's first message arrives.
    pub fn init_bob(sk: &[u8; 32], our_initial_dh: StaticSecret) -> Self {
        Self {
            dhs: our_initial_dh,
            dhr: None,
            rk: Zeroizing::new(*sk),
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: IndexMap::new(),
            max_skipped: 2000,
        }
    }

    pub fn our_dh_public(&self) -> PublicKey {
        PublicKey::from(&self.dhs)
    }

    /// Whether a message from the peer has been authenticated. The receiving
    /// chain is created only by a DH ratchet step inside [`decrypt`](Self::decrypt),
    /// which is rolled back unless the message authenticates.
    pub fn has_receiving_chain(&self) -> bool {
        self.ckr.is_some()
    }

    /// Whether this is exactly the state [`init_bob`](Self::init_bob) creates
    /// and nothing has happened to since: no peer ratchet key, no sending or
    /// receiving chain, all counters zero, no skipped keys.
    ///
    /// Such a ratchet has authenticated nothing (a receiving chain appears
    /// only through a decrypt that authenticated) and cannot encrypt
    /// ([`encrypt`](Self::encrypt) returns [`RatchetError::NotInitialized`]),
    /// so it has produced no ciphertext either. Read-only; it says nothing
    /// about the root key or `dhs`, which it does not inspect.
    pub fn is_initial_responder_state(&self) -> bool {
        self.dhr.is_none()
            && self.cks.is_none()
            && self.ckr.is_none()
            && self.ns == 0
            && self.nr == 0
            && self.pn == 0
            && self.skipped.is_empty()
    }

    pub fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Result<(Header, Vec<u8>), RatchetError> {
        let cks = self.cks.as_ref().ok_or(RatchetError::NotInitialized)?;
        let (new_cks, mk) = kdf_ck(cks);
        // The next chain key is installed first; the old one is wiped as the
        // assignment drops it. `mk` is wiped when this function returns, on
        // success and on the `?` below alike.
        self.cks = Some(new_cks);
        let header = Header {
            dh: *self.our_dh_public().as_bytes(),
            pn: self.pn,
            n: self.ns,
        };
        self.ns += 1;
        let full_ad = concat_ad(ad, &header.to_bytes());
        let ct = aead_encrypt(&mk, plaintext, &full_ad)?;
        Ok((header, ct))
    }

    /// Decrypt with commit-on-success semantics.
    ///
    /// `decrypt_inner` mutates ratchet state (skipped keys, DH ratchet step, chain
    /// advance) *before* the final AEAD authentication result is known. A forged or
    /// unknown-DH message that fails authentication must not desync the session, so
    /// we snapshot all mutable state up front and roll it back on any error. State is
    /// only kept when authentication succeeds.
    pub fn decrypt(
        &mut self,
        header: &Header,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, RatchetError> {
        let snapshot = self.snapshot();
        match self.decrypt_inner(header, ciphertext, ad) {
            // `snapshot` falls out of scope here; the key fields of the unused
            // rollback copy wipe themselves as it is dropped — on this return
            // and on panic/unwind alike.
            Ok(pt) => Ok(pt),
            Err(e) => {
                self.restore(snapshot);
                Err(e)
            }
        }
    }

    fn decrypt_inner(
        &mut self,
        header: &Header,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, RatchetError> {
        let full_ad = concat_ad(ad, &header.to_bytes());

        // 1. Check skipped keys first (handles out-of-order and across-chain late arrivals).
        if let Some(mk) = self.skipped.swap_remove(&(header.dh, header.n)) {
            return aead_decrypt(&mk, ciphertext, &full_ad);
        }

        // 2. New peer DH key? Do receiving DH ratchet step.
        let need_dh = match self.dhr {
            Some(dhr) => *dhr.as_bytes() != header.dh,
            None => true,
        };
        if need_dh {
            // Save remaining keys from the old chain (so late messages from old chain still decrypt).
            self.skip_message_keys(header.pn)?;
            self.dh_ratchet_step(PublicKey::from(header.dh))?;
        }

        // 3. Skip ahead in the current chain to header.n.
        self.skip_message_keys(header.n)?;

        // 4. Derive the message key.
        let ckr = self.ckr.as_ref().ok_or(RatchetError::NotInitialized)?;
        let (new_ckr, mk) = kdf_ck(ckr);
        self.ckr = Some(new_ckr);
        self.nr += 1;

        aead_decrypt(&mk, ciphertext, &full_ad)
    }

    /// Capture all mutable state so a failed `decrypt_inner` can be rolled back.
    fn snapshot(&self) -> RatchetSnapshot {
        RatchetSnapshot {
            dhs: self.dhs.clone(),
            dhr: self.dhr,
            rk: self.rk.clone(),
            cks: self.cks.clone(),
            ckr: self.ckr.clone(),
            ns: self.ns,
            nr: self.nr,
            pn: self.pn,
            skipped: self.skipped.clone(),
        }
    }

    /// Put a snapshot back. Each assignment drops the value it replaces, which
    /// wipes the abandoned (mutated) key material of that field.
    fn restore(&mut self, snap: RatchetSnapshot) {
        self.dhs = snap.dhs;
        self.dhr = snap.dhr;
        self.rk = snap.rk;
        self.cks = snap.cks;
        self.ckr = snap.ckr;
        self.ns = snap.ns;
        self.nr = snap.nr;
        self.pn = snap.pn;
        self.skipped = snap.skipped;
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<(), RatchetError> {
        if self.nr.saturating_add(MAX_SKIP) < until {
            return Err(RatchetError::SkipLimit);
        }
        if let Some(ckr) = self.ckr.as_mut() {
            while self.nr < until {
                let (new_ckr, mk) = kdf_ck(ckr);
                // Each assignment wipes the chain key it replaces; the message
                // key moves into `skipped`, where it stays until it is
                // consumed or evicted.
                *ckr = new_ckr;
                let dhr_bytes = *self.dhr.expect("dhr set when ckr is").as_bytes();
                self.skipped.insert((dhr_bytes, self.nr), mk);
                self.nr += 1;
            }
            self.trim_skipped();
        }
        Ok(())
    }

    /// Standard Signal DH ratchet step on receive:
    ///
    ///   1. Derive new RECEIVING chain from DH(our current DHs, new their DHr).
    ///   2. Generate new local DH keypair.
    ///   3. Derive new SENDING chain from DH(new DHs, new their DHr).
    ///
    /// This guarantees sender's CKs equals receiver's CKr at the matching point.
    fn dh_ratchet_step(&mut self, new_dhr: PublicKey) -> Result<(), RatchetError> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(new_dhr);

        {
            // `dh_out` (a `SharedSecret`) is wiped when this block ends.
            let dh_out = self.dhs.diffie_hellman(&new_dhr);
            let (rk, ckr) = kdf_rk(&self.rk, dh_out.as_bytes());
            self.rk = rk;
            self.ckr = Some(ckr);
        }

        self.dhs = StaticSecret::random_from_rng(OsRng);
        let dh_out = self.dhs.diffie_hellman(&new_dhr);
        let (rk, cks) = kdf_rk(&self.rk, dh_out.as_bytes());
        self.rk = rk;
        self.cks = Some(cks);
        Ok(())
    }

    fn trim_skipped(&mut self) {
        // Evict oldest-inserted entries first (FIFO by IndexMap insertion order).
        // The evicted key is dropped, and so wiped, by the end of the condition.
        while self.skipped.len() > self.max_skipped {
            if self.skipped.shift_remove_index(0).is_none() {
                break;
            }
        }
    }
}

// All secret fields wipe themselves when dropped (see the struct's docs).
impl ZeroizeOnDrop for DoubleRatchet {}

/// Rollback copy of `DoubleRatchet` mutable state, used for commit-on-success
/// decryption. Holds secret key material.
///
/// It needs no `Drop` of its own: every secret field wipes itself. So the copy
/// is wiped whichever way `decrypt` ends — the success path, where it is simply
/// dropped, an error, where `restore` moves it back over the state it replaces,
/// and unwinding. (Unwinding relies on the workspace not setting
/// `panic = "abort"`, a `Cargo.toml` profile setting outside this patch.)
struct RatchetSnapshot {
    dhs: StaticSecret,
    dhr: Option<PublicKey>,
    rk: RootKey,
    cks: Option<ChainKey>,
    ckr: Option<ChainKey>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: IndexMap<([u8; 32], u32), MessageKey>,
}

/// Root KDF: `HKDF-SHA256(salt = rk, ikm = dh_out, info = "DoubleRatchet/RootKDF/v1")`
/// split into `(new root key, new chain key)`. Both outputs are wiped on drop.
///
/// The HKDF pseudorandom key is a secret intermediate: `Hkdf::new` would drop
/// it unwiped, so it is taken from `extract` and wiped here. What the `hkdf`,
/// `hmac` and `sha2` crates keep inside their own values (a keyed hasher state,
/// the per-block output of `expand`) has no wiping in those crates and cannot
/// be reached from here.
fn kdf_rk(rk: &[u8; 32], dh_out: &[u8]) -> (RootKey, ChainKey) {
    let (mut prk, hk) = Hkdf::<Sha256>::extract(Some(rk), dh_out);
    prk.as_mut_slice().zeroize();
    let mut okm = Zeroizing::new([0u8; 64]);
    hk.expand(b"DoubleRatchet/RootKDF/v1", &mut okm[..])
        .expect("hkdf expand");
    let mut new_rk = Zeroizing::new([0u8; 32]);
    let mut new_ck = Zeroizing::new([0u8; 32]);
    new_rk.copy_from_slice(&okm[..32]);
    new_ck.copy_from_slice(&okm[32..]);
    (new_rk, new_ck)
}

/// Chain KDF: `new chain key = HMAC-SHA256(ck, 0x02)`, `message key =
/// HMAC-SHA256(ck, 0x01)`. Both outputs are wiped on drop.
fn kdf_ck(ck: &[u8; 32]) -> (ChainKey, MessageKey) {
    let mut new_ck = Zeroizing::new([0u8; 32]);
    let mut mk = Zeroizing::new([0u8; 32]);
    hmac_tag(ck, 0x02, &mut new_ck);
    hmac_tag(ck, 0x01, &mut mk);
    (new_ck, mk)
}

/// `HMAC-SHA256(key, [tag])` written into `out`. The tag is derived secret
/// material, so the `Output` it passes through is wiped once copied.
fn hmac_tag(key: &[u8; 32], tag: u8, out: &mut [u8; 32]) {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac");
    mac.update(&[tag]);
    let mut bytes = mac.finalize().into_bytes();
    out.copy_from_slice(&bytes);
    bytes.as_mut_slice().zeroize();
}

fn aead_encrypt(key: &[u8; 32], plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>, RatchetError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt((&nonce).into(), Payload { msg: plaintext, aad: ad })
        .map_err(|_| RatchetError::Decryption)?;
    let mut out = Vec::with_capacity(NONCE_SIZE + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn aead_decrypt(key: &[u8; 32], ct_with_nonce: &[u8], ad: &[u8]) -> Result<Vec<u8>, RatchetError> {
    if ct_with_nonce.len() < NONCE_SIZE {
        return Err(RatchetError::Decryption);
    }
    let (nonce, ct) = ct_with_nonce.split_at(NONCE_SIZE);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce.into(), Payload { msg: ct, aad: ad })
        .map_err(|_| RatchetError::Decryption)
}

fn concat_ad(ad: &[u8], header_bytes: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(ad.len() + header_bytes.len());
    v.extend_from_slice(ad);
    v.extend_from_slice(header_bytes);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    // (Wipe-on-drop tests are at the end of this module: `secret_fields_wipe_on_drop`
    // and `secret_fields_are_wiping_types`.)

    // ── L-3 FIFO eviction tests ───────────────────────────────────────────────

    #[test]
    fn trim_skipped_fifo_oldest_evicted_newest_retained() {
        let mut dr = DoubleRatchet::init_bob(&[0u8; 32], StaticSecret::random_from_rng(OsRng));
        dr.max_skipped = 3;
        let dhr = [0u8; 32];
        for i in 0u32..5 {
            dr.skipped.insert((dhr, i), Zeroizing::new([i as u8; 32]));
        }
        dr.trim_skipped();
        assert_eq!(dr.skipped.len(), 3, "cap must be enforced");
        assert!(!dr.skipped.contains_key(&(dhr, 0)), "oldest (0) must be evicted");
        assert!(!dr.skipped.contains_key(&(dhr, 1)), "second-oldest (1) must be evicted");
        assert!(dr.skipped.contains_key(&(dhr, 2)), "entry 2 must survive");
        assert!(dr.skipped.contains_key(&(dhr, 3)), "entry 3 must survive");
        assert!(dr.skipped.contains_key(&(dhr, 4)), "newest (4) must survive");
    }

    #[test]
    fn trim_skipped_evicted_value_is_zeroized() {
        // Verify: evicted entry is removed and its slot is gone; retained value is intact.
        // (We cannot read freed memory, so we assert the retained value was NOT zeroed —
        // proof that only the evicted value was touched.)
        let mut dr = DoubleRatchet::init_bob(&[0u8; 32], StaticSecret::random_from_rng(OsRng));
        dr.max_skipped = 1;
        let dhr = [0u8; 32];
        dr.skipped.insert((dhr, 0), Zeroizing::new([0xAB_u8; 32]));
        dr.skipped.insert((dhr, 1), Zeroizing::new([0xCD_u8; 32]));
        dr.trim_skipped();
        assert!(!dr.skipped.contains_key(&(dhr, 0)), "evicted entry removed");
        assert!(dr.skipped.contains_key(&(dhr, 1)), "retained entry present");
        assert_eq!(*dr.skipped[&(dhr, 1)], [0xCD_u8; 32], "retained value must not be zeroized");
    }

    #[test]
    fn trim_skipped_recently_skipped_key_survives_cap() {
        // Scenario: a recently-stored skipped key (needed by a delayed legit message)
        // must survive when older entries fill the cap and are evicted.
        let mut dr = DoubleRatchet::init_bob(&[0u8; 32], StaticSecret::random_from_rng(OsRng));
        dr.max_skipped = 3;
        let dhr = [0u8; 32];
        for i in 0u32..3 {
            dr.skipped.insert((dhr, i), Zeroizing::new([i as u8; 32]));
        }
        let recent_mk = [0xBB_u8; 32];
        dr.skipped.insert((dhr, 3), Zeroizing::new(recent_mk));
        dr.trim_skipped();
        assert_eq!(dr.skipped.len(), 3, "cap enforced");
        assert!(!dr.skipped.contains_key(&(dhr, 0)), "oldest evicted");
        assert!(dr.skipped.contains_key(&(dhr, 3)), "recently-skipped key survived");
        assert_eq!(*dr.skipped[&(dhr, 3)], recent_mk, "recently-skipped key value intact");
    }

    /// Establish a matched Alice/Bob ratchet pair sharing one root key.
    fn established_pair() -> (DoubleRatchet, DoubleRatchet) {
        let root = [7u8; 32];
        let bob_spk = StaticSecret::random_from_rng(OsRng);
        let bob_pk = PublicKey::from(&bob_spk);
        let alice = DoubleRatchet::init_alice(&root, bob_pk);
        let bob = DoubleRatchet::init_bob(&root, bob_spk);
        (alice, bob)
    }

    /// F-1 regression: a forged / unknown-DH message that fails AEAD authentication
    /// must not mutate ratchet state. Without commit-on-success the failed decrypt
    /// performs a DH ratchet step, desyncing the session so the next genuine message
    /// can no longer be decrypted.
    #[test]
    fn forged_unknown_dh_message_does_not_mutate_state() {
        let (mut alice, mut bob) = established_pair();
        let ad = b"assoc";

        // Alice sends a genuine message; Bob has not received it yet.
        let (hdr1, ct1) = alice.encrypt(b"hello", ad).unwrap();

        // Forge a message: unknown DH public key + garbage ciphertext.
        let attacker_dh = *PublicKey::from(&StaticSecret::random_from_rng(OsRng)).as_bytes();
        let forged_hdr = Header {
            dh: attacker_dh,
            pn: 0,
            n: 0,
        };
        let forged_ct = vec![0u8; NONCE_SIZE + 16];

        // Fingerprint Bob's pre-attack state.
        let before_dhr = bob.dhr;
        let before_rk = bob.rk.clone();
        let before_cks = bob.cks.clone();
        let before_ckr = bob.ckr.clone();
        let before_ns = bob.ns;
        let before_nr = bob.nr;
        let before_pn = bob.pn;
        let before_skipped = bob.skipped.len();
        let before_dhs = *PublicKey::from(&bob.dhs).as_bytes();

        // Forged message must fail authentication.
        assert!(bob.decrypt(&forged_hdr, &forged_ct, ad).is_err());

        // State must be untouched by the failed decrypt.
        assert_eq!(bob.dhr, before_dhr, "dhr must not change on failed decrypt");
        assert_eq!(bob.rk, before_rk, "root key must not change");
        assert_eq!(bob.cks, before_cks, "sending chain key must not change");
        assert_eq!(bob.ckr, before_ckr, "receiving chain key must not change");
        assert_eq!(bob.ns, before_ns, "send counter must not change");
        assert_eq!(bob.nr, before_nr, "receive counter must not change");
        assert_eq!(bob.pn, before_pn, "previous-chain counter must not change");
        assert_eq!(bob.skipped.len(), before_skipped, "skipped keys must not change");
        assert_eq!(*PublicKey::from(&bob.dhs).as_bytes(), before_dhs, "dhs must not change");

        // The genuine message still decrypts — proof the session was not desynced.
        let pt = bob.decrypt(&hdr1, &ct1, ad).unwrap();
        assert_eq!(pt, b"hello");

        // Bidirectional check: the forged attempt left the session fully usable in
        // the *other* direction too — Bob can reply and Alice can decrypt it.
        let (hdr2, ct2) = bob.encrypt(b"hi alice", ad).unwrap();
        let pt2 = alice.decrypt(&hdr2, &ct2, ad).unwrap();
        assert_eq!(pt2, b"hi alice");
    }

    /// F-1 regression: the early skipped-key lookup (`skipped.swap_remove`) mutates
    /// `self.skipped` before the AEAD result is known. A forged ciphertext reusing a
    /// legitimately stored skipped key's `(dh, n)` coordinates must fail
    /// authentication without consuming that stored key, and the real delayed
    /// message must still decrypt afterward.
    #[test]
    fn forged_ciphertext_reusing_skipped_key_header_does_not_consume_key() {
        let (mut alice, mut bob) = established_pair();
        let ad = b"assoc";

        // Alice sends three messages on the same sending chain; Bob receives only
        // the third, which forces him to store keys for message 0 and 1 as skipped.
        let (hdr0, ct0) = alice.encrypt(b"zero", ad).unwrap();
        let (_hdr1, _ct1) = alice.encrypt(b"one", ad).unwrap();
        let (hdr2, ct2) = alice.encrypt(b"two", ad).unwrap();

        let pt2 = bob.decrypt(&hdr2, &ct2, ad).unwrap();
        assert_eq!(pt2, b"two");
        assert!(
            bob.skipped.contains_key(&(hdr0.dh, hdr0.n)),
            "message 0's key must have been stored as skipped"
        );
        let before_skipped_len = bob.skipped.len();

        // Attacker knows the header is public (dh, n are sent in cleartext) but not
        // the derived message key, so a forged ciphertext at hdr0's coordinates must
        // fail authentication.
        let forged_ct = vec![0u8; ct0.len()];
        assert!(bob.decrypt(&hdr0, &forged_ct, ad).is_err());

        // The stored skipped key must survive the failed forged attempt.
        assert_eq!(
            bob.skipped.len(),
            before_skipped_len,
            "forged decrypt must not consume the stored skipped key"
        );
        assert!(
            bob.skipped.contains_key(&(hdr0.dh, hdr0.n)),
            "skipped key for message 0 must still be present after the forged attempt"
        );

        // The genuine delayed message must still decrypt using the untouched key.
        let pt0 = bob.decrypt(&hdr0, &ct0, ad).unwrap();
        assert_eq!(pt0, b"zero");
    }

    #[test]
    fn only_an_untouched_responder_is_in_the_initial_responder_state() {
        let (mut alice, mut bob) = established_pair();
        assert!(bob.is_initial_responder_state());
        assert!(!alice.is_initial_responder_state(), "initiator has dhr and cks");

        // A refused encrypt and a forged message leave it untouched.
        assert!(matches!(bob.encrypt(b"x", b"ad"), Err(RatchetError::NotInitialized)));
        let forged = Header { dh: [7u8; 32], pn: 0, n: 0 };
        assert!(bob.decrypt(&forged, &[0u8; NONCE_SIZE + 16], b"ad").is_err());
        assert!(bob.is_initial_responder_state());

        // One authenticated message ends it for good.
        let (h, c) = alice.encrypt(b"hi", b"ad").unwrap();
        bob.decrypt(&h, &c, b"ad").unwrap();
        assert!(!bob.is_initial_responder_state());

        // Each field on its own disqualifies an otherwise initial state.
        type Mutate = fn(&mut DoubleRatchet);
        let cases: [(&str, Mutate); 7] = [
            ("dhr", |r| r.dhr = Some(PublicKey::from([9u8; 32]))),
            ("cks", |r| r.cks = Some(Zeroizing::new([1u8; 32]))),
            ("ckr", |r| r.ckr = Some(Zeroizing::new([1u8; 32]))),
            ("ns", |r| r.ns = 1),
            ("nr", |r| r.nr = 1),
            ("pn", |r| r.pn = 1),
            ("skipped", |r| {
                r.skipped.insert(([0u8; 32], 0), Zeroizing::new([0u8; 32]));
            }),
        ];
        for (field, mutate) in cases {
            let mut r = DoubleRatchet::init_bob(&[3u8; 32], StaticSecret::random_from_rng(OsRng));
            mutate(&mut r);
            assert!(!r.is_initial_responder_state(), "{field} set");
        }
    }

    // ── Compatibility with the implementation before A-3 ─────────────────────
    //
    // The values below were produced by the code at `ef6426d` (before secrets
    // were moved into wiping types) and pasted here. The KDFs are
    // deterministic, so their outputs must be byte-identical; the ratchet
    // fixture is a conversation whose keys, ciphertexts and checkpoints were
    // written by that code and must still decrypt, in the same order, to the
    // same plaintexts and the same deterministic state.

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn chain_and_root_kdfs_match_the_previous_implementation() {
        let (new_ck, mk) = kdf_ck(&[0x11u8; 32]);
        assert_eq!(
            hex(&*new_ck),
            "ed50b271f4852277c8218e209858d8bd32a3228a9e4fb6b5a16fb9b4755c53bc"
        );
        assert_eq!(
            hex(&*mk),
            "c4ede064b5f2a51225b2175e5b84fb73f9cec689ac3d912ac4878f7ebeab0149"
        );
        let dh: Vec<u8> = (0u8..32).collect();
        let (new_rk, new_ck) = kdf_rk(&[0x22u8; 32], &dh);
        assert_eq!(
            hex(&*new_rk),
            "f9787207e897ea341808d38c1f70522284ca6608b97fd0f91eb03b8096477d55"
        );
        assert_eq!(
            hex(&*new_ck),
            "5f8bea3797a47abad1f9547a112d9ecbd0b7b3920b1da857930ad5c77af84356"
        );
    }

    // Fixture from the previous implementation: Alice's state and four of her
    // messages (plaintexts `m0`..`m3`, AD `kat-ad`), and Bob's initial state.
    const ALICE_CHECKPOINT: &str = concat!(
        "0103038ea0aceeb9abf8228443c0cdb80393b0654d878030bdc6aa28ad3e2878",
        "2bc680e1a53d3eee82b62b3048578cf38c980ddd1131243a1047fe48482942d6",
        "b64888cd605d2c61d7a0bcdb3b06d33e9ea562be8becd9ae58bb93b1c2404863",
        "a74a672a7eaedaa83e634d013f57389f9a32e78f4ccfa4467c4cff291f445381",
        "21ec000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000007d000000000"
    );
    const BOB_CHECKPOINT: &str = concat!(
        "0100b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0",
        "b0b0000000000000000000000000000000000000000000000000000000000000",
        "00005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
        "5a5a000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000007d000000000"
    );
    const MSG0_HEADER: &str = concat!(
        "b8494eefa99ba3b72d593648020fd71e75b6b031b0ad6afccc258b2fcc762612",
        "0000000000000000"
    );
    const MSG0_CIPHERTEXT: &str = concat!(
        "ae624e28ec92b32d23a78576094257f2ec28e3b4ab9b3dd3d0c0f1d16987facd",
        "2a9b64204a4638a307be"
    );
    const MSG1_HEADER: &str = concat!(
        "b8494eefa99ba3b72d593648020fd71e75b6b031b0ad6afccc258b2fcc762612",
        "0000000000000001"
    );
    const MSG1_CIPHERTEXT: &str = concat!(
        "8642aa9d44cd388198a2c0b8012ac1652748409ed7ad88a01cc3748f2b9f88e3",
        "830f499fef6776a90999"
    );
    const MSG2_HEADER: &str = concat!(
        "b8494eefa99ba3b72d593648020fd71e75b6b031b0ad6afccc258b2fcc762612",
        "0000000000000002"
    );
    const MSG2_CIPHERTEXT: &str = concat!(
        "c7863300686b9cb1487ad47af9104e7a96db876f351a49a81a2e70d9998b6c69",
        "64c5fee176238d28e1cf"
    );
    const MSG3_HEADER: &str = concat!(
        "b8494eefa99ba3b72d593648020fd71e75b6b031b0ad6afccc258b2fcc762612",
        "0000000000000003"
    );
    const MSG3_CIPHERTEXT: &str = concat!(
        "653983bc2d2aee3f31976cfbdc085bc79dec9126bd1b1f580a1d4351abadbaca",
        "10e2bc4c57863e4d4604"
    );

    fn fixture_message(header: &str, ciphertext: &str) -> (Header, Vec<u8>) {
        (
            Header::from_bytes(&unhex(header)).unwrap(),
            unhex(ciphertext),
        )
    }

    /// Bob, restored from a checkpoint the previous implementation wrote,
    /// decrypts messages it produced: message 2 first (a DH ratchet step that
    /// skips 0 and 1), then the two skipped ones, then 3. Every plaintext,
    /// the receiving chain key, the counters and each skipped key match what
    /// the previous implementation computed for the same input.
    #[test]
    fn a_conversation_written_by_the_previous_implementation_still_decrypts() {
        let ad = unhex("6b61742d6164");
        let mut bob = DoubleRatchet::from_checkpoint(&unhex(BOB_CHECKPOINT)).unwrap();
        let msgs = [
            fixture_message(MSG0_HEADER, MSG0_CIPHERTEXT),
            fixture_message(MSG1_HEADER, MSG1_CIPHERTEXT),
            fixture_message(MSG2_HEADER, MSG2_CIPHERTEXT),
            fixture_message(MSG3_HEADER, MSG3_CIPHERTEXT),
        ];
        // (message, plaintext, ckr, nr, pn, dhr, skipped as "dh:n:mk,...")
        let expected: [(usize, &str, &str, u32, u32, &str, &str); 4] = [
            (2, "6d32", "a8ebb09bd83b9050a7fc83f323a99762efa76185e6e6c80f3ec31e1868fcfb9f", 3, 0, "b8494eefa99ba3b72d593648020fd71e75b6b031b0ad6afccc258b2fcc762612", "b8494eefa99ba3b72d593648020fd71e75b6b031b0ad6afccc258b2fcc762612:0:282c873d6bfde80b15f017180859d9e9c478bf88a8660a2178dea428fa7f7bef,b8494eefa99ba3b72d593648020fd71e75b6b031b0ad6afccc258b2fcc762612:1:9bfe678d52c7a1934257b8d48d87bbc7b2a6d2368d161c65acc18b6cb1109d6f"),
            (0, "6d30", "a8ebb09bd83b9050a7fc83f323a99762efa76185e6e6c80f3ec31e1868fcfb9f", 3, 0, "b8494eefa99ba3b72d593648020fd71e75b6b031b0ad6afccc258b2fcc762612", "b8494eefa99ba3b72d593648020fd71e75b6b031b0ad6afccc258b2fcc762612:1:9bfe678d52c7a1934257b8d48d87bbc7b2a6d2368d161c65acc18b6cb1109d6f"),
            (1, "6d31", "a8ebb09bd83b9050a7fc83f323a99762efa76185e6e6c80f3ec31e1868fcfb9f", 3, 0, "b8494eefa99ba3b72d593648020fd71e75b6b031b0ad6afccc258b2fcc762612", ""),
            (3, "6d33", "5f0dde7d6d693dccc250077f81fd958b9f6dd0247a2ca30da53aa9c54eb28275", 4, 0, "b8494eefa99ba3b72d593648020fd71e75b6b031b0ad6afccc258b2fcc762612", ""),
        ];
        for (i, pt, ckr, nr, pn, dhr, skipped) in expected {
            let (h, c) = &msgs[i];
            assert_eq!(hex(&bob.decrypt(h, c, &ad).unwrap()), pt, "message {i}");
            assert_eq!(hex(&**bob.ckr.as_ref().unwrap()), ckr, "ckr after {i}");
            assert_eq!((bob.nr, bob.pn), (nr, pn), "counters after {i}");
            assert_eq!(hex(bob.dhr.unwrap().as_bytes()), dhr, "dhr after {i}");
            let held: Vec<String> = bob
                .skipped
                .iter()
                .map(|((dh, n), mk)| format!("{}:{}:{}", hex(dh), n, hex(&**mk)))
                .collect();
            assert_eq!(held.join(","), skipped, "skipped keys after {i}");
        }
    }

    /// The previous implementation's Alice state (a checkpoint it wrote) is
    /// accepted, and re-encoding it yields the same bytes.
    #[test]
    fn a_checkpoint_written_by_the_previous_implementation_round_trips_byte_for_byte() {
        for record in [ALICE_CHECKPOINT, BOB_CHECKPOINT] {
            let bytes = unhex(record);
            let ratchet = DoubleRatchet::from_checkpoint(&bytes).unwrap();
            assert_eq!(*ratchet.to_checkpoint().unwrap(), bytes);
        }
    }

    /// Both directions across a DH ratchet, starting from states the previous
    /// implementation wrote: Bob reads Alice's message 0, answers, Alice reads
    /// the answer and sends again, and Bob reads that.
    #[test]
    fn a_restored_previous_state_keeps_conversing_in_both_directions() {
        let ad = unhex("6b61742d6164");
        let mut alice = DoubleRatchet::from_checkpoint(&unhex(ALICE_CHECKPOINT)).unwrap();
        let mut bob = DoubleRatchet::from_checkpoint(&unhex(BOB_CHECKPOINT)).unwrap();
        let (h0, c0) = fixture_message(MSG0_HEADER, MSG0_CIPHERTEXT);
        assert_eq!(bob.decrypt(&h0, &c0, &ad).unwrap(), b"m0");
        let (h, c) = bob.encrypt(b"reply", &ad).unwrap();
        assert_eq!(alice.decrypt(&h, &c, &ad).unwrap(), b"reply");
        let (h, c) = alice.encrypt(b"again", &ad).unwrap();
        assert_eq!(bob.decrypt(&h, &c, &ad).unwrap(), b"again");
    }

    // ── Secrets are held in wiping types ─────────────────────────────────────

    fn is_wiping<T: ZeroizeOnDrop>(_: &T) {}

    /// Compile-time pin: every 32-byte secret a ratchet holds, and every key a
    /// KDF returns, is a type that wipes itself when dropped. Turning one of
    /// them back into a plain `[u8; 32]` stops this test from compiling.
    ///
    /// `dhs` is a `StaticSecret`, which wipes on drop through its own generated
    /// `Drop` but does not implement the `ZeroizeOnDrop` marker, so it cannot be
    /// pinned here; `secret_fields_wipe_on_drop` checks it by observing it.
    #[test]
    fn secret_fields_are_wiping_types() {
        let (alice, _) = established_pair();
        is_wiping(&alice);
        is_wiping(&alice.rk);
        if let Some(k) = &alice.cks {
            is_wiping(k);
        }
        if let Some(k) = &alice.ckr {
            is_wiping(k);
        }
        for mk in alice.skipped.values() {
            is_wiping(mk);
        }
        let (a, b) = kdf_ck(&[1u8; 32]);
        is_wiping(&a);
        is_wiping(&b);
        let (a, b) = kdf_rk(&[1u8; 32], &[2u8; 32]);
        is_wiping(&a);
        is_wiping(&b);
    }

    /// Dropping a ratchet wipes the secret keys it holds inline.
    ///
    /// This inspects memory only while it is still allocated: the ratchet is
    /// dropped in place inside a `MaybeUninit` local, whose storage outlives
    /// the drop, and only plain fixed-size key arrays are read back. Nothing is
    /// read from freed memory, and the heap-allocated skipped-key map (freed by
    /// the drop) is not touched. What this shows is that the drop glue of the
    /// field types zeroes their bytes; it says nothing about copies elsewhere.
    #[test]
    fn secret_fields_wipe_on_drop() {
        use std::mem::MaybeUninit;
        use std::ptr::{addr_of, drop_in_place, read};

        let mut ratchet = DoubleRatchet::init_bob(&[0xA1; 32], StaticSecret::from([0xA2; 32]));
        ratchet.cks = Some(Zeroizing::new([0xA3; 32]));
        ratchet.ckr = Some(Zeroizing::new([0xA4; 32]));
        ratchet
            .skipped
            .insert(([0; 32], 0), Zeroizing::new([0xA5; 32]));
        assert_eq!(*ratchet.rk, [0xA1; 32], "precondition");

        let mut slot = MaybeUninit::new(ratchet);
        let p = slot.as_mut_ptr();
        // SAFETY: `slot` holds an initialised `DoubleRatchet`, dropped exactly
        // once here and never used as a whole afterwards.
        unsafe { drop_in_place(p) };
        // SAFETY: `slot` is a live local, so its storage is allocated. The four
        // fields read are inline arrays (or an `Option` of one) that dropping
        // only overwrites with zeroes, so every value read is a valid,
        // initialised value of its type.
        let (dhs, rk, cks, ckr) = unsafe {
            (
                read(addr_of!((*p).dhs)),
                read(addr_of!((*p).rk)),
                read(addr_of!((*p).cks)),
                read(addr_of!((*p).ckr)),
            )
        };
        assert_eq!(dhs.as_bytes(), &[0u8; 32], "dhs wiped");
        assert_eq!(*rk, [0u8; 32], "rk wiped");
        assert_eq!(cks, Some(Zeroizing::new([0u8; 32])), "cks wiped");
        assert_eq!(ckr, Some(Zeroizing::new([0u8; 32])), "ckr wiped");
    }

    /// A skipped key is used once: consuming it removes the entry, its key is
    /// wiped as the removed value is dropped, and the same message cannot be
    /// decrypted a second time.
    #[test]
    fn a_consumed_skipped_key_is_gone_and_cannot_decrypt_again() {
        let (mut alice, mut bob) = established_pair();
        let ad = b"assoc";
        let (h0, c0) = alice.encrypt(b"zero", ad).unwrap();
        let (h1, c1) = alice.encrypt(b"one", ad).unwrap();
        assert_eq!(bob.decrypt(&h1, &c1, ad).unwrap(), b"one");
        assert!(
            bob.skipped.contains_key(&(h0.dh, h0.n)),
            "message 0 was skipped"
        );

        assert_eq!(bob.decrypt(&h0, &c0, ad).unwrap(), b"zero");
        assert!(bob.skipped.is_empty(), "the consumed key is removed");
        assert!(
            bob.decrypt(&h0, &c0, ad).is_err(),
            "a replay finds no key and does not decrypt"
        );
        assert!(
            bob.skipped.is_empty(),
            "the failed replay restored the state"
        );
    }

    // ── Where key containers end (instrumented) ─────────────────────────────
    //
    // These tests run with the counting stand-in in `probe` in place of
    // `Zeroizing`. They check that the code drops key containers where it says
    // it does, not that memory is cleared: that is `zeroize`'s job.

    use super::probe::{live_keys, start_block_log, start_log, take_block_log, take_log};

    /// 32-byte key containers a ratchet holds as state.
    fn held(r: &DoubleRatchet) -> isize {
        1 + r.cks.is_some() as isize + r.ckr.is_some() as isize + r.skipped.len() as isize
    }

    /// Runs `op` on `r` and checks that every key container it created and the
    /// state does not hold has been dropped by the time it returns.
    fn no_leftover<R>(
        r: &mut DoubleRatchet,
        what: &str,
        op: impl FnOnce(&mut DoubleRatchet) -> R,
    ) -> R {
        let (live0, held0) = (live_keys(), held(r));
        let out = op(r);
        assert_eq!(
            live_keys() - live0,
            held(r) - held0,
            "{what}: a key container outlived the operation"
        );
        out
    }

    /// After each operation returns, the only live key containers are the ones
    /// the ratchet state holds: no message key, chain key, rollback copy or
    /// KDF output is still alive.
    #[test]
    fn no_temporary_key_outlives_an_operation() {
        let (mut alice, mut bob) = established_pair();
        let ad = b"assoc";
        let mut sent = Vec::new();
        for i in 0..3u8 {
            sent.push(no_leftover(&mut alice, "encrypt", |r| {
                r.encrypt(&[i], ad).unwrap()
            }));
        }

        // First receive: a DH ratchet step and two skipped keys.
        let (h2, c2) = &sent[2];
        no_leftover(&mut bob, "decrypt with a DH step and skipped keys", |r| {
            assert_eq!(r.decrypt(h2, c2, ad).unwrap(), [2]);
        });
        assert_eq!(bob.skipped.len(), 2);
        // A skipped key is consumed.
        let (h0, c0) = &sent[0];
        no_leftover(&mut bob, "decrypt consuming a skipped key", |r| {
            assert_eq!(r.decrypt(h0, c0, ad).unwrap(), [0]);
        });
        // Bob replies, and Alice takes a DH step of her own.
        let (hr, cr) = no_leftover(&mut bob, "encrypt after a DH step", |r| {
            r.encrypt(b"r", ad).unwrap()
        });
        no_leftover(&mut alice, "decrypt with a DH step", |r| {
            assert_eq!(r.decrypt(&hr, &cr, ad).unwrap(), b"r");
        });

        // Failures roll back and leave nothing behind.
        let forged = Header {
            dh: [7u8; 32],
            pn: 0,
            n: 0,
        };
        no_leftover(&mut bob, "decrypt of an unknown DH key", |r| {
            assert!(r.decrypt(&forged, &[0u8; NONCE_SIZE + 16], ad).is_err());
        });
        let (h1, c1) = &sent[1];
        let mut tampered = c1.clone();
        *tampered.last_mut().unwrap() ^= 1;
        no_leftover(
            &mut bob,
            "decrypt failing authentication on a skipped key",
            |r| {
                assert!(r.decrypt(h1, &tampered, ad).is_err());
            },
        );
        no_leftover(&mut bob, "decrypt of a replay", |r| {
            assert!(r.decrypt(h0, c0, ad).is_err());
        });
    }

    /// Copies of a ratchet — for staging and from a checkpoint — hold exactly
    /// the keys of the state they copy, and give all of them back when dropped,
    /// including when decoding a checkpoint fails part way.
    #[test]
    fn copies_and_restores_give_every_key_back() {
        let (mut alice, mut bob) = established_pair();
        let ad = b"assoc";
        let sent: Vec<_> = (0..3u8).map(|i| alice.encrypt(&[i], ad).unwrap()).collect();
        bob.decrypt(&sent[2].0, &sent[2].1, ad).unwrap();
        assert_eq!(bob.skipped.len(), 2);

        let live0 = live_keys();
        let copy = bob.staged_copy();
        assert_eq!(
            live_keys() - live0,
            held(&copy),
            "a staged copy holds the same keys"
        );
        drop(copy);
        assert_eq!(live_keys(), live0, "dropping the copy returns them all");

        let record = bob.to_checkpoint().unwrap();
        let back = DoubleRatchet::from_checkpoint(&record).unwrap();
        assert_eq!(
            live_keys() - live0,
            held(&back),
            "a restored ratchet holds the same keys"
        );
        drop(back);
        assert_eq!(live_keys(), live0);

        // Second skipped entry made a duplicate of the first: decoding builds
        // the ratchet, then refuses it. Everything it made must go.
        let mut broken = record.to_vec();
        let (first, second) = (182, 182 + 68);
        broken.copy_within(first..first + 36, second);
        assert!(matches!(
            DoubleRatchet::from_checkpoint(&broken),
            Err(CheckpointError::DuplicateSkippedKey)
        ));
        assert_eq!(
            live_keys(),
            live0,
            "a refused checkpoint leaves no key alive"
        );
    }

    /// The message key of an `encrypt` and the chain key it replaces are dropped
    /// (and so wiped) when `encrypt` returns; the new chain key is state and is
    /// not.
    #[test]
    fn encrypt_wipes_the_message_key_and_the_replaced_chain_key() {
        let (mut alice, _) = established_pair();
        let old_ck: [u8; 32] = **alice.cks.as_ref().unwrap();
        let (new_ck, mk) = kdf_ck(&old_ck);
        let (new_ck, mk): ([u8; 32], [u8; 32]) = (*new_ck, *mk);

        start_log();
        alice.encrypt(b"x", b"ad").unwrap();
        let log = take_log();

        assert_eq!(log.iter().filter(|k| **k == mk).count(), 1, "message key");
        assert_eq!(
            log.iter().filter(|k| **k == old_ck).count(),
            1,
            "replaced chain key"
        );
        assert_eq!(
            log.iter().filter(|k| **k == new_ck).count(),
            0,
            "new chain key is live"
        );
        assert_eq!(**alice.cks.as_ref().unwrap(), new_ck);
    }

    /// The keys Alice's messages use, in order, from her current chain.
    fn message_keys(alice: &DoubleRatchet, n: usize) -> Vec<[u8; 32]> {
        let mut ck: [u8; 32] = **alice.cks.as_ref().unwrap();
        (0..n)
            .map(|_| {
                let (next, mk) = kdf_ck(&ck);
                ck = *next;
                *mk
            })
            .collect()
    }

    /// Consuming a skipped key wipes it; a skipped key that is not consumed is
    /// still held and is not wiped.
    ///
    /// A `decrypt` also keeps a rollback copy of the state, and that copy is
    /// dropped (wiped) when the call returns. So a key that was held before the
    /// call is dropped once through the copy, and once more if it is consumed.
    #[test]
    fn consuming_a_skipped_key_wipes_it_and_only_it() {
        let (mut alice, mut bob) = established_pair();
        let ad = b"assoc";
        let mks = message_keys(&alice, 3);
        let sent: Vec<_> = (0..3u8).map(|i| alice.encrypt(&[i], ad).unwrap()).collect();
        bob.decrypt(&sent[2].0, &sent[2].1, ad).unwrap();
        assert_eq!(bob.skipped.len(), 2, "keys 0 and 1 are skipped");

        start_log();
        bob.decrypt(&sent[0].0, &sent[0].1, ad).unwrap();
        let log = take_log();
        let times = |k: &[u8; 32]| log.iter().filter(|x| *x == k).count();

        assert_eq!(
            times(&mks[0]),
            2,
            "consumed: its rollback copy and the key itself"
        );
        assert_eq!(times(&mks[1]), 1, "kept: only its rollback copy");
        assert_eq!(bob.skipped.len(), 1);
        assert_eq!(
            *bob.skipped[&(sent[1].0.dh, 1)],
            mks[1],
            "the kept key is intact"
        );
    }

    /// An evicted skipped key is wiped when it is evicted; the ones that fit
    /// stay held.
    #[test]
    fn evicting_a_skipped_key_wipes_it() {
        let (mut alice, mut bob) = established_pair();
        bob.max_skipped = 1;
        let ad = b"assoc";
        let mks = message_keys(&alice, 4);
        let sent: Vec<_> = (0..4u8).map(|i| alice.encrypt(&[i], ad).unwrap()).collect();

        start_log();
        assert_eq!(bob.decrypt(&sent[3].0, &sent[3].1, ad).unwrap(), [3]);
        let log = take_log();
        let times = |k: &[u8; 32]| log.iter().filter(|x| *x == k).count();

        assert_eq!(bob.skipped.len(), 1, "room for one skipped key");
        assert_eq!(times(&mks[0]), 1, "evicted first");
        assert_eq!(times(&mks[1]), 1, "evicted second");
        assert_eq!(times(&mks[2]), 0, "kept, still held");
        assert_eq!(
            times(&mks[3]),
            1,
            "the message key of the decrypted message"
        );
        assert_eq!(*bob.skipped[&(sent[2].0.dh, 2)], mks[2]);
    }

    /// The 64-byte block the root KDF expands into (new root key || new chain
    /// key) is dropped, and so wiped, before `kdf_rk` returns; only its two
    /// halves leave, each in a container of its own.
    #[test]
    fn the_root_kdf_output_block_is_dropped_before_it_returns() {
        let (rk, dh_out) = ([1u8; 32], [2u8; 32]);

        start_block_log();
        let live0 = live_keys();
        let (new_rk, new_ck) = kdf_rk(&rk, &dh_out);
        let log = take_block_log();

        assert_eq!(live_keys() - live0, 2, "only the two halves stay alive");
        assert_eq!(log.len(), 1, "one output block, dropped once");
        assert_eq!(log[0][..32], new_rk[..]);
        assert_eq!(log[0][32..], new_ck[..]);
    }
}
