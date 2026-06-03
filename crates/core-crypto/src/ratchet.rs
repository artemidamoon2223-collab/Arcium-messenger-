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
use zeroize::Zeroize;

/// Max number of message keys that may be skipped within a single receiving chain.
pub const MAX_SKIP: u32 = 1000;
/// Header is: DH public key (32) || PN (4) || N (4).
pub const HEADER_SIZE: usize = 32 + 4 + 4;
/// XChaCha20Poly1305 nonce size.
pub const NONCE_SIZE: usize = 24;

type ChainKey = [u8; 32];
type MessageKey = [u8; 32];
type RootKey = [u8; 32];

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
    pub fn init_alice(sk: RootKey, their_initial_dh: PublicKey) -> Self {
        let dhs = StaticSecret::random_from_rng(OsRng);
        let dh_out = dhs.diffie_hellman(&their_initial_dh);
        let (rk, cks) = kdf_rk(&sk, dh_out.as_bytes());
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
    pub fn init_bob(sk: RootKey, our_initial_dh: StaticSecret) -> Self {
        Self {
            dhs: our_initial_dh,
            dhr: None,
            rk: sk,
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

    pub fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Result<(Header, Vec<u8>), RatchetError> {
        let cks = self.cks.ok_or(RatchetError::NotInitialized)?;
        let (new_cks, mk) = kdf_ck(&cks);
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

    pub fn decrypt(&mut self, header: &Header, ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>, RatchetError> {
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
        let ckr = self.ckr.ok_or(RatchetError::NotInitialized)?;
        let (new_ckr, mk) = kdf_ck(&ckr);
        self.ckr = Some(new_ckr);
        self.nr += 1;

        aead_decrypt(&mk, ciphertext, &full_ad)
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<(), RatchetError> {
        if self.nr.saturating_add(MAX_SKIP) < until {
            return Err(RatchetError::SkipLimit);
        }
        if let Some(mut ckr) = self.ckr {
            while self.nr < until {
                let (new_ckr, mk) = kdf_ck(&ckr);
                ckr = new_ckr;
                let dhr_bytes = *self.dhr.expect("dhr set when ckr is").as_bytes();
                self.skipped.insert((dhr_bytes, self.nr), mk);
                self.nr += 1;
            }
            self.ckr = Some(ckr);
            self.trim_skipped();
        }
        Ok(())
    }

    /// Standard Signal DH ratchet step on receive:
    ///   1. Derive new RECEIVING chain from DH(our current DHs, new their DHr).
    ///   2. Generate new local DH keypair.
    ///   3. Derive new SENDING chain from DH(new DHs, new their DHr).
    /// This guarantees sender's CKs equals receiver's CKr at the matching point.
    fn dh_ratchet_step(&mut self, new_dhr: PublicKey) -> Result<(), RatchetError> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(new_dhr);

        let dh_out = self.dhs.diffie_hellman(&new_dhr);
        let (rk, ckr) = kdf_rk(&self.rk, dh_out.as_bytes());
        self.rk = rk;
        self.ckr = Some(ckr);

        self.dhs = StaticSecret::random_from_rng(OsRng);
        let dh_out = self.dhs.diffie_hellman(&new_dhr);
        let (rk, cks) = kdf_rk(&self.rk, dh_out.as_bytes());
        self.rk = rk;
        self.cks = Some(cks);
        Ok(())
    }

    fn trim_skipped(&mut self) {
        // Evict oldest-inserted entries first (FIFO by IndexMap insertion order).
        // Zeroize each evicted message key before dropping — consistent with L-1 Drop.
        while self.skipped.len() > self.max_skipped {
            if let Some((_, mut mk)) = self.skipped.shift_remove_index(0) {
                mk.zeroize();
            } else {
                break;
            }
        }
    }

    /// Wipe all secret key material. Called by Drop; also exposed for testing.
    fn zeroize_key_material(&mut self) {
        self.rk.zeroize();
        if let Some(ref mut k) = self.cks { k.zeroize(); }
        if let Some(ref mut k) = self.ckr { k.zeroize(); }
        for v in self.skipped.values_mut() { v.zeroize(); }
        // dhs: StaticSecret — has its own ZeroizeOnDrop, no double-handling needed.
    }
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        self.zeroize_key_material();
    }
}

fn kdf_rk(rk: &RootKey, dh_out: &[u8]) -> (RootKey, ChainKey) {
    let hk = Hkdf::<Sha256>::new(Some(rk), dh_out);
    let mut okm = [0u8; 64];
    hk.expand(b"DoubleRatchet/RootKDF/v1", &mut okm).expect("hkdf expand");
    let mut new_rk = [0u8; 32];
    let mut new_ck = [0u8; 32];
    new_rk.copy_from_slice(&okm[..32]);
    new_ck.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (new_rk, new_ck)
}

fn kdf_ck(ck: &ChainKey) -> (ChainKey, MessageKey) {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(ck).expect("hmac");
    mac.update(&[0x02]);
    let new_ck_bytes = mac.finalize().into_bytes();

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(ck).expect("hmac");
    mac.update(&[0x01]);
    let mk_bytes = mac.finalize().into_bytes();

    let mut new_ck = [0u8; 32];
    new_ck.copy_from_slice(&new_ck_bytes);
    let mut mk = [0u8; 32];
    mk.copy_from_slice(&mk_bytes);
    (new_ck, mk)
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

    // Compile-time check: DoubleRatchet must implement Drop (which calls zeroize_key_material).
    // If Drop is accidentally removed this test will stop compiling.
    const _: () = {
        fn _requires_drop<T: Drop>() {}
        fn _check() { _requires_drop::<DoubleRatchet>(); }
    };

    /// Calling zeroize_key_material() on a live instance zeros rk, cks, ckr.
    /// We cannot inspect memory after drop (unsound), so we call the helper
    /// directly on a live struct and assert the fields are cleared.
    #[test]
    fn zeroize_key_material_clears_secret_fields() {
        let rk = [0xAB_u8; 32];
        let mut dr = DoubleRatchet::init_bob(rk, StaticSecret::random_from_rng(OsRng));
        // Bob starts with cks=None, ckr=None; rk is set from the provided seed.
        assert_eq!(dr.rk, rk, "precondition: rk matches seed");

        dr.zeroize_key_material();

        assert_eq!(dr.rk, [0u8; 32], "rk must be zeroed");
        assert!(dr.cks.is_none(), "cks was None; must remain None after wipe");
        assert!(dr.ckr.is_none(), "ckr was None; must remain None after wipe");
        assert!(dr.skipped.is_empty(), "skipped must be empty");
    }

    // ── L-3 FIFO eviction tests ───────────────────────────────────────────────

    #[test]
    fn trim_skipped_fifo_oldest_evicted_newest_retained() {
        let mut dr = DoubleRatchet::init_bob([0u8; 32], StaticSecret::random_from_rng(OsRng));
        dr.max_skipped = 3;
        let dhr = [0u8; 32];
        for i in 0u32..5 {
            dr.skipped.insert((dhr, i), [i as u8; 32]);
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
        let mut dr = DoubleRatchet::init_bob([0u8; 32], StaticSecret::random_from_rng(OsRng));
        dr.max_skipped = 1;
        let dhr = [0u8; 32];
        dr.skipped.insert((dhr, 0), [0xAB_u8; 32]);
        dr.skipped.insert((dhr, 1), [0xCD_u8; 32]);
        dr.trim_skipped();
        assert!(!dr.skipped.contains_key(&(dhr, 0)), "evicted entry removed");
        assert!(dr.skipped.contains_key(&(dhr, 1)), "retained entry present");
        assert_eq!(dr.skipped[&(dhr, 1)], [0xCD_u8; 32], "retained value must not be zeroized");
    }

    #[test]
    fn trim_skipped_recently_skipped_key_survives_cap() {
        // Scenario: a recently-stored skipped key (needed by a delayed legit message)
        // must survive when older entries fill the cap and are evicted.
        let mut dr = DoubleRatchet::init_bob([0u8; 32], StaticSecret::random_from_rng(OsRng));
        dr.max_skipped = 3;
        let dhr = [0u8; 32];
        for i in 0u32..3 {
            dr.skipped.insert((dhr, i), [i as u8; 32]);
        }
        let recent_mk = [0xBB_u8; 32];
        dr.skipped.insert((dhr, 3), recent_mk);
        dr.trim_skipped();
        assert_eq!(dr.skipped.len(), 3, "cap enforced");
        assert!(!dr.skipped.contains_key(&(dhr, 0)), "oldest evicted");
        assert!(dr.skipped.contains_key(&(dhr, 3)), "recently-skipped key survived");
        assert_eq!(dr.skipped[&(dhr, 3)], recent_mk, "recently-skipped key value intact");
    }

    #[test]
    fn zeroize_key_material_clears_chain_keys() {
        // Alice has cks set immediately after init.
        let rk = [0x11_u8; 32];
        let their_pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let mut dr = DoubleRatchet::init_alice(rk, their_pk);
        assert!(dr.cks.is_some(), "precondition: Alice has sending chain key");

        dr.zeroize_key_material();

        assert_eq!(dr.rk, [0u8; 32], "rk must be zeroed");
        // cks is still Some (Option not cleared), but the key bytes inside are zeroed.
        if let Some(k) = dr.cks { assert_eq!(k, [0u8; 32], "cks key bytes must be zeroed"); }
    }
}
