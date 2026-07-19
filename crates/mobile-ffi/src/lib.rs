use core_crypto::ratchet::{DoubleRatchet, Header, RatchetError, HEADER_SIZE};
use core_crypto::x3dh::{x3dh_initiate, x3dh_respond, PrekeyBundle, X3dhError};
use core_protocol::{Session, SessionManager};
use core_storage::{EncryptedStore, StorageError};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

#[derive(Debug, Error, uniffi::Error)]
pub enum CoreError {
    #[error("storage error: {msg}")]
    Storage { msg: String },
    #[error("invalid master key: {msg}")]
    InvalidKey { msg: String },
    #[error("handshake error: {msg}")]
    Handshake { msg: String },
    #[error("no session for id {session_id}")]
    NoSession { session_id: u64 },
    #[error("ratchet error: {msg}")]
    Crypto { msg: String },
}

impl From<StorageError> for CoreError {
    fn from(e: StorageError) -> Self {
        CoreError::Storage { msg: e.to_string() }
    }
}

impl From<X3dhError> for CoreError {
    fn from(e: X3dhError) -> Self {
        CoreError::Handshake { msg: e.to_string() }
    }
}

impl From<RatchetError> for CoreError {
    fn from(e: RatchetError) -> Self {
        CoreError::Crypto { msg: e.to_string() }
    }
}

// ── Identity ──────────────────────────────────────────────────────────────────

#[derive(uniffi::Object)]
pub struct Identity {
    signing_key: SigningKey,
    dh_key: StaticSecret,
}

#[uniffi::export]
impl Identity {
    #[uniffi::constructor]
    pub fn generate() -> Arc<Self> {
        Arc::new(Self {
            signing_key: SigningKey::generate(&mut OsRng),
            dh_key: StaticSecret::random_from_rng(OsRng),
        })
    }

    /// Returns the 32-byte Ed25519 verifying (public) key.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }

    /// Returns the 32-byte X25519 DH public key (used for X3DH key agreement).
    /// Distinct from `public_key_bytes()`, which is the Ed25519 signing key.
    pub fn dh_public_key_bytes(&self) -> Vec<u8> {
        PublicKey::from(&self.dh_key).as_bytes().to_vec()
    }
}

// ── ArciumCore ────────────────────────────────────────────────────────────────

const IDENTITY_KEY: &str = "identity/v1";
const PREKEYS_KEY: &str = "prekeys/v1";

/// Wire layout of a persisted prekey record:
///   signed_prekey_sk(32) || signature(64) || has_otp(1) || [otp_sk(32)]
/// The signature is computed once, at `establish_prekeys` time, over the
/// signed-prekey's public bytes with the identity's signing key, and
/// persisted alongside the secret — so `export_prekey_bundle` never needs to
/// re-sign anything; it only reads what's already there (D3).
fn pack_prekeys(signed_sk: &StaticSecret, signature: &Signature, otp_sk: Option<&StaticSecret>) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(32 + 64 + 1 + 32));
    out.extend_from_slice(&signed_sk.to_bytes());
    out.extend_from_slice(&signature.to_bytes());
    match otp_sk {
        Some(sk) => {
            out.push(1);
            out.extend_from_slice(&sk.to_bytes());
        }
        None => out.push(0),
    }
    out
}

fn unpack_prekeys(bytes: &[u8]) -> Result<(StaticSecret, Signature, Option<StaticSecret>), CoreError> {
    if bytes.len() != 97 && bytes.len() != 129 {
        return Err(CoreError::Storage {
            msg: format!("corrupt prekey record: {} bytes", bytes.len()),
        });
    }
    let signed_sk_bytes: [u8; 32] = bytes[0..32].try_into().expect("checked length");
    let signed_sk = StaticSecret::from(signed_sk_bytes);
    let sig_bytes: [u8; 64] = bytes[32..96].try_into().expect("checked length");
    let signature = Signature::from_bytes(&sig_bytes);
    let has_otp = bytes[96] == 1;
    let otp_sk = if has_otp {
        if bytes.len() != 129 {
            return Err(CoreError::Storage {
                msg: "corrupt prekey record: otp flag set but record too short".into(),
            });
        }
        let otp_bytes: [u8; 32] = bytes[97..129].try_into().expect("checked length");
        Some(StaticSecret::from(otp_bytes))
    } else {
        None
    };
    Ok((signed_sk, signature, otp_sk))
}

/// Wire layout of an exported prekey bundle (D3):
///   identity_pk(32) || signing_pk(32) || signed_prekey_pk(32) || signature(64)
///   || has_otp(1) || [one_time_prekey_pk(32)]
fn bytes_to_pubkey(b: &[u8]) -> Result<PublicKey, CoreError> {
    let arr: [u8; 32] = b
        .try_into()
        .map_err(|_| CoreError::Handshake { msg: "expected a 32-byte public key".into() })?;
    Ok(PublicKey::from(arr))
}

fn unpack_prekey_bundle(bytes: &[u8]) -> Result<PrekeyBundle, CoreError> {
    if bytes.len() != 161 && bytes.len() != 193 {
        return Err(CoreError::Handshake {
            msg: format!("corrupt prekey bundle: {} bytes", bytes.len()),
        });
    }
    let identity_pk = bytes_to_pubkey(&bytes[0..32])?;
    let signing_pk_bytes: [u8; 32] = bytes[32..64].try_into().expect("checked length");
    let signing_pk = VerifyingKey::from_bytes(&signing_pk_bytes)
        .map_err(|_| CoreError::Handshake { msg: "invalid signing public key".into() })?;
    let signed_prekey_pk = bytes_to_pubkey(&bytes[64..96])?;
    let sig_bytes: [u8; 64] = bytes[96..160].try_into().expect("checked length");
    let signed_prekey_signature = Signature::from_bytes(&sig_bytes);
    let has_otp = bytes[160] == 1;
    let one_time_prekey_pk = if has_otp {
        if bytes.len() != 193 {
            return Err(CoreError::Handshake {
                msg: "corrupt prekey bundle: otp flag set but bundle too short".into(),
            });
        }
        Some(bytes_to_pubkey(&bytes[161..193])?)
    } else {
        None
    };
    Ok(PrekeyBundle {
        identity_pk,
        signing_pk,
        signed_prekey_pk,
        signed_prekey_signature,
        one_time_prekey_pk,
    })
}

#[derive(uniffi::Object)]
pub struct ArciumCore {
    store: Mutex<EncryptedStore>,
    // D1: in-memory only, deliberately not persisted. Sessions are lost on
    // process death; that is expected and acceptable for this task.
    sessions: Mutex<SessionManager>,
}

#[uniffi::export]
impl ArciumCore {
    #[uniffi::constructor]
    pub fn new(storage_path: String, master_key: Vec<u8>) -> Result<Arc<Self>, CoreError> {
        let key: [u8; 32] = master_key.try_into().map_err(|_| CoreError::InvalidKey {
            msg: "expected exactly 32 bytes".into(),
        })?;
        let store = EncryptedStore::open(&storage_path, key)?;
        Ok(Arc::new(Self {
            store: Mutex::new(store),
            sessions: Mutex::new(SessionManager::new()),
        }))
    }

    pub fn save_identity(&self, identity: Arc<Identity>) -> Result<(), CoreError> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(64));
        bytes.extend_from_slice(identity.signing_key.as_bytes());
        bytes.extend_from_slice(&identity.dh_key.to_bytes());
        self.store
            .lock()
            .map_err(|_| CoreError::Storage { msg: "mutex poisoned".into() })?
            .put(IDENTITY_KEY, &bytes)?;
        Ok(())
    }

    pub fn load_identity(&self) -> Option<Arc<Identity>> {
        // A poisoned mutex must not panic across the FFI boundary; treat the
        // store as unavailable, consistent with save_identity's error path.
        let store = match self.store.lock() {
            Ok(guard) => guard,
            Err(_) => return None,
        };
        let bytes = match store.get(IDENTITY_KEY) {
            Ok(b) => Zeroizing::new(b),
            Err(_) => return None, // NotFound or wrong-key Decryption → None
        };
        if bytes.len() != 64 {
            return None;
        }
        let sk_bytes: [u8; 32] = bytes[..32].try_into().ok()?;
        let dh_bytes: [u8; 32] = bytes[32..].try_into().ok()?;
        Some(Arc::new(Identity {
            signing_key: SigningKey::from_bytes(&sk_bytes),
            dh_key: StaticSecret::from(dh_bytes),
        }))
    }

    /// Generates a signed-prekey keypair (and, for now, always a one-time
    /// prekey — see D4: exhaustion/replenishment bookkeeping is out of
    /// scope, so the same one-time prekey is reused across every
    /// `establish_session_responder` call, which is a known, documented
    /// limitation, not a production-ready model), signs the signed-prekey
    /// with the saved identity's signing key, and persists everything
    /// (secrets + signature) to the encrypted store. Calling this again
    /// silently overwrites the previous prekeys (same UPSERT semantics as
    /// `save_identity`) — no "already established" guard exists.
    pub fn establish_prekeys(&self) -> Result<(), CoreError> {
        let identity = self.require_identity()?;
        let signed_prekey_sk = StaticSecret::random_from_rng(OsRng);
        let signed_prekey_pk = PublicKey::from(&signed_prekey_sk);
        let signature = identity.signing_key.sign(signed_prekey_pk.as_bytes());
        let otp_sk = StaticSecret::random_from_rng(OsRng);
        let packed = pack_prekeys(&signed_prekey_sk, &signature, Some(&otp_sk));
        self.store
            .lock()
            .map_err(|_| CoreError::Storage { msg: "mutex poisoned".into() })?
            .put(PREKEYS_KEY, &packed)?;
        Ok(())
    }

    /// Pure read of the already-persisted prekey bundle (D3) — does not
    /// generate anything. Fails if `establish_prekeys` was never called.
    pub fn export_prekey_bundle(&self) -> Result<Vec<u8>, CoreError> {
        let identity = self.require_identity()?;
        let prekey_bytes = self
            .store
            .lock()
            .map_err(|_| CoreError::Storage { msg: "mutex poisoned".into() })?
            .get(PREKEYS_KEY)?;
        let (signed_sk, signature, otp_sk) = unpack_prekeys(&prekey_bytes)?;
        let signed_prekey_pk = PublicKey::from(&signed_sk);
        let identity_pk = PublicKey::from(&identity.dh_key);
        let signing_pk = identity.signing_key.verifying_key();

        let mut out = Vec::with_capacity(193);
        out.extend_from_slice(identity_pk.as_bytes());
        out.extend_from_slice(signing_pk.as_bytes());
        out.extend_from_slice(signed_prekey_pk.as_bytes());
        out.extend_from_slice(&signature.to_bytes());
        match otp_sk {
            Some(sk) => {
                out.push(1);
                out.extend_from_slice(PublicKey::from(&sk).as_bytes());
            }
            None => out.push(0),
        }
        Ok(out)
    }

    /// Establishes a session as the X3DH initiator ("Alice") against a
    /// peer's exported prekey bundle. Returns
    /// `our_identity_pk(32) || our_ephemeral_pk(32)` — the bytes the peer
    /// needs to call `establish_session_responder`.
    pub fn establish_session_initiator(
        &self,
        session_id: u64,
        peer_bundle: Vec<u8>,
    ) -> Result<Vec<u8>, CoreError> {
        let identity = self.require_identity()?;
        let bundle = unpack_prekey_bundle(&peer_bundle)?;
        let our_identity_pk = PublicKey::from(&identity.dh_key);
        let alice_session = x3dh_initiate(&identity.dh_key, our_identity_pk, &bundle)?;

        let ratchet = DoubleRatchet::init_alice(alice_session.root_key, alice_session.their_signed_prekey_pk);
        let session = Session { ratchet, ad: alice_session.ad.clone() };
        self.sessions
            .lock()
            .map_err(|_| CoreError::Storage { msg: "mutex poisoned".into() })?
            .new_session(session_id, session);

        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(our_identity_pk.as_bytes());
        out.extend_from_slice(alice_session.ephemeral_pk.as_bytes());
        Ok(out)
    }

    /// Establishes a session as the X3DH responder ("Bob") from Alice's
    /// identity + ephemeral public keys (the bytes returned by
    /// `establish_session_initiator`). Requires `establish_prekeys` to have
    /// been called first.
    pub fn establish_session_responder(
        &self,
        session_id: u64,
        alice_identity_pk: Vec<u8>,
        alice_ephemeral_pk: Vec<u8>,
    ) -> Result<(), CoreError> {
        let identity = self.require_identity()?;
        let alice_id_pk = bytes_to_pubkey(&alice_identity_pk)?;
        let alice_eph_pk = bytes_to_pubkey(&alice_ephemeral_pk)?;

        let prekey_bytes = self
            .store
            .lock()
            .map_err(|_| CoreError::Storage { msg: "mutex poisoned".into() })?
            .get(PREKEYS_KEY)?;
        let (signed_sk, _signature, otp_sk) = unpack_prekeys(&prekey_bytes)?;

        let our_identity_pk = PublicKey::from(&identity.dh_key);
        let bob_session = x3dh_respond(
            &identity.dh_key,
            our_identity_pk,
            &signed_sk,
            otp_sk.as_ref(),
            alice_id_pk,
            alice_eph_pk,
        );

        let ratchet = DoubleRatchet::init_bob(bob_session.root_key, signed_sk);
        let session = Session { ratchet, ad: bob_session.ad.clone() };
        self.sessions
            .lock()
            .map_err(|_| CoreError::Storage { msg: "mutex poisoned".into() })?
            .new_session(session_id, session);
        Ok(())
    }

    /// Encrypts `plaintext` for the given established session. Returns
    /// `header.to_bytes()(40) || ciphertext`.
    pub fn encrypt_message(&self, session_id: u64, plaintext: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| CoreError::Storage { msg: "mutex poisoned".into() })?;
        let session = sessions
            .get_session(session_id)
            .ok_or(CoreError::NoSession { session_id })?;
        let (header, ciphertext) = session.ratchet.encrypt(&plaintext, &session.ad)?;

        let mut out = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
        out.extend_from_slice(&header.to_bytes());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypts `message` (as produced by `encrypt_message`) for the given
    /// established session. Preserves the F-1 commit-on-success guarantee:
    /// `DoubleRatchet::decrypt` internally snapshots and rolls back on any
    /// authentication failure, so a forged/tampered message leaves the
    /// session's ratchet state completely unchanged — this wrapper adds no
    /// extra mutation that could undermine that.
    pub fn decrypt_message(&self, session_id: u64, message: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        if message.len() < HEADER_SIZE {
            return Err(CoreError::Crypto { msg: "message shorter than header".into() });
        }
        let (header_bytes, ciphertext) = message.split_at(HEADER_SIZE);
        let header = Header::from_bytes(header_bytes)?;

        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| CoreError::Storage { msg: "mutex poisoned".into() })?;
        let session = sessions
            .get_session(session_id)
            .ok_or(CoreError::NoSession { session_id })?;
        let plaintext = session.ratchet.decrypt(&header, ciphertext, &session.ad)?;
        Ok(plaintext)
    }
}

// Plain (non-exported) impl block: helpers here are NOT visible to UniFFI,
// unlike methods inside the `#[uniffi::export] impl ArciumCore` block above,
// where export applies to every method regardless of Rust-level visibility.
impl ArciumCore {
    fn require_identity(&self) -> Result<Arc<Identity>, CoreError> {
        self.load_identity()
            .ok_or_else(|| CoreError::InvalidKey { msg: "no identity saved — call save_identity first".into() })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn key32(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    #[test]
    fn identity_generates_keys() {
        let id = Identity::generate();
        assert_ne!(id.public_key_bytes(), vec![0u8; 32], "public key must not be all zeros");
    }

    #[test]
    fn identity_public_key_correct_size() {
        assert_eq!(Identity::generate().public_key_bytes().len(), 32);
    }

    #[test]
    fn identity_dh_public_key_correct_size_and_distinct_from_signing_key() {
        let id = Identity::generate();
        let dh_pk = id.dh_public_key_bytes();
        assert_eq!(dh_pk.len(), 32);
        assert_ne!(dh_pk, id.public_key_bytes(), "DH key and signing key must differ");
    }

    #[test]
    fn core_saves_and_loads_identity() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db").to_str().unwrap().to_string();

        let core = ArciumCore::new(path, key32(0)).unwrap();
        let id = Identity::generate();
        let pk = id.public_key_bytes();
        core.save_identity(id).unwrap();

        let loaded = core.load_identity().expect("identity must be present after save");
        assert_eq!(loaded.public_key_bytes(), pk);
    }

    #[test]
    fn core_with_wrong_key_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db").to_str().unwrap().to_string();

        // Save with key 0x00…
        let core = ArciumCore::new(path.clone(), key32(0)).unwrap();
        core.save_identity(Identity::generate()).unwrap();

        // Open same file with key 0x01… → Decryption fails → None
        let core2 = ArciumCore::new(path, key32(1)).unwrap();
        assert!(core2.load_identity().is_none());
    }

    #[test]
    fn core_new_rejects_short_master_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db").to_str().unwrap().to_string();
        let result = ArciumCore::new(path, vec![0u8; 16]);
        assert!(matches!(result, Err(CoreError::InvalidKey { .. })));
    }

    #[test]
    fn save_identity_returns_ok_on_success() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db").to_str().unwrap().to_string();
        let core = ArciumCore::new(path, key32(0)).unwrap();
        let result = core.save_identity(Identity::generate());
        assert!(result.is_ok(), "save_identity must return Ok on success");
    }

    #[test]
    fn save_identity_returns_err_on_poisoned_mutex() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db").to_str().unwrap().to_string();
        let core = Arc::new(ArciumCore::new(path, key32(0)).unwrap());
        // Poison the mutex by panicking while holding the lock in another thread.
        let core2 = Arc::clone(&core);
        let _ = std::thread::spawn(move || {
            let _guard = core2.store.lock().unwrap();
            panic!("poison");
        })
        .join();
        // The mutex is now poisoned; save_identity must return Err, not panic.
        let result = core.save_identity(Identity::generate());
        assert!(
            matches!(result, Err(CoreError::Storage { .. })),
            "poisoned mutex must surface as CoreError::Storage, got {:?}",
            result
        );
    }

    #[test]
    fn load_identity_returns_none_on_poisoned_mutex() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db").to_str().unwrap().to_string();
        let core = Arc::new(ArciumCore::new(path, key32(0)).unwrap());
        core.save_identity(Identity::generate()).unwrap();
        // Poison the mutex by panicking while holding the lock in another thread.
        let core2 = Arc::clone(&core);
        let _ = std::thread::spawn(move || {
            let _guard = core2.store.lock().unwrap();
            panic!("poison");
        })
        .join();
        // The mutex is now poisoned; load_identity must return None, not panic.
        assert!(
            core.load_identity().is_none(),
            "poisoned mutex must yield None, not a panic across FFI"
        );
    }

    // ── Messaging FFI surface ────────────────────────────────────────────────

    fn fresh_core(byte: u8) -> Arc<ArciumCore> {
        let dir = tempdir().unwrap();
        // Leak the tempdir so the DB file survives for the life of the test
        // (the harness's short-lived arcium-msgffi scratch clone is disposed
        // separately; this only needs to survive one test function).
        let path = dir.keep().join("db").to_str().unwrap().to_string();
        ArciumCore::new(path, key32(byte)).unwrap()
    }

    #[test]
    fn establish_prekeys_then_export_bundle_round_trips_stably() {
        let core = fresh_core(1);
        core.save_identity(Identity::generate()).unwrap();
        core.establish_prekeys().unwrap();

        let bundle1 = core.export_prekey_bundle().unwrap();
        let bundle2 = core.export_prekey_bundle().unwrap();
        assert_eq!(bundle1, bundle2, "export_prekey_bundle must be a pure read (D3), not regenerate");
        assert_eq!(bundle1.len(), 193, "bundle with an OTP present must be 193 bytes");
    }

    #[test]
    fn export_prekey_bundle_fails_before_establish_prekeys() {
        let core = fresh_core(2);
        core.save_identity(Identity::generate()).unwrap();
        assert!(core.export_prekey_bundle().is_err());
    }

    #[test]
    fn alice_to_bob_full_round_trip_recovers_exact_plaintext() {
        let session_id: u64 = 42;

        let bob = fresh_core(10);
        bob.save_identity(Identity::generate()).unwrap();
        bob.establish_prekeys().unwrap();
        let bob_bundle = bob.export_prekey_bundle().unwrap();

        let alice = fresh_core(20);
        alice.save_identity(Identity::generate()).unwrap();

        let alice_handshake_bytes = alice.establish_session_initiator(session_id, bob_bundle).unwrap();
        assert_eq!(alice_handshake_bytes.len(), 64);
        let alice_identity_pk = alice_handshake_bytes[..32].to_vec();
        let alice_ephemeral_pk = alice_handshake_bytes[32..].to_vec();

        bob.establish_session_responder(session_id, alice_identity_pk, alice_ephemeral_pk)
            .unwrap();

        let plaintext = b"hello arcium".to_vec();
        let message = alice.encrypt_message(session_id, plaintext.clone()).unwrap();

        // Ciphertext must not equal the plaintext — this is not a stub echo.
        assert_ne!(&message[HEADER_SIZE..], plaintext.as_slice());

        let recovered = bob.decrypt_message(session_id, message).unwrap();
        assert_eq!(recovered, plaintext, "Bob must recover exactly what Alice sent");
    }

    #[test]
    fn forged_message_fails_and_does_not_desync_the_session() {
        let session_id: u64 = 7;

        let bob = fresh_core(30);
        bob.save_identity(Identity::generate()).unwrap();
        bob.establish_prekeys().unwrap();
        let bob_bundle = bob.export_prekey_bundle().unwrap();

        let alice = fresh_core(40);
        alice.save_identity(Identity::generate()).unwrap();
        let handshake = alice.establish_session_initiator(session_id, bob_bundle).unwrap();
        bob.establish_session_responder(session_id, handshake[..32].to_vec(), handshake[32..].to_vec())
            .unwrap();

        let genuine = alice.encrypt_message(session_id, b"real message".to_vec()).unwrap();

        // Tamper one byte of the ciphertext (not the header) before Bob ever
        // sees a genuine message — this is Bob's very first decrypt, so it
        // also exercises the F-1 path at the "no dhr set yet" boundary.
        let mut forged = genuine.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0xFF;

        assert!(bob.decrypt_message(session_id, forged).is_err(), "forged ciphertext must fail authentication");

        // The genuine message, unmodified, must still decrypt correctly —
        // proof the failed forged attempt did not desync Bob's session.
        let recovered = bob.decrypt_message(session_id, genuine).unwrap();
        assert_eq!(recovered, b"real message");
    }

    #[test]
    fn multi_message_both_directions_ratchet_advances() {
        let session_id: u64 = 99;

        let bob = fresh_core(50);
        bob.save_identity(Identity::generate()).unwrap();
        bob.establish_prekeys().unwrap();
        let bob_bundle = bob.export_prekey_bundle().unwrap();

        let alice = fresh_core(60);
        alice.save_identity(Identity::generate()).unwrap();
        let handshake = alice.establish_session_initiator(session_id, bob_bundle).unwrap();
        bob.establish_session_responder(session_id, handshake[..32].to_vec(), handshake[32..].to_vec())
            .unwrap();

        // Alice must send first: Bob's sending chain key isn't derived until
        // his receiving DH ratchet step runs on the first inbound message.
        let m1 = alice.encrypt_message(session_id, b"one".to_vec()).unwrap();
        assert_eq!(bob.decrypt_message(session_id, m1).unwrap(), b"one");

        let m2 = alice.encrypt_message(session_id, b"two".to_vec()).unwrap();
        assert_eq!(bob.decrypt_message(session_id, m2).unwrap(), b"two");

        // Now Bob can reply — his cks was derived by the DH step above.
        let r1 = bob.encrypt_message(session_id, b"reply one".to_vec()).unwrap();
        assert_eq!(alice.decrypt_message(session_id, r1).unwrap(), b"reply one");

        let r2 = bob.encrypt_message(session_id, b"reply two".to_vec()).unwrap();
        assert_eq!(alice.decrypt_message(session_id, r2).unwrap(), b"reply two");

        let m3 = alice.encrypt_message(session_id, b"three".to_vec()).unwrap();
        assert_eq!(bob.decrypt_message(session_id, m3).unwrap(), b"three");
    }

    #[test]
    fn encrypt_and_decrypt_fail_with_no_session() {
        let core = fresh_core(70);
        core.save_identity(Identity::generate()).unwrap();
        assert!(matches!(
            core.encrypt_message(1, b"x".to_vec()),
            Err(CoreError::NoSession { session_id: 1 })
        ));
        assert!(matches!(
            core.decrypt_message(1, vec![0u8; HEADER_SIZE]),
            Err(CoreError::NoSession { session_id: 1 })
        ));
    }
}
