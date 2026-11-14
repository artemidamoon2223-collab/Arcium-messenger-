//! The relay's keys, and the mailbox authentication of `RELAY_PROTOCOL_V2`.
//!
//! A relay has two key pairs, both made by `arcium-relay keygen`:
//!
//! - its **TLS key**, Ed25519, kept as its 32-byte seed. Clients pin the
//!   SHA-256 of its `SubjectPublicKeyInfo` (`crate::tls`).
//! - its **auth key**, X25519. Clients pin the public half.
//!
//! To act for the owner `O` of a mailbox, a client proves it holds the secret
//! of `O`, an X25519 identity key, without sending anything derived from it
//! that is valid beyond this connection:
//!
//! ```text
//! k   = HKDF-SHA256(salt = "arcium-relay-auth-salt-v1", ikm = DH(id_sk, auth_pk),
//!                   info = "arcium-relay-auth-v1")
//! tag = HMAC-SHA256(k, challenge || exporter || O)
//! ```
//!
//! `challenge` is the 32 random bytes of the relay's HELLO, `exporter` 32
//! bytes of TLS 1.3 exported keying material of this connection (RFC 8446
//! section 7.5, label `"arcium-relay-auth-v1"`, no context). The relay checks
//! the tag with `DH(auth_sk, O)`, which is the same shared secret, and
//! compares it in constant time. A DH output of all zeros (a low-order key on
//! either side) is refused on both sides: it would give a key anyone can
//! compute.
//!
//! The identity key is used in one more DH context here. It is separated from
//! the others by the HKDF salt and `info`: the salt gives this derivation its
//! own pseudorandom key even if `auth_pk` is some peer's identity key, whose
//! DH with ours other derivations (the handshake refusal MAC) also extract
//! without a salt. That is cross-protocol key reuse; it has not been reviewed
//! by a cryptographer. REVISIT AT SECURITY AUDIT.

use std::fmt;
use std::io::{self, Write};
use std::path::Path;

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::address::{hex, parse_hex32, AddressError, RelayAddress};
use crate::protocol::Key;

/// HKDF salt of the authentication key.
pub const AUTH_KEY_SALT: &[u8] = b"arcium-relay-auth-salt-v1";
/// HKDF `info` of the authentication key.
pub const AUTH_KEY_INFO: &[u8] = b"arcium-relay-auth-v1";
/// TLS exporter label of the connection binding.
pub const EXPORTER_LABEL: &[u8] = b"arcium-relay-auth-v1";
/// Length of the exported keying material, the challenge and the tag.
pub const AUTH_LEN: usize = 32;

/// The first line of a keys file, which names its format.
const KEYS_FILE_PREFIX: &str = "arcium-relay-keys-v1:";

/// The MAC keyed with `k` for the shared secret `shared`. `None` if `shared`
/// is all zeros.
fn auth_mac(shared: &[u8; 32]) -> Option<Hmac<Sha256>> {
    if bool::from(shared.ct_eq(&[0u8; 32])) {
        return None;
    }
    // The HKDF pseudorandom key is secret; `Hkdf::new` drops it unwiped, so it
    // is taken from `extract` and wiped here.
    let (mut prk, hk) = Hkdf::<Sha256>::extract(Some(AUTH_KEY_SALT), shared);
    prk.as_mut_slice().zeroize();
    let mut k = Zeroizing::new([0u8; 32]);
    hk.expand(AUTH_KEY_INFO, &mut k[..]).expect("hkdf expand");
    Some(<Hmac<Sha256> as KeyInit>::new_from_slice(&k[..]).expect("hmac"))
}

fn mac_input(mac: &mut Hmac<Sha256>, challenge: &[u8; 32], exporter: &[u8; 32], owner: &Key) {
    mac.update(challenge);
    mac.update(exporter);
    mac.update(owner);
}

/// The AUTH tag for `owner` on the connection with `challenge` and
/// `exporter`, from `shared = DH(id_sk, auth_pk)`. `None` if `shared` is all
/// zeros.
pub(crate) fn auth_tag(
    shared: &[u8; 32],
    challenge: &[u8; 32],
    exporter: &[u8; 32],
    owner: &Key,
) -> Option<[u8; AUTH_LEN]> {
    let mut mac = auth_mac(shared)?;
    mac_input(&mut mac, challenge, exporter, owner);
    // The tag is only borrowed from the `CtOutput`, which wipes itself.
    let tag = mac.finalize();
    let mut out = [0u8; AUTH_LEN];
    out.copy_from_slice(tag.as_bytes());
    Some(out)
}

/// Whether `tag` proves `owner` on the connection with `challenge` and
/// `exporter`, checked by the relay with its auth secret. Compared in
/// constant time; false for a low-order `owner`.
pub(crate) fn verify_auth_tag(
    auth_sk: &StaticSecret,
    challenge: &[u8; 32],
    exporter: &[u8; 32],
    owner: &Key,
    tag: &[u8; AUTH_LEN],
) -> bool {
    // `SharedSecret` wipes itself on drop.
    let shared = auth_sk.diffie_hellman(&PublicKey::from(*owner));
    let Some(mut mac) = auth_mac(shared.as_bytes()) else {
        return false;
    };
    mac_input(&mut mac, challenge, exporter, owner);
    mac.verify_slice(tag).is_ok()
}

/// A relay's two secret keys.
pub struct RelayKeys {
    tls_seed: Zeroizing<[u8; 32]>,
    auth_secret: StaticSecret,
}

impl fmt::Debug for RelayKeys {
    /// Public values only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayKeys")
            .field("tls_pin", &self.tls_pin().map(|p| hex(&p)))
            .field("auth_pk", &hex(&self.auth_public()))
            .finish()
    }
}

impl RelayKeys {
    /// Fresh keys from the operating system's random number generator.
    pub fn generate() -> io::Result<Self> {
        let mut tls_seed = Zeroizing::new([0u8; 32]);
        let mut auth = Zeroizing::new([0u8; 32]);
        let no_randomness = |e: rand_core::Error| io::Error::other(format!("no randomness: {e}"));
        OsRng.try_fill_bytes(&mut tls_seed[..]).map_err(no_randomness)?;
        OsRng.try_fill_bytes(&mut auth[..]).map_err(no_randomness)?;
        Ok(Self {
            tls_seed,
            auth_secret: StaticSecret::from(*auth),
        })
    }

    /// Writes the keys to a new file at `path`, readable and writable by its
    /// owner only (mode 0600). Refuses, with `AlreadyExists`, if anything is
    /// at `path`; removes what it wrote if writing fails.
    #[cfg(unix)]
    pub fn write_new(&self, path: &Path) -> io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        let mut text = Zeroizing::new(String::with_capacity(KEYS_FILE_PREFIX.len() + 130));
        text.push_str(KEYS_FILE_PREFIX);
        text.push_str(&Zeroizing::new(hex(&self.tls_seed[..])));
        text.push(':');
        text.push_str(&Zeroizing::new(hex(self.auth_secret.as_bytes())));
        text.push('\n');
        let written = file.write_all(text.as_bytes()).and_then(|()| file.sync_all());
        if written.is_err() {
            drop(file);
            let _ = std::fs::remove_file(path);
        }
        written
    }

    /// Writing secrets needs file permissions this build cannot set.
    #[cfg(not(unix))]
    pub fn write_new(&self, _path: &Path) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "writing relay keys needs Unix file permissions",
        ))
    }

    /// Reads keys written by [`RelayKeys::write_new`]. The format is exact:
    /// one line, `arcium-relay-keys-v1:<tls_seed>:<auth_secret>`, both in 64
    /// lowercase hex digits, and a final newline.
    pub fn read(path: &Path) -> io::Result<Self> {
        let bytes = Zeroizing::new(std::fs::read(path)?);
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "not an arcium-relay keys file");
        let text = std::str::from_utf8(&bytes).map_err(|_| bad())?;
        let body = text
            .strip_prefix(KEYS_FILE_PREFIX)
            .and_then(|t| t.strip_suffix('\n'))
            .ok_or_else(bad)?;
        let (tls, auth) = body.split_once(':').ok_or_else(bad)?;
        let tls_seed = Zeroizing::new(parse_hex32(tls).ok_or_else(bad)?);
        let auth = Zeroizing::new(parse_hex32(auth).ok_or_else(bad)?);
        Ok(Self {
            tls_seed,
            auth_secret: StaticSecret::from(*auth),
        })
    }

    pub(crate) fn tls_seed(&self) -> &[u8; 32] {
        &self.tls_seed
    }

    pub(crate) fn auth_secret(&self) -> &StaticSecret {
        &self.auth_secret
    }

    /// SHA-256 of the TLS key's `SubjectPublicKeyInfo`: the pin clients use.
    pub fn tls_pin(&self) -> io::Result<[u8; 32]> {
        let key = crate::tls::signing_key(&self.tls_seed).map_err(io::Error::other)?;
        Ok(crate::tls::pin_of(&crate::tls::spki(key.as_ref()).map_err(io::Error::other)?))
    }

    /// The public half of the auth key.
    pub fn auth_public(&self) -> Key {
        PublicKey::from(&self.auth_secret).to_bytes()
    }

    /// The connection string clients use to reach this relay at `host` and
    /// `port`.
    pub fn address(&self, host: &str, port: u16) -> io::Result<RelayAddress> {
        RelayAddress::new(host, port, self.tls_pin()?, self.auth_public())
            .map_err(|e: AddressError| io::Error::new(io::ErrorKind::InvalidInput, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn party(byte: u8) -> (StaticSecret, Key) {
        let sk = StaticSecret::from([byte; 32]);
        let pk = PublicKey::from(&sk).to_bytes();
        (sk, pk)
    }

    /// The client's tag (from `DH(id_sk, auth_pk)`) verifies at the relay
    /// (with `DH(auth_sk, owner)`), and changing any input breaks it.
    #[test]
    fn a_tag_verifies_only_for_its_owner_challenge_exporter_and_relay() {
        let (auth_sk, auth_pk) = party(1);
        let (id_sk, owner) = party(2);
        let (other_sk, other) = party(3);
        let (c, x) = ([4u8; 32], [5u8; 32]);
        let shared = id_sk.diffie_hellman(&PublicKey::from(auth_pk)).to_bytes();
        let tag = auth_tag(&shared, &c, &x, &owner).unwrap();
        assert!(verify_auth_tag(&auth_sk, &c, &x, &owner, &tag));
        assert!(!verify_auth_tag(&auth_sk, &[6; 32], &x, &owner, &tag), "challenge");
        assert!(!verify_auth_tag(&auth_sk, &c, &[6; 32], &owner, &tag), "exporter");
        assert!(!verify_auth_tag(&auth_sk, &c, &x, &other, &tag), "owner");
        assert!(!verify_auth_tag(&other_sk, &c, &x, &owner, &tag), "relay key");
        let mut flipped = tag;
        flipped[31] ^= 1;
        assert!(!verify_auth_tag(&auth_sk, &c, &x, &owner, &flipped), "tag");
        // Another identity's secret gives another tag.
        let wrong = other_sk.diffie_hellman(&PublicKey::from(auth_pk)).to_bytes();
        let forged = auth_tag(&wrong, &c, &x, &owner).unwrap();
        assert!(!verify_auth_tag(&auth_sk, &c, &x, &owner, &forged));
    }

    /// A low-order owner key gives an all-zero DH output, so a key anyone
    /// could compute; both sides refuse it.
    #[test]
    fn an_all_zero_shared_secret_is_refused_on_both_sides() {
        let (auth_sk, _) = party(1);
        assert!(auth_tag(&[0; 32], &[4; 32], &[5; 32], &[0; 32]).is_none());
        // The all-zero public key has low order: every DH with it is zero.
        // The tag anyone could compute from that zero key is refused.
        let low_order = [0u8; 32];
        let public_tag = documented_tag(&[0; 32], &[4; 32], &[5; 32], &low_order);
        assert!(!verify_auth_tag(&auth_sk, &[4; 32], &[5; 32], &low_order, &public_tag));
    }

    fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
        mac.update(data);
        mac.finalize().as_bytes().as_slice().try_into().unwrap()
    }

    /// The documented derivation from HMAC-SHA256 alone (RFC 5869 written
    /// out: extract `PRK = HMAC(salt, ikm)`, expand one block
    /// `k = HMAC(PRK, info || 0x01)`), without the `hkdf` crate.
    fn documented_tag(shared: &[u8; 32], c: &[u8; 32], x: &[u8; 32], o: &Key) -> [u8; 32] {
        let prk = hmac_sha256(b"arcium-relay-auth-salt-v1", shared);
        let k = hmac_sha256(&prk, b"arcium-relay-auth-v1\x01");
        hmac_sha256(&k, &[&c[..], &x[..], &o[..]].concat())
    }

    #[test]
    fn the_tag_is_the_documented_derivation() {
        let (c, x, o) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        for shared in [[9u8; 32], [1u8; 32]] {
            assert_eq!(auth_tag(&shared, &c, &x, &o).unwrap(), documented_tag(&shared, &c, &x, &o));
        }
    }

    #[cfg(unix)]
    #[test]
    fn keys_are_written_with_mode_0600_never_over_a_file_and_read_back() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.keys");
        let keys = RelayKeys::generate().unwrap();
        keys.write_new(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode {mode:o}");
        let back = RelayKeys::read(&path).unwrap();
        assert_eq!(back.tls_pin().unwrap(), keys.tls_pin().unwrap());
        assert_eq!(back.auth_public(), keys.auth_public());

        // Never over an existing file: refused, and the file is unchanged.
        let before = std::fs::read(&path).unwrap();
        let other = RelayKeys::generate().unwrap();
        let err = other.write_new(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(RelayKeys::read(&path).unwrap().auth_public(), keys.auth_public());
    }

    #[test]
    fn a_malformed_keys_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.keys");
        let h = "ab".repeat(32);
        for bad in [
            String::new(),
            format!("arcium-relay-keys-v1:{h}:{h}"),     // no newline
            format!("arcium-relay-keys-v1:{h}:{h}\n\n"), // two
            format!("arcium-relay-keys-v2:{h}:{h}\n"),
            format!("arcium-relay-keys-v1:{h}\n"),
            format!("arcium-relay-keys-v1:{h}:{h}:{h}\n"),
            format!("arcium-relay-keys-v1:{}:{h}\n", h.to_uppercase()),
            format!("arcium-relay-keys-v1:{}:{h}\n", &h[..62]),
        ] {
            std::fs::write(&path, &bad).unwrap();
            let err = RelayKeys::read(&path).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{bad:?}");
        }
        std::fs::write(&path, format!("arcium-relay-keys-v1:{h}:{h}\n")).unwrap();
        assert!(RelayKeys::read(&path).is_ok());
    }

    #[test]
    fn debug_shows_public_values_only() {
        let keys = RelayKeys::generate().unwrap();
        let shown = format!("{keys:?}");
        assert!(shown.contains(&hex(&keys.auth_public())));
        assert!(!shown.contains(&hex(&keys.tls_seed[..])));
        assert!(!shown.contains(&hex(keys.auth_secret.as_bytes())));
    }
}
