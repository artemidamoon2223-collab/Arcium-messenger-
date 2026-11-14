//! The TLS layer of `RELAY_PROTOCOL_V2`: TLS 1.3 only, rustls with the ring
//! provider, and RFC 7250 raw public keys instead of X.509 certificates.
//!
//! The relay presents its Ed25519 public key as a bare DER
//! `SubjectPublicKeyInfo` (rustls `AlwaysResolvesServerRawPublicKeys`). The
//! client requires a raw public key (`requires_raw_public_keys`), accepts it
//! only if its SHA-256 equals the pin of the connection string (compared in
//! constant time), and checks the TLS 1.3 handshake signature under that key
//! with the provider's verification algorithms
//! (`verify_tls13_signature_with_raw_key`), Ed25519 only. No certificate
//! authority, name or validity period is involved: the pin is the identity.
//!
//! Every connection is a full handshake: the client disables resumption and
//! early data, the server stores no sessions and issues no tickets, so every
//! connection is authenticated by the pinned key itself. No SNI is sent: the
//! relay does not use it, and the pin does not depend on a name.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::Resumption;
use rustls::crypto::{ring, verify_tls13_signature_with_raw_key, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{
    CertificateDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime,
};
use rustls::server::{AlwaysResolvesServerRawPublicKeys, NoServerSessionStorage};
use rustls::sign::{CertifiedKey, SigningKey};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error, ServerConfig, SignatureScheme,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// The name the client gives rustls. Never sent (SNI is off) and never
/// checked (the pin is): rustls only needs one.
const SERVER_NAME: &str = "arcium-relay.invalid";

/// PKCS#8 v1 (RFC 8410) prefix of an Ed25519 private key; the 32-byte seed
/// follows.
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

fn provider() -> Arc<CryptoProvider> {
    let mut provider = ring::default_provider();
    // X25519 only: a client cannot make the relay compute P-256 or P-384
    // key exchanges, which cost it more than they cost the client.
    provider.kx_groups = vec![ring::kx_group::X25519];
    Arc::new(provider)
}

/// The relay's TLS signing key from its 32-byte Ed25519 seed.
pub(crate) fn signing_key(seed: &[u8; 32]) -> Result<Arc<dyn SigningKey>, Error> {
    let mut der = Zeroizing::new(Vec::with_capacity(48));
    der.extend_from_slice(&ED25519_PKCS8_PREFIX);
    der.extend_from_slice(seed);
    ring::sign::any_eddsa_type(&PrivatePkcs8KeyDer::from(&der[..]))
}

/// The DER `SubjectPublicKeyInfo` of `key`: what the relay presents.
pub(crate) fn spki(key: &dyn SigningKey) -> Result<Vec<u8>, Error> {
    key.public_key()
        .map(|k| k.as_ref().to_vec())
        .ok_or_else(|| Error::General("signing key has no public key".into()))
}

/// The pin of a `SubjectPublicKeyInfo`: its SHA-256.
pub(crate) fn pin_of(spki: &[u8]) -> [u8; 32] {
    Sha256::digest(spki).into()
}

/// The relay's TLS configuration: TLS 1.3 only, `key` presented as a raw
/// public key, no client certificate, no resumption.
pub(crate) fn server_config(key: Arc<dyn SigningKey>) -> Result<Arc<ServerConfig>, Error> {
    let spki = spki(key.as_ref())?;
    let certified = Arc::new(CertifiedKey::new(vec![CertificateDer::from(spki)], key));
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(certified)));
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

/// The client's TLS configuration for a relay whose key has `pin`.
pub(crate) fn client_config(pin: [u8; 32]) -> Result<Arc<ClientConfig>, Error> {
    let provider = provider();
    let verifier = PinnedRawKey {
        pin,
        algorithms: provider.signature_verification_algorithms,
    };
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.resumption = Resumption::disabled();
    config.enable_sni = false;
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

pub(crate) fn server_name() -> ServerName<'static> {
    ServerName::try_from(SERVER_NAME).expect("a valid DNS name")
}

/// Accepts exactly one server key: a raw public key whose SHA-256 is `pin`.
#[derive(Debug)]
struct PinnedRawKey {
    pin: [u8; 32],
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedRawKey {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // A raw public key stands alone. `end_entity` is the bare SPKI
        // (`requires_raw_public_keys` below makes rustls refuse X.509).
        let pinned: bool = pin_of(end_entity.as_ref()).ct_eq(&self.pin).into();
        if !intermediates.is_empty() || !pinned {
            return Err(Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // Unreachable: the configuration offers TLS 1.3 only.
        Err(Error::General("TLS 1.2 is not used".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        if dss.scheme != SignatureScheme::ED25519 {
            return Err(Error::PeerMisbehaved(
                rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
            ));
        }
        // `cert` is the SPKI `verify_server_cert` accepted.
        let spki = SubjectPublicKeyInfoDer::from(cert.as_ref());
        verify_tls13_signature_with_raw_key(message, &spki, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SPKI rustls presents for an Ed25519 key is the RFC 8410 encoding:
    /// a fixed 12-byte header and the 32-byte public key.
    #[test]
    fn the_presented_key_is_the_rfc_8410_spki() {
        let presented = spki(signing_key(&[7; 32]).unwrap().as_ref()).unwrap();
        assert_eq!(presented.len(), 44);
        assert_eq!(
            presented[..12],
            [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]
        );
        // Another seed, another key and pin.
        let other = spki(signing_key(&[8; 32]).unwrap().as_ref()).unwrap();
        assert_ne!(pin_of(&presented), pin_of(&other));
    }

    #[test]
    fn the_verifier_accepts_only_the_pinned_key_alone() {
        let presented = spki(signing_key(&[7; 32]).unwrap().as_ref()).unwrap();
        let v = PinnedRawKey {
            pin: pin_of(&presented),
            algorithms: provider().signature_verification_algorithms,
        };
        let cert = CertificateDer::from(presented.clone());
        let name = server_name();
        let now = UnixTime::now();
        assert!(v.verify_server_cert(&cert, &[], &name, &[], now).is_ok());
        let mut flipped = presented.clone();
        flipped[43] ^= 1;
        assert!(v
            .verify_server_cert(&CertificateDer::from(flipped), &[], &name, &[], now)
            .is_err());
        assert!(v
            .verify_server_cert(&cert, std::slice::from_ref(&cert), &name, &[], now)
            .is_err());
        assert!(v.requires_raw_public_keys());
        assert_eq!(v.supported_verify_schemes(), vec![SignatureScheme::ED25519]);
    }

    /// Runs a handshake in memory; on failure, which side refused and why.
    fn handshake(
        client: &mut rustls::ClientConnection,
        server: &mut rustls::ServerConnection,
    ) -> Result<(), (&'static str, Error)> {
        for _ in 0..10 {
            let mut wire = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut wire).unwrap();
            }
            let mut rest = wire.as_slice();
            while !rest.is_empty() {
                server.read_tls(&mut rest).unwrap();
                server.process_new_packets().map_err(|e| ("server", e))?;
            }
            let mut wire = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut wire).unwrap();
            }
            let mut rest = wire.as_slice();
            while !rest.is_empty() {
                client.read_tls(&mut rest).unwrap();
                client.process_new_packets().map_err(|e| ("client", e))?;
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(());
            }
        }
        panic!("the handshake did not finish");
    }

    /// A relay that presents the pinned key but signs with another one (it
    /// does not hold the pinned key's secret) is refused by the client: the
    /// pin alone is not trusted, the TLS 1.3 signature is checked under the
    /// pinned key. The real key, as a control, completes the handshake.
    #[test]
    fn a_relay_presenting_the_pinned_key_without_its_secret_is_refused() {
        let pinned = spki(signing_key(&[7; 32]).unwrap().as_ref()).unwrap();
        let impostor = signing_key(&[8; 32]).unwrap();
        let certified = Arc::new(CertifiedKey::new(vec![CertificateDer::from(pinned.clone())], impostor));
        let forged = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(certified)));
        let client_config = client_config(pin_of(&pinned)).unwrap();

        let mut client = rustls::ClientConnection::new(client_config.clone(), server_name()).unwrap();
        let mut server = rustls::ServerConnection::new(Arc::new(forged)).unwrap();
        let (side, err) = handshake(&mut client, &mut server).unwrap_err();
        assert_eq!(side, "client", "{err:?}");
        assert!(
            matches!(err, Error::InvalidCertificate(CertificateError::BadSignature)),
            "{err:?}"
        );

        let real = server_config(signing_key(&[7; 32]).unwrap()).unwrap();
        let mut client = rustls::ClientConnection::new(client_config, server_name()).unwrap();
        let mut server = rustls::ServerConnection::new(real).unwrap();
        handshake(&mut client, &mut server).unwrap();
        assert_eq!(client.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
    }
}
