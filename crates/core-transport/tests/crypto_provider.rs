//! `install_crypto_provider` in a process of its own: nothing else in this
//! test binary creates a Tor client or a TLS configuration, so the process
//! default provider is the one this call installs, or none.

use rustls::crypto::CryptoProvider;

/// Its cipher suites and key exchange groups, which tell ring's default
/// provider apart from another provider or another configuration.
fn names(p: &CryptoProvider) -> (Vec<rustls::CipherSuite>, Vec<rustls::NamedGroup>) {
    (
        p.cipher_suites.iter().map(|s| s.suite()).collect(),
        p.kx_groups.iter().map(|g| g.name()).collect(),
    )
}

#[test]
fn install_crypto_provider_installs_ring_once() {
    assert!(CryptoProvider::get_default().is_none(), "a provider before the call");
    core_transport::install_crypto_provider();
    let first = CryptoProvider::get_default().expect("no provider after the call").clone();
    assert_eq!(names(&first), names(&rustls::crypto::ring::default_provider()));
    core_transport::install_crypto_provider();
    let second = CryptoProvider::get_default().expect("no provider after the second call");
    assert!(std::sync::Arc::ptr_eq(&first, second), "the second call replaced the provider");
}
