//! `RELAY_PROTOCOL_V2` end to end: a relay from `serve_v2`, clients from
//! `Connection::connect_v2`, over real TLS on loopback.

use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use x25519_dalek::{PublicKey, StaticSecret};

use crate::address::RelayAddress;
use crate::auth::RelayKeys;
use crate::client::{ClientError, Connection};
use crate::protocol::*;
use crate::server::{serve, serve_v2, RelayConfig, RelayHandle};

struct Identity {
    sk: StaticSecret,
    pk: Key,
}

fn identity(byte: u8) -> Identity {
    let sk = StaticSecret::from([byte; 32]);
    let pk = PublicKey::from(&sk).to_bytes();
    Identity { sk, pk }
}

/// What the app's closure does: DH of its identity secret with the relay's
/// auth key.
fn dh(sk: &StaticSecret) -> impl FnOnce(&[u8; 32]) -> [u8; 32] + '_ {
    move |auth_pk| sk.diffie_hellman(&PublicKey::from(*auth_pk)).to_bytes()
}

fn start_v2(config: RelayConfig, keys: &RelayKeys) -> (RelayHandle, RelayAddress) {
    let relay = serve_v2(TcpListener::bind("127.0.0.1:0").unwrap(), config, keys).unwrap();
    let addr = keys.address("127.0.0.1", relay.addr().port()).unwrap();
    (relay, addr)
}

fn conn(addr: &RelayAddress) -> Connection {
    Connection::connect_v2(addr, Duration::from_secs(5)).unwrap()
}

fn unauthorized<T: std::fmt::Debug>(r: Result<T, ClientError>) -> bool {
    matches!(r, Err(ClientError::Refused(ErrorCode::Unauthorized)))
}

#[test]
fn v2_round_trip_send_auth_fetch_delete_and_bundle() {
    let keys = RelayKeys::generate().unwrap();
    let (relay, addr) = start_v2(RelayConfig::default(), &keys);
    let bob = identity(2);
    let mut sender = conn(&addr);
    let s1 = sender.send(bob.pk, b"one".to_vec()).unwrap();
    let s2 = sender.send(bob.pk, b"two".to_vec()).unwrap();
    assert_eq!(sender.send(bob.pk, b"one".to_vec()).unwrap(), s1, "duplicate");

    let mut b = conn(&addr);
    b.authenticate(bob.pk, dh(&bob.sk)).unwrap();
    assert_eq!(
        b.fetch(bob.pk, 10).unwrap(),
        vec![(s1, b"one".to_vec()), (s2, b"two".to_vec())]
    );
    assert_eq!(b.fetch_after(bob.pk, s1, 10).unwrap(), vec![(s2, b"two".to_vec())]);
    b.delete(bob.pk, vec![s1]).unwrap();
    assert_eq!(relay.stored(&bob.pk), vec![(s2, b"two".to_vec())]);
    b.put_bundle(bob.pk, vec![5; 204]).unwrap();
    assert_eq!(sender.get_bundle(bob.pk).unwrap(), Some(vec![5; 204]));
    assert_eq!(sender.get_bundle([9; 32]).unwrap(), None);
    relay.stop();
}

#[test]
fn a_wrong_pin_fails_the_handshake() {
    let keys = RelayKeys::generate().unwrap();
    let (relay, addr) = start_v2(RelayConfig::default(), &keys);
    let mut pin = *addr.tls_pin();
    pin[0] ^= 1;
    let wrong = RelayAddress::new(addr.host(), addr.port(), pin, *addr.auth_pk()).unwrap();
    let err = Connection::connect_v2(&wrong, Duration::from_secs(5)).err().expect("refused");
    assert!(
        matches!(err, ClientError::Tls(rustls::Error::InvalidCertificate(_))),
        "{err:?}"
    );
    // The pin of another relay's key fails the same way.
    let other = RelayKeys::generate().unwrap().address(addr.host(), addr.port()).unwrap();
    let err = Connection::connect_v2(&other, Duration::from_secs(5)).err().expect("refused");
    assert!(matches!(err, ClientError::Tls(_)), "{err:?}");
    // The right pin works.
    assert_eq!(conn(&addr).get_bundle([1; 32]).unwrap(), None);
    relay.stop();
}

#[test]
fn a_wrong_identity_or_auth_key_is_unauthorized_and_changes_nothing() {
    let keys = RelayKeys::generate().unwrap();
    let (relay, addr) = start_v2(RelayConfig::default(), &keys);
    let (bob, mallory) = (identity(2), identity(3));
    let s1 = conn(&addr).send(bob.pk, b"one".to_vec()).unwrap();

    // Bob's key, Mallory's secret.
    let mut m = conn(&addr);
    assert!(unauthorized(m.authenticate(bob.pk, dh(&mallory.sk))));
    assert!(unauthorized(m.fetch(bob.pk, 10)));
    assert!(unauthorized(m.fetch_after(bob.pk, 0, 10)));
    assert!(unauthorized(m.delete(bob.pk, vec![s1])));
    assert!(unauthorized(m.put_bundle(bob.pk, vec![6; 10])));

    // Bob's secret, but another relay's auth key (a wrong connection string
    // with the right pin): the relay computes another key and refuses.
    let other_auth = RelayKeys::generate().unwrap().auth_public();
    let misaddressed = RelayAddress::new(addr.host(), addr.port(), *addr.tls_pin(), other_auth).unwrap();
    let mut w = conn(&misaddressed);
    assert!(unauthorized(w.authenticate(bob.pk, dh(&bob.sk))));
    assert!(unauthorized(w.fetch(bob.pk, 10)));

    assert_eq!(relay.stored(&bob.pk), vec![(s1, b"one".to_vec())], "nothing deleted");
    assert_eq!(conn(&addr).get_bundle(bob.pk).unwrap(), None, "no bundle published");
    relay.stop();
}

#[test]
fn after_auth_another_owners_mailbox_and_bundle_are_unauthorized() {
    let keys = RelayKeys::generate().unwrap();
    let (relay, addr) = start_v2(RelayConfig::default(), &keys);
    let (alice, bob) = (identity(1), identity(2));
    let mut sender = conn(&addr);
    let to_alice = sender.send(alice.pk, b"for alice".to_vec()).unwrap();
    let to_bob = sender.send(bob.pk, b"for bob".to_vec()).unwrap();
    let mut a = conn(&addr);
    a.authenticate(alice.pk, dh(&alice.sk)).unwrap();
    a.put_bundle(alice.pk, vec![1; 100]).unwrap();

    let mut b = conn(&addr);
    b.authenticate(bob.pk, dh(&bob.sk)).unwrap();
    assert!(unauthorized(b.fetch(alice.pk, 10)));
    assert!(unauthorized(b.fetch_after(alice.pk, 0, 10)));
    assert!(unauthorized(b.delete(alice.pk, vec![to_alice])));
    assert!(unauthorized(b.put_bundle(alice.pk, vec![9; 100])));
    // Bob's own mailbox, on the same connection.
    assert_eq!(b.fetch(bob.pk, 10).unwrap(), vec![(to_bob, b"for bob".to_vec())]);

    assert_eq!(relay.stored(&alice.pk), vec![(to_alice, b"for alice".to_vec())]);
    assert_eq!(sender.get_bundle(alice.pk).unwrap(), Some(vec![1; 100]));
    relay.stop();
}

#[test]
fn without_auth_only_send_and_get_bundle_are_answered() {
    let keys = RelayKeys::generate().unwrap();
    let (relay, addr) = start_v2(RelayConfig::default(), &keys);
    let bob = identity(2);
    let mut c = conn(&addr);
    let s = c.send(bob.pk, b"x".to_vec()).unwrap();
    assert_eq!(c.get_bundle(bob.pk).unwrap(), None);
    assert!(unauthorized(c.fetch(bob.pk, 10)));
    assert!(unauthorized(c.fetch_after(bob.pk, 0, 10)));
    assert!(unauthorized(c.delete(bob.pk, vec![s])));
    assert!(unauthorized(c.put_bundle(bob.pk, vec![1; 10])));
    // The refusals did not close the connection.
    let t = c.send(bob.pk, b"y".to_vec()).unwrap();
    assert_eq!(relay.stored(&bob.pk), vec![(s, b"x".to_vec()), (t, b"y".to_vec())]);
    assert_eq!(c.get_bundle(bob.pk).unwrap(), None);
    relay.stop();
}

/// One AUTH is checked per connection. After a valid one, a second is
/// refused and the first still holds; after a wrong one, even a valid one is
/// refused.
#[test]
fn auth_is_checked_once_per_connection() {
    let keys = RelayKeys::generate().unwrap();
    let (relay, addr) = start_v2(RelayConfig::default(), &keys);
    let (alice, bob) = (identity(1), identity(2));
    let bob_shared = dh(&bob.sk)(addr.auth_pk());

    let mut b = conn(&addr);
    b.authenticate(bob.pk, dh(&bob.sk)).unwrap();
    let again = b.tag_for(&bob.pk, &bob_shared);
    assert!(unauthorized(b.send_auth(bob.pk, again)), "the same valid tag again");
    assert!(unauthorized(b.authenticate(alice.pk, dh(&alice.sk))), "another owner");
    assert!(b.fetch(bob.pk, 1).unwrap().is_empty(), "still acts for bob");
    assert!(unauthorized(b.fetch(alice.pk, 1)));

    let mut c = conn(&addr);
    assert!(unauthorized(c.authenticate(bob.pk, dh(&alice.sk))));
    assert!(unauthorized(c.authenticate(bob.pk, dh(&bob.sk))), "valid, but after a wrong one");
    assert!(unauthorized(c.fetch(bob.pk, 1)));
    relay.stop();
}

/// A tag is bound to its connection's challenge and TLS exporter: replayed on
/// another connection it is refused, while on its own it is accepted.
#[test]
fn a_tag_replayed_on_another_connection_fails() {
    let keys = RelayKeys::generate().unwrap();
    let (relay, addr) = start_v2(RelayConfig::default(), &keys);
    let bob = identity(2);
    conn(&addr).send(bob.pk, b"x".to_vec()).unwrap();
    let shared = dh(&bob.sk)(addr.auth_pk());

    let mut first = conn(&addr);
    let tag = first.tag_for(&bob.pk, &shared);
    let mut second = conn(&addr);
    assert_ne!(second.tag_for(&bob.pk, &shared), tag, "another challenge and exporter");
    assert!(unauthorized(second.send_auth(bob.pk, tag)));
    assert!(unauthorized(second.fetch(bob.pk, 10)));

    first.send_auth(bob.pk, tag).unwrap();
    assert_eq!(first.fetch(bob.pk, 10).unwrap().len(), 1);
    relay.stop();
}

/// With a database file, a V2 relay keeps what it accepted across a restart,
/// with its keys read back from their file: the connection string's pin and
/// auth key stay valid.
#[test]
fn persistence_works_under_v2() {
    let dir = tempfile::tempdir().unwrap();
    let config = RelayConfig {
        db: Some(dir.path().join("relay.db")),
        ..RelayConfig::default()
    };
    let keys = RelayKeys::generate().unwrap();
    let key_file = dir.path().join("relay.keys");
    keys.write_new(&key_file).unwrap();
    let bob = identity(2);
    let (relay, addr) = start_v2(config.clone(), &keys);
    let s1 = conn(&addr).send(bob.pk, b"one".to_vec()).unwrap();
    let s2 = conn(&addr).send(bob.pk, b"two".to_vec()).unwrap();
    let mut b = conn(&addr);
    b.authenticate(bob.pk, dh(&bob.sk)).unwrap();
    b.put_bundle(bob.pk, vec![5; 204]).unwrap();
    b.delete(bob.pk, vec![s1]).unwrap();
    relay.stop();

    let keys = RelayKeys::read(&key_file).unwrap();
    let (again, addr2) = start_v2(config, &keys);
    assert_eq!(addr2.tls_pin(), addr.tls_pin());
    assert_eq!(addr2.auth_pk(), addr.auth_pk());
    let mut b = conn(&addr2);
    b.authenticate(bob.pk, dh(&bob.sk)).unwrap();
    assert_eq!(b.fetch(bob.pk, 10).unwrap(), vec![(s2, b"two".to_vec())]);
    assert_eq!(b.get_bundle(bob.pk).unwrap(), Some(vec![5; 204]));
    again.stop();
}

/// V1 is unchanged: it answers AUTH with BAD_REQUEST, as an operation it
/// does not know. The versions do not talk to each other.
#[test]
fn v1_refuses_auth_and_the_versions_do_not_mix() {
    let v1 = serve(TcpListener::bind("127.0.0.1:0").unwrap(), RelayConfig::default()).unwrap();
    let mut raw = TcpStream::connect(v1.addr()).unwrap();
    let auth = Request::Auth {
        owner: [1; 32],
        tag: [2; 32],
    };
    write_frame(&mut raw, &auth.encode()).unwrap();
    assert_eq!(read_frame(&mut raw).unwrap().unwrap(), vec![2]);

    let keys = RelayKeys::generate().unwrap();
    let to_v1 = keys.address("127.0.0.1", v1.addr().port()).unwrap();
    assert!(Connection::connect_v2(&to_v1, Duration::from_secs(5)).is_err());
    let (v2, addr) = start_v2(RelayConfig::default(), &keys);
    assert!(Connection::connect(&addr.socket_addr(), Duration::from_secs(5))
        .and_then(|mut c| c.send([2; 32], vec![1]))
        .is_err());
    assert!(v2.stored(&[2; 32]).is_empty());
    v1.stop();
    v2.stop();
}

/// The tag is bound to the connection's TLS exporter, not only to its
/// challenge: a tag made with this connection's challenge but another
/// connection's exporter is refused. This is what stops a relay that pins
/// its own TLS key, but names the real relay's auth key, from passing on
/// the real relay's challenge and reusing the victim's tag there.
#[test]
fn a_tag_with_another_connections_exporter_is_refused() {
    let keys = RelayKeys::generate().unwrap();
    let (relay, addr) = start_v2(RelayConfig::default(), &keys);
    let bob = identity(2);
    let shared = dh(&bob.sk)(addr.auth_pk());
    let mut victim = conn(&addr);
    let other = conn(&addr);
    let (challenge, own_exporter) = victim.binding();
    let (_, other_exporter) = other.binding();
    assert_ne!(own_exporter, other_exporter);
    let wrong = crate::auth::auth_tag(&shared, &challenge, &other_exporter, &bob.pk).unwrap();
    assert!(unauthorized(victim.send_auth(bob.pk, wrong)));
    let mut fresh = conn(&addr);
    let (challenge, exporter) = fresh.binding();
    let right = crate::auth::auth_tag(&shared, &challenge, &exporter, &bob.pk).unwrap();
    fresh.send_auth(bob.pk, right).unwrap();
    relay.stop();
}

/// An owner key with the top bit set is refused even with a tag that is
/// valid for it: X25519 ignores that bit, so the holder of a key would
/// otherwise also open the mailbox of its altered twin.
#[test]
fn an_owner_key_with_the_top_bit_set_is_refused() {
    let keys = RelayKeys::generate().unwrap();
    let (relay, addr) = start_v2(RelayConfig::default(), &keys);
    let bob = identity(2);
    let shared = dh(&bob.sk)(addr.auth_pk());
    let mut twin = bob.pk;
    twin[31] |= 0x80;
    let mut c = conn(&addr);
    let (challenge, exporter) = c.binding();
    let tag = crate::auth::auth_tag(&shared, &challenge, &exporter, &twin).unwrap();
    assert!(unauthorized(c.send_auth(twin, tag)));
    relay.stop();
}

/// A client that opens a TCP connection and never finishes the TLS
/// handshake is closed after `handshake_timeout`, not after each idle read.
#[test]
fn an_unfinished_handshake_is_closed_at_the_deadline() {
    use std::io::Read;
    let keys = RelayKeys::generate().unwrap();
    let (relay, addr) = start_v2(
        RelayConfig {
            handshake_timeout: Duration::from_millis(200),
            ..RelayConfig::default()
        },
        &keys,
    );
    let mut raw = TcpStream::connect(("127.0.0.1", addr.port())).unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let started = std::time::Instant::now();
    let mut buf = [0u8; 16];
    let n = raw.read(&mut buf).unwrap_or(0);
    assert_eq!(n, 0, "closed without an answer");
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    relay.stop();
}

/// One IP address may hold at most `max_connections_per_address`
/// connections; the next is closed at once, and a freed slot is usable again.
#[test]
fn connections_from_one_address_are_capped() {
    use std::io::Read;
    let relay = serve(
        TcpListener::bind("127.0.0.1:0").unwrap(),
        RelayConfig {
            max_connections_per_address: 2,
            ..RelayConfig::default()
        },
    )
    .unwrap();
    let a = TcpStream::connect(relay.addr()).unwrap();
    let _b = TcpStream::connect(relay.addr()).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    let mut third = TcpStream::connect(relay.addr()).unwrap();
    third.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(third.read(&mut buf).unwrap_or(0), 0, "the third is closed");
    drop(a);
    std::thread::sleep(Duration::from_millis(200));
    let mut c = Connection::connect(&relay.addr().to_string(), Duration::from_secs(5)).unwrap();
    assert!(c.fetch([1; 32], 1).unwrap().is_empty(), "a freed slot serves again");
    relay.stop();
}

/// A database a V2 relay has served is refused by a V1 relay, which would
/// open its mailboxes to anyone.
#[test]
fn a_v1_relay_refuses_a_v2_database() {
    let dir = tempfile::tempdir().unwrap();
    let config = RelayConfig {
        db: Some(dir.path().join("relay.db")),
        ..RelayConfig::default()
    };
    let keys = RelayKeys::generate().unwrap();
    let (relay, _addr) = start_v2(config.clone(), &keys);
    relay.stop();
    let err = serve(TcpListener::bind("127.0.0.1:0").unwrap(), config).err().expect("refused");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}
