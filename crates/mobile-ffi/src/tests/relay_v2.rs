//! Devices over a `RELAY_PROTOCOL_V2` relay (`serve_v2`, real TLS on
//! loopback): messaging end to end, what the relay's mailbox authentication
//! keeps from everyone but a mailbox's owner (tracker R-9), and rounds that
//! fail on a wrong connection string without changing anything.

use super::net_harness::*;
use super::*;
use crate::network::NetworkMessenger;
use relay::address::RelayAddress;
use relay::auth::RelayKeys;
use relay::client::{ClientError, Connection};
use relay::protocol::ErrorCode;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(5);

fn key(d: &Device) -> [u8; 32] {
    d.pk.as_slice().try_into().unwrap()
}

fn unauthorized<T: std::fmt::Debug>(r: Result<T, ClientError>) -> bool {
    matches!(r, Err(ClientError::Refused(ErrorCode::Unauthorized)))
}

/// AUTH on a raw connection as `owner`, with the DH of `d`'s identity, as
/// `d`'s messenger computes it.
fn auth_as(conn: &mut Connection, owner: [u8; 32], d: &Device) -> Result<(), ClientError> {
    conn.authenticate(owner, |auth_pk| *d.core.identity_dh(auth_pk).unwrap().unwrap())
}

/// A messenger on `d`'s store for the relay at `relay`.
fn messenger(d: &Device, relay: &RelayAddress) -> Arc<NetworkMessenger> {
    NetworkMessenger::new(d.core.clone(), relay.to_string(), 0, 2000)
}

#[test]
fn identity_dh_is_the_x25519_of_the_identity_key_and_refuses_low_order_keys() {
    let d = Device::new("127.0.0.1:1", 1);
    let relay_sk = StaticSecret::random_from_rng(OsRng);
    let relay_pk = PublicKey::from(&relay_sk);
    let ours = d.core.identity_dh(relay_pk.as_bytes()).unwrap().expect("not low order");
    // What the relay computes with its secret and the device's public key.
    let theirs = relay_sk.diffie_hellman(&PublicKey::from(key(&d)));
    assert_eq!(&ours[..], theirs.as_bytes());
    // Zero, and one (a point of order 4), give all zeros.
    let mut one = [0u8; 32];
    one[0] = 1;
    for low in [[0u8; 32], one] {
        assert!(d.core.identity_dh(&low).unwrap().is_none(), "{low:?}");
    }
}

/// First contact, texts both ways and their receipts. Every round
/// authenticates (`settle` fails on any round error), and each device reads
/// and deletes its own mailbox.
#[test]
fn two_devices_exchange_texts_and_receipts_over_a_v2_relay() {
    let (relay, addr) = start_relay_v2();
    let addr = addr.to_string();
    // Bob publishes his bundle (PUT_BUNDLE, after AUTH); Alice fetches it
    // (GET_BUNDLE, no AUTH) and opens the session; both settle.
    let (alice, bob) = connected(&addr);
    alice.send(&bob, "a1", "hello bob");
    settle(&[&alice, &bob]);
    assert_eq!(bob.texts(&alice), vec!["hello bob"]);
    assert_eq!(alice.undelivered(&bob), 0, "Bob's receipt arrived");
    bob.send(&alice, "b1", "hello alice");
    settle(&[&alice, &bob]);
    assert_eq!(alice.texts(&bob), vec!["hello alice"]);
    assert_eq!(bob.undelivered(&alice), 0, "Alice's receipt arrived");
    assert!(relay.stored(&key(&alice)).is_empty());
    assert!(relay.stored(&key(&bob)).is_empty());
    assert_eq!(relay.canary_hits(), 0, "no plaintext reached the relay");
    relay.stop();
}

/// R-9: neither a connection without AUTH nor a third device, authenticated
/// as itself or claiming the owner's key, can read or delete Bob's mailbox
/// or replace his bundle.
#[test]
fn only_a_mailboxs_owner_can_read_or_delete_it_or_publish_its_bundle() {
    let (relay, addr) = start_relay_v2();
    let text = addr.to_string();
    let (alice, bob) = connected(&text);
    let mallory = Device::new(&text, 3);
    mallory.net.publish_prekeys().unwrap();
    let mallory_bundle = mallory.core.export_prekey_bundle().unwrap();
    let bob_key = key(&bob);
    alice.send(&bob, "a1", "for bob only");
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    let waiting = relay.stored(&bob_key);
    assert_eq!(waiting.len(), 1);
    let seqs: Vec<u64> = waiting.iter().map(|(seq, _)| *seq).collect();
    let bundle = Connection::connect_v2(&addr, TIMEOUT).unwrap().get_bundle(bob_key).unwrap();
    assert!(bundle.is_some());

    let mut anonymous = Connection::connect_v2(&addr, TIMEOUT).unwrap();
    assert!(unauthorized(anonymous.fetch(bob_key, 10)));
    assert!(unauthorized(anonymous.fetch_after(bob_key, 0, 10)));
    assert!(unauthorized(anonymous.delete(bob_key, seqs.clone())));
    assert!(unauthorized(anonymous.put_bundle(bob_key, mallory_bundle.clone())));

    let mut as_herself = Connection::connect_v2(&addr, TIMEOUT).unwrap();
    auth_as(&mut as_herself, key(&mallory), &mallory).unwrap();
    assert!(as_herself.fetch_after(key(&mallory), 0, 10).is_ok(), "her own mailbox");
    assert!(unauthorized(as_herself.fetch(bob_key, 10)));
    assert!(unauthorized(as_herself.fetch_after(bob_key, 0, 10)));
    assert!(unauthorized(as_herself.delete(bob_key, seqs.clone())));
    assert!(unauthorized(as_herself.put_bundle(bob_key, mallory_bundle.clone())));

    // Her secret gives a tag the relay refuses for Bob's key, and the
    // connection stays without an owner.
    let mut claiming = Connection::connect_v2(&addr, TIMEOUT).unwrap();
    assert!(unauthorized(auth_as(&mut claiming, bob_key, &mallory)));
    assert!(unauthorized(claiming.fetch_after(bob_key, 0, 10)));
    assert!(unauthorized(claiming.delete(bob_key, seqs)));
    assert!(unauthorized(claiming.put_bundle(bob_key, mallory_bundle)));

    assert_eq!(relay.stored(&bob_key), waiting, "nothing read out or deleted");
    assert_eq!(
        Connection::connect_v2(&addr, TIMEOUT).unwrap().get_bundle(bob_key).unwrap(),
        bundle,
        "Bob's bundle is unchanged"
    );
    // Bob's own messenger reads, answers and deletes.
    settle(&[&alice, &bob]);
    assert_eq!(bob.texts(&alice), vec!["for bob only"]);
    assert_eq!(alice.undelivered(&bob), 0);
    assert!(relay.stored(&bob_key).is_empty());
    relay.stop();
}

/// A relay whose TLS key is not the pinned one is never talked to: the round
/// ends with one network error, and nothing is sent, read or changed.
#[test]
fn a_wrong_pin_fails_the_round_with_a_network_error_and_changes_nothing() {
    let (relay, addr) = start_relay_v2();
    let (alice, bob) = connected(&addr.to_string());
    let carol = Device::new(&addr.to_string(), 3);
    alice.knows(&carol);
    carol.net.publish_prekeys().unwrap();
    alice.send(&bob, "a1", "waits for the right relay");
    let mut pin = *addr.tls_pin();
    pin[0] ^= 1;
    let wrong = messenger(
        &alice,
        &RelayAddress::new(addr.host(), addr.port(), pin, *addr.auth_pk()).unwrap(),
    );

    let r = wrong.sync();
    assert_eq!(r.errors.len(), 1, "{:?}", r.errors);
    assert!(r.errors[0].starts_with("network: relay TLS handshake failed"), "{:?}", r.errors);
    assert_eq!((r.published, r.fetched, r.accepted, r.delivered), (0, 0, 0, 0));
    assert!(matches!(wrong.publish_prekeys(), Err(CoreError::Network { .. })));
    assert!(matches!(
        wrong.start_session(carol.pk.clone()),
        Err(CoreError::Network { .. })
    ));
    assert!(!alice.core.has_session(local_session_handle(carol.pk.clone()).unwrap()).unwrap());
    assert!(relay.stored(&key(&bob)).is_empty(), "nothing was sent");
    assert_eq!(alice.undelivered(&bob), 1, "the text stays pending");

    // With the right connection string it goes out.
    settle(&[&alice, &bob]);
    assert_eq!(bob.texts(&alice), vec!["waits for the right relay"]);
    relay.stop();
}

/// The right TLS key with another relay's auth key: the relay refuses the
/// AUTH, and the round ends there with a network error.
#[test]
fn a_refused_auth_fails_the_round_with_a_network_error_and_changes_nothing() {
    let (relay, addr) = start_relay_v2();
    let (alice, bob) = connected(&addr.to_string());
    alice.send(&bob, "a1", "pending");
    bob.send(&alice, "b1", "for alice");
    assert!(bob.sync().errors.is_empty());
    let waiting = relay.stored(&key(&alice));
    assert_eq!(waiting.len(), 1);
    let other = RelayKeys::generate().unwrap().auth_public();
    let wrong = messenger(
        &alice,
        &RelayAddress::new(addr.host(), addr.port(), *addr.tls_pin(), other).unwrap(),
    );

    let r = wrong.sync();
    assert_eq!(r.errors, vec!["network: relay refused the request: Unauthorized".to_string()]);
    assert_eq!((r.published, r.fetched, r.accepted, r.delivered), (0, 0, 0, 0));
    assert!(matches!(wrong.publish_prekeys(), Err(CoreError::Network { .. })));
    assert!(relay.stored(&key(&bob)).is_empty(), "nothing was sent");
    assert_eq!(relay.stored(&key(&alice)), waiting, "nothing was read or deleted");
    assert_eq!(alice.undelivered(&bob), 1);
    assert!(alice.texts(&bob).is_empty());

    settle(&[&alice, &bob]);
    assert_eq!(alice.texts(&bob), vec!["for alice"]);
    assert_eq!(bob.texts(&alice), vec!["pending"]);
    relay.stop();
}

/// An auth key of low order would give an all-zero DH output, so a tag
/// anyone could compute: the messenger refuses it, and so does the relay
/// client; nothing changes.
#[test]
fn an_auth_key_of_low_order_fails_the_round_and_changes_nothing() {
    let (relay, addr) = start_relay_v2();
    let (alice, bob) = connected(&addr.to_string());
    alice.send(&bob, "a1", "pending");
    let wrong = messenger(
        &alice,
        &RelayAddress::new(addr.host(), addr.port(), *addr.tls_pin(), [0; 32]).unwrap(),
    );

    let r = wrong.sync();
    assert_eq!(
        r.errors,
        vec!["network: cannot authenticate to the relay: its auth key is of low order".to_string()]
    );
    assert_eq!((r.published, r.fetched), (0, 0));
    assert!(relay.stored(&key(&bob)).is_empty(), "nothing was sent");
    assert_eq!(alice.undelivered(&bob), 1);
    relay.stop();
}

/// A string with the V2 prefix that does not parse is refused; it is never
/// tried as `host:port`, even with a V1 relay listening where it points.
#[test]
fn a_malformed_v2_string_is_never_tried_as_v1() {
    let v1 = start_relay();
    let port = v1.addr().port();
    let malformed = format!(
        "arcium-relay-v2:127.0.0.1:{port}:{}:{}",
        "AB".repeat(32), // uppercase: refused
        "ab".repeat(32)
    );
    let d = Device::new(&malformed, 1);
    let r = d.sync();
    assert_eq!(
        r.errors,
        vec!["network: invalid relay address: TLS pin is not 64 lowercase hex digits".to_string()]
    );
    assert!(matches!(d.net.publish_prekeys(), Err(CoreError::Network { .. })));
    let mut plain = Connection::connect(&v1.addr().to_string(), TIMEOUT).unwrap();
    assert_eq!(plain.get_bundle(key(&d)).unwrap(), None, "the V1 relay heard nothing");
    v1.stop();
}
