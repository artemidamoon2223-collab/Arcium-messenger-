//! A relay with an onion address (docs/NET-MESSAGING.md, section 3a): reached
//! only through the onion path, never directly, and when Tor cannot be had
//! the connection fails with nothing tried directly. A relay with any other
//! address never touches the onion path. In the app the onion path is the
//! process's Tor client; here a stand-in records each address it is asked
//! for and opens plain TCP to a local relay instead.

use super::net_harness::*;
use super::*;
use crate::network::tor::{OnionPath, ONION_REQUEST_DEADLINE};
use crate::network::NetworkMessenger;
use relay::address::RelayAddress;
use relay::client::{Connector, RelayStream, TcpConnector, REQUEST_DEADLINE};
use std::time::Duration;

/// A well-formed v3 onion name (56 base32 characters).
fn onion_host() -> String {
    format!("{}.onion", "a".repeat(56))
}

/// Stands in for Tor: records the address it is asked for and connects to
/// `target` over TCP; with no target, fails as a Tor start that failed.
struct StandInTor {
    target: Option<String>,
    asked: Arc<Mutex<Vec<String>>>,
}

impl OnionPath for StandInTor {
    fn connector(&self) -> Result<Box<dyn Connector>, CoreError> {
        match &self.target {
            Some(target) => Ok(Box::new(Redirect {
                target: target.clone(),
                asked: Arc::clone(&self.asked),
            })),
            None => Err(CoreError::Network {
                msg: "Tor did not start: no network (stand-in)".into(),
            }),
        }
    }
}

struct Redirect {
    target: String,
    asked: Arc<Mutex<Vec<String>>>,
}

impl Connector for Redirect {
    fn connect(&self, addr: &str, timeout: Duration) -> std::io::Result<Box<dyn RelayStream>> {
        self.asked.lock().unwrap().push(addr.to_string());
        TcpConnector.connect(&self.target, timeout)
    }
}

/// An onion path that must never be asked: the relay is not an onion.
struct NoTor;

impl OnionPath for NoTor {
    fn connector(&self) -> Result<Box<dyn Connector>, CoreError> {
        panic!("a relay that is not an onion asked for Tor");
    }
}

/// `d` talking to `relay` over `path`.
fn over(d: &mut Device, relay: &str, path: Arc<dyn OnionPath>) {
    d.net = NetworkMessenger::with_onion_path(d.core.clone(), relay.to_string(), 0, 2000, path);
}

/// Alice and Bob over `relay` through `path`, contacts with a session, one
/// round trip done (as `connected`).
fn connected_over(relay: &str, path: Arc<dyn OnionPath>) -> (Device, Device) {
    let (mut alice, mut bob) = (Device::new(relay, 1), Device::new(relay, 2));
    over(&mut alice, relay, Arc::clone(&path));
    over(&mut bob, relay, path);
    alice.knows(&bob);
    bob.knows(&alice);
    bob.net.publish_prekeys().unwrap();
    alice.net.start_session(bob.pk.clone()).unwrap();
    settle(&[&alice, &bob]);
    (alice, bob)
}

/// Texts both ways over a V2 relay at an onion address: every connection
/// asks the onion path for exactly that address, and TLS to the pinned key
/// and AUTH work over it as over TCP.
#[test]
fn a_v2_relay_at_an_onion_address_is_reached_only_through_the_onion_path() {
    let (relay, direct) = start_relay_v2();
    let onion = RelayAddress::new(&onion_host(), direct.port(), *direct.tls_pin(), *direct.auth_pk()).unwrap();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let tor = Arc::new(StandInTor {
        target: Some(direct.socket_addr()),
        asked: Arc::clone(&asked),
    });
    let (alice, bob) = connected_over(&onion.to_string(), tor);
    alice.send(&bob, "a1", "over the onion");
    settle(&[&alice, &bob]);
    assert_eq!(bob.texts(&alice), vec!["over the onion"]);
    assert_eq!(alice.undelivered(&bob), 0);
    let asked = asked.lock().unwrap();
    assert!(!asked.is_empty());
    let expected = format!("{}:{}", onion_host(), direct.port());
    assert!(asked.iter().all(|a| *a == expected), "{asked:?}");
    assert_eq!(relay.canary_hits(), 0);
    relay.stop();
}

/// A development (V1) relay at an onion address goes through the onion path
/// too: an onion name never reaches this device's resolver.
#[test]
fn a_v1_relay_at_an_onion_address_is_reached_only_through_the_onion_path() {
    let relay = start_relay();
    let port = relay.addr().port();
    let onion = format!("{}:{port}", onion_host());
    let asked = Arc::new(Mutex::new(Vec::new()));
    let tor = Arc::new(StandInTor {
        target: Some(format!("127.0.0.1:{port}")),
        asked: Arc::clone(&asked),
    });
    let mut d = Device::new(&onion, 1);
    over(&mut d, &onion, tor);
    d.net.publish_prekeys().unwrap();
    assert_eq!(*asked.lock().unwrap(), vec![onion]);
    relay.stop();
}

/// When Tor cannot be had, every operation on an onion relay fails with
/// Tor's error, and nothing is tried directly: a direct attempt would fail
/// otherwise (this device cannot resolve an onion name), and the relay,
/// reachable directly, stores nothing.
#[test]
fn without_tor_an_onion_relay_fails_and_nothing_is_tried_directly() {
    let (relay, direct) = start_relay_v2();
    let onion = RelayAddress::new(&onion_host(), direct.port(), *direct.tls_pin(), *direct.auth_pk()).unwrap();
    let no_tor = || {
        Arc::new(StandInTor {
            target: None,
            asked: Arc::new(Mutex::new(Vec::new())),
        })
    };
    let v1 = format!("{}:{}", onion_host(), direct.port());
    for addr in [onion.to_string(), v1] {
        let mut d = Device::new(&addr, 1);
        over(&mut d, &addr, no_tor());
        let e = d.net.publish_prekeys().err().unwrap();
        assert!(e.to_string().contains("Tor did not start"), "{addr}: {e}");
        let r = d.sync();
        assert_eq!(r.errors.len(), 1, "{addr}: {:?}", r.errors);
        assert!(r.errors[0].contains("Tor did not start"), "{addr}: {:?}", r.errors);
        assert!(relay.stored(&d.pk.as_slice().try_into().unwrap()).is_empty());
    }
    relay.stop();
}

/// A relay at an ordinary address never asks for Tor ([`NoTor`] panics).
#[test]
fn a_relay_at_an_ordinary_address_never_asks_for_tor() {
    let (relay, direct) = start_relay_v2();
    let (alice, bob) = connected_over(&direct.to_string(), Arc::new(NoTor));
    alice.send(&bob, "a1", "direct");
    settle(&[&alice, &bob]);
    assert_eq!(bob.texts(&alice), vec!["direct"]);
    relay.stop();
}

/// An onion relay's requests get 60 s each; any other relay keeps 30 s.
#[test]
fn an_onion_relay_gets_the_longer_request_deadline() {
    let d = Device::new("127.0.0.1:1", 1);
    let onion = NetworkMessenger::with_onion_path(d.core.clone(), format!("{}:1", onion_host()), 0, 2000, Arc::new(NoTor));
    assert_eq!(onion.request_deadline(), ONION_REQUEST_DEADLINE);
    assert_eq!(d.net.request_deadline(), REQUEST_DEADLINE);
    assert_eq!(ONION_REQUEST_DEADLINE, Duration::from_secs(60));
}
