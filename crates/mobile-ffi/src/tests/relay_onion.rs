//! A relay with an onion address (docs/NET-MESSAGING.md, section 3a): reached
//! only through the onion path, never directly, and when Tor cannot be had
//! the connection fails with nothing tried directly. A relay with any other
//! address never touches the onion path. In the app the onion path is the
//! process's Tor client and the direct path is TCP; here both are stand-ins
//! that record every address they are asked for, and the onion stand-in
//! opens plain TCP to a local relay.

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

type Asked = Arc<Mutex<Vec<String>>>;

/// Stands in for Tor: records the address it is asked for and connects to
/// `target` over TCP; with no target, fails as a Tor start that failed.
struct StandInTor {
    target: Option<String>,
    asked: Asked,
    /// How long each connection waits before it opens, as Tor's start and a
    /// rendezvous circuit would.
    delay: Duration,
}

impl OnionPath for StandInTor {
    fn connector(&self) -> Result<Box<dyn Connector>, CoreError> {
        match &self.target {
            Some(target) => Ok(Box::new(Redirect {
                target: Some(target.clone()),
                asked: Arc::clone(&self.asked),
                delay: self.delay,
            })),
            None => Err(CoreError::Network {
                msg: "Tor did not start: no network (stand-in)".into(),
            }),
        }
    }
}

/// Records each address asked for, then connects over TCP to `target`, or
/// to the address itself when there is none (the direct path).
struct Redirect {
    target: Option<String>,
    asked: Asked,
    delay: Duration,
}

impl Connector for Redirect {
    fn connect(&self, addr: &str, timeout: Duration) -> std::io::Result<Box<dyn RelayStream>> {
        self.asked.lock().unwrap().push(addr.to_string());
        std::thread::sleep(self.delay);
        TcpConnector.connect(self.target.as_deref().unwrap_or(addr), timeout)
    }
}

/// An onion path that must never be asked: the relay is not an onion.
struct NoTor;

impl OnionPath for NoTor {
    fn connector(&self) -> Result<Box<dyn Connector>, CoreError> {
        panic!("a relay that is not an onion asked for Tor");
    }
}

/// `d` talking to `relay` over `onion`, with a direct path that records
/// every address it is asked for; returns that record.
fn over(d: &mut Device, relay: &str, onion: Arc<dyn OnionPath>) -> Asked {
    let direct: Asked = Arc::new(Mutex::new(Vec::new()));
    let path = Arc::new(Redirect {
        target: None,
        asked: Arc::clone(&direct),
        delay: Duration::ZERO,
    });
    d.net = NetworkMessenger::with_paths(d.core.clone(), relay.to_string(), 0, 2000, onion, path);
    direct
}

/// Alice and Bob over `relay` through `onion`, contacts with a session, one
/// round trip done (as `connected`); and the records of their direct paths.
fn connected_over(relay: &str, onion: Arc<dyn OnionPath>) -> (Device, Device, Asked, Asked) {
    let (mut alice, mut bob) = (Device::new(relay, 1), Device::new(relay, 2));
    let alice_direct = over(&mut alice, relay, Arc::clone(&onion));
    let bob_direct = over(&mut bob, relay, onion);
    alice.knows(&bob);
    bob.knows(&alice);
    bob.net.publish_prekeys().unwrap();
    alice.net.start_session(bob.pk.clone()).unwrap();
    settle(&[&alice, &bob]);
    (alice, bob, alice_direct, bob_direct)
}

/// Texts both ways over a V2 relay at an onion address: every connection
/// asks the onion path for exactly that address, none asks the direct path,
/// every one gets the 60 s request deadline, and TLS to the pinned key and
/// AUTH work over it as over TCP.
#[test]
fn a_v2_relay_at_an_onion_address_is_reached_only_through_the_onion_path() {
    let (relay, direct) = start_relay_v2();
    let onion = RelayAddress::new(&onion_host(), direct.port(), *direct.tls_pin(), *direct.auth_pk()).unwrap();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let tor = Arc::new(StandInTor {
        target: Some(direct.socket_addr()),
        asked: Arc::clone(&asked),
        delay: Duration::ZERO,
    });
    let (alice, bob, alice_direct, bob_direct) = connected_over(&onion.to_string(), tor);
    alice.send(&bob, "a1", "over the onion");
    settle(&[&alice, &bob]);
    assert_eq!(bob.texts(&alice), vec!["over the onion"]);
    assert_eq!(alice.undelivered(&bob), 0);
    let asked = asked.lock().unwrap();
    assert!(!asked.is_empty());
    let expected = format!("{}:{}", onion_host(), direct.port());
    assert!(asked.iter().all(|a| *a == expected), "{asked:?}");
    assert!(alice_direct.lock().unwrap().is_empty(), "a direct attempt");
    assert!(bob_direct.lock().unwrap().is_empty(), "a direct attempt");
    for d in [&alice, &bob] {
        assert_eq!(*d.net.last_deadline.lock().unwrap(), Some(ONION_REQUEST_DEADLINE));
    }
    assert_eq!(ONION_REQUEST_DEADLINE, Duration::from_secs(60));
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
        delay: Duration::ZERO,
    });
    let mut d = Device::new(&onion, 1);
    let direct = over(&mut d, &onion, tor);
    d.net.publish_prekeys().unwrap();
    assert_eq!(*asked.lock().unwrap(), vec![onion]);
    assert!(direct.lock().unwrap().is_empty(), "a direct attempt");
    relay.stop();
}

/// When Tor cannot be had, every operation on an onion relay (V2 and V1, any
/// case, final dots) fails with Tor's error, and the direct path is never
/// asked.
#[test]
fn without_tor_an_onion_relay_fails_and_nothing_is_tried_directly() {
    let (relay, direct) = start_relay_v2();
    let onion = RelayAddress::new(&onion_host(), direct.port(), *direct.tls_pin(), *direct.auth_pk()).unwrap();
    let port = direct.port();
    let host = onion_host();
    let v1 = [
        format!("{host}:{port}"),
        format!("{}:{port}", host.to_uppercase()),
        format!("{host}.:{port}"),
        format!("{host}..:{port}"),
    ];
    for addr in std::iter::once(onion.to_string()).chain(v1) {
        let no_tor = Arc::new(StandInTor {
            target: None,
            asked: Arc::new(Mutex::new(Vec::new())),
            delay: Duration::ZERO,
        });
        let mut d = Device::new(&addr, 1);
        let direct = over(&mut d, &addr, no_tor);
        let e = d.net.publish_prekeys().err().unwrap();
        assert!(e.to_string().contains("Tor did not start"), "{addr}: {e}");
        let r = d.sync();
        assert_eq!(r.errors.len(), 1, "{addr}: {:?}", r.errors);
        assert!(r.errors[0].contains("Tor did not start"), "{addr}: {:?}", r.errors);
        assert!(direct.lock().unwrap().is_empty(), "{addr}: a direct attempt");
    }
    relay.stop();
}

/// A relay at an ordinary address never asks for Tor ([`NoTor`] panics):
/// every connection goes the direct way, to the address as given, with the
/// 30 s request deadline.
#[test]
fn a_relay_at_an_ordinary_address_never_asks_for_tor() {
    let (relay, direct) = start_relay_v2();
    let (alice, bob, alice_direct, _) = connected_over(&direct.to_string(), Arc::new(NoTor));
    alice.send(&bob, "a1", "direct");
    settle(&[&alice, &bob]);
    assert_eq!(bob.texts(&alice), vec!["direct"]);
    let asked = alice_direct.lock().unwrap();
    assert!(!asked.is_empty());
    assert!(asked.iter().all(|a| *a == direct.socket_addr()), "{asked:?}");
    assert_eq!(*alice.net.last_deadline.lock().unwrap(), Some(REQUEST_DEADLINE));
    relay.stop();
}

/// The round's budget counts its requests from when its connection is open,
/// not the wait for it: over a slow onion path (Tor's start, a rendezvous
/// circuit) that takes longer than the whole budget, the round still sends
/// the pending text. Budget scaled down to 300 ms.
#[test]
fn the_wait_for_an_onion_connection_does_not_use_up_the_round_budget() {
    let (relay, direct) = start_relay_v2();
    let onion = RelayAddress::new(&onion_host(), direct.port(), *direct.tls_pin(), *direct.auth_pk()).unwrap();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let fast = Arc::new(StandInTor {
        target: Some(direct.socket_addr()),
        asked: Arc::clone(&asked),
        delay: Duration::ZERO,
    });
    let (mut alice, bob, _, _) = connected_over(&onion.to_string(), fast);
    let slow = Arc::new(StandInTor {
        target: Some(direct.socket_addr()),
        asked,
        delay: Duration::from_millis(600),
    });
    over(&mut alice, &onion.to_string(), slow);
    alice
        .net
        .set_limits(Duration::from_secs(5), Duration::from_millis(300), Duration::from_secs(300));
    alice.send(&bob, "a1", "after a slow start");
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert!(r.published >= 1, "nothing sent: {r:?}");
    assert_eq!(relay.stored(&key(&bob)).len(), 1);
    relay.stop();
}

fn key(d: &Device) -> [u8; 32] {
    d.pk.as_slice().try_into().unwrap()
}
