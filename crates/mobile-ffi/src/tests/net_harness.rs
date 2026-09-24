//! Test infrastructure for the network tests: independent devices, a real
//! relay on a TCP port, and a proxy that breaks chosen relay operations.

use super::*;
use crate::network::wire::Envelope;
use crate::network::{NetworkMessenger, SyncReport};
use relay::protocol::{read_frame, write_frame};
use relay::server::{serve, RelayConfig, RelayHandle};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};

/// Plaintext every test text contains; the relay alerts if it ever stores it.
pub const CANARY: &[u8] = b"CANARY-PLAINTEXT-7f3a";

pub fn start_relay() -> RelayHandle {
    serve(
        TcpListener::bind("127.0.0.1:0").unwrap(),
        RelayConfig {
            canary: Some(CANARY.to_vec()),
            ..RelayConfig::default()
        },
    )
    .unwrap()
}

/// One device: its own database file, identity and messenger.
pub struct Device {
    pub path: String,
    pub byte: u8,
    pub core: Arc<ArciumCore>,
    pub net: Arc<NetworkMessenger>,
    pub pk: Vec<u8>,
    /// Messages this device's syncs accepted cryptographically, in total.
    pub accepted: AtomicU32,
}

impl Device {
    pub fn new(relay: &str, byte: u8) -> Self {
        let path = tempdir()
            .unwrap()
            .keep()
            .join("db")
            .to_str()
            .unwrap()
            .to_string();
        let core = ArciumCore::new(path.clone(), key32(byte)).unwrap();
        core.save_identity(Identity::generate()).unwrap();
        Self::open(path, byte, relay, core)
    }

    /// The device stored at `path`, as a new process would open it.
    pub fn reopen(path: &str, byte: u8, relay: &str) -> Self {
        let core = ArciumCore::new(path.to_string(), key32(byte)).unwrap();
        Self::open(path.to_string(), byte, relay, core)
    }

    fn open(path: String, byte: u8, relay: &str, core: Arc<ArciumCore>) -> Self {
        // Retransmit on every sync: tests decide timing by calling sync.
        let net = NetworkMessenger::new(core.clone(), relay.to_string(), 0, 2000);
        let pk = core.contact_card().unwrap()[1..33].to_vec();
        Self {
            path,
            byte,
            core,
            net,
            pk,
            accepted: AtomicU32::new(0),
        }
    }

    /// The same device after a restart: a new core on the same file.
    pub fn restart(&self, relay: &str) -> Self {
        Self::reopen(&self.path, self.byte, relay)
    }

    /// Pins `other`'s card, as if exchanged out of band.
    pub fn knows(&self, other: &Device) {
        self.core
            .add_contact(other.core.contact_card().unwrap())
            .unwrap();
    }

    pub fn sync(&self) -> SyncReport {
        let r = self.net.sync();
        self.accepted.fetch_add(r.accepted, Ordering::SeqCst);
        r
    }

    pub fn accepted_total(&self) -> u32 {
        self.accepted.load(Ordering::SeqCst)
    }

    pub fn send(&self, to: &Device, id: &str, text: &str) -> Vec<u8> {
        let body = [text.as_bytes(), CANARY].concat();
        self.net
            .send_text(to.pk.clone(), id.as_bytes().to_vec(), body)
            .unwrap()
            .message_id
    }

    /// Texts received from `from`, without the canary suffix.
    pub fn texts(&self, from: &Device) -> Vec<String> {
        self.net
            .received_texts(from.pk.clone())
            .unwrap()
            .into_iter()
            .map(|t| String::from_utf8(t.text[..t.text.len() - CANARY.len()].to_vec()).unwrap())
            .collect()
    }

    pub fn undelivered(&self, to: &Device) -> usize {
        self.net.undelivered(to.pk.clone()).unwrap().len()
    }

    pub fn generation_with(&self, peer: &Device) -> u64 {
        let our = self.core.our_identity_pk().unwrap();
        let (mut store, _messenger) = self.core.lock().unwrap();
        let binding = core_protocol::checkpoint::SessionBinding {
            our_identity_pk: our,
            peer_identity_pk: peer.pk.as_slice().try_into().unwrap(),
        };
        core_protocol::durable::DurableSession::load(
            &mut core_protocol::durable::S1CheckpointStore::new(&mut store),
            &binding,
        )
        .unwrap()
        .expect("session")
        .generation()
    }
}

/// Alice and Bob, contacts of each other, with a session Alice started and
/// Bob accepted, and one round trip done.
pub fn connected(relay: &str) -> (Device, Device) {
    let (alice, bob) = (Device::new(relay, 1), Device::new(relay, 2));
    alice.knows(&bob);
    bob.knows(&alice);
    bob.net.publish_prekeys().unwrap();
    alice.net.start_session(bob.pk.clone()).unwrap();
    settle(&[&alice, &bob]);
    (alice, bob)
}

/// Syncs every device in turn until a round changes nothing.
pub fn settle(devices: &[&Device]) {
    for _ in 0..10 {
        // Every device syncs every round (no short-circuit).
        let quiet = devices.iter().fold(true, |quiet, d| {
            let r = d.sync();
            assert!(r.errors.is_empty(), "{:?}", r.errors);
            r.accepted == 0
                && r.sessions_accepted == 0
                && r.delivered == 0
                && r.fetched == 0
                && r.published == 0
                && quiet
        });
        if quiet {
            return;
        }
    }
    panic!("devices did not settle");
}

/// Stores `env` in `to`'s mailbox directly, as a network attacker could.
pub fn inject(relay: &str, to: &Device, env: Vec<u8>) {
    relay::client::Connection::connect(relay, std::time::Duration::from_secs(2))
        .unwrap()
        .send(to.pk.as_slice().try_into().unwrap(), env)
        .unwrap();
}

/// Message envelopes currently stored for `to`.
pub fn stored_messages(relay: &RelayHandle, to: &Device) -> Vec<Vec<u8>> {
    relay
        .stored(&to.pk.as_slice().try_into().unwrap())
        .into_iter()
        .filter_map(|(_, e)| match Envelope::decode(&e) {
            Some(Envelope::Message { wire, .. }) => Some(wire),
            _ => None,
        })
        .collect()
}

/// What the proxy breaks for the next request with the armed operation byte.
#[derive(Clone, Copy)]
pub enum Cut {
    /// The request never reaches the relay.
    Request,
    /// The relay handles the request; its response never arrives.
    Response,
}

/// A TCP proxy in front of a relay. Arm it with an operation byte (see
/// `relay::protocol`) and it breaks the next such request, then disarms.
pub struct Proxy {
    pub addr: String,
    armed: Arc<AtomicU8>,
    mode: Arc<AtomicU8>,
}

impl Proxy {
    pub fn start(relay: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let armed = Arc::new(AtomicU8::new(0));
        let mode = Arc::new(AtomicU8::new(0));
        let (target, a, m) = (relay.to_string(), armed.clone(), mode.clone());
        std::thread::spawn(move || {
            for client in listener.incoming().flatten() {
                let (target, a, m) = (target.clone(), a.clone(), m.clone());
                std::thread::spawn(move || relay_through(client, &target, &a, &m));
            }
        });
        Self { addr, armed, mode }
    }

    pub fn arm(&self, op: u8, cut: Cut) {
        self.mode
            .store(matches!(cut, Cut::Response) as u8, Ordering::SeqCst);
        self.armed.store(op, Ordering::SeqCst);
    }

    pub fn fired(&self) -> bool {
        self.armed.load(Ordering::SeqCst) == 0
    }
}

fn relay_through(mut client: TcpStream, target: &str, armed: &AtomicU8, mode: &AtomicU8) {
    let Ok(mut server) = TcpStream::connect(target) else {
        return;
    };
    while let Ok(Some(req)) = read_frame(&mut client) {
        let op = req.first().copied().unwrap_or(0);
        let hit = op != 0
            && armed
                .compare_exchange(op, 0, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok();
        if hit && mode.load(Ordering::SeqCst) == 0 {
            break; // drop the request
        }
        if write_frame(&mut server, &req).is_err() {
            break;
        }
        let Ok(Some(resp)) = read_frame(&mut server) else {
            break;
        };
        if hit {
            break; // drop the response
        }
        if write_frame(&mut client, &resp).is_err() {
            break;
        }
    }
    let _ = client.shutdown(Shutdown::Both);
    let _ = server.shutdown(Shutdown::Both);
}
