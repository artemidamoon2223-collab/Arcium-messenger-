//! Test infrastructure for the network tests: independent devices, a real
//! relay on a TCP port, and a proxy that breaks chosen relay operations.
//!
//! Most tests use a `RELAY_PROTOCOL_V1` relay ([`start_relay`]): the
//! [`Proxy`] reads plaintext frames, which TLS would hide. `relay_v2.rs`
//! runs devices over a `RELAY_PROTOCOL_V2` relay ([`start_relay_v2`]).

use super::*;
use crate::network::wire::Envelope;
use crate::network::{NetworkMessenger, SyncReport};
use relay::address::RelayAddress;
use relay::auth::RelayKeys;
use relay::protocol::{read_frame, write_frame};
use relay::server::{serve, serve_v2, RelayConfig, RelayHandle};
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

/// A `RELAY_PROTOCOL_V2` relay with fresh keys, and its connection string.
pub fn start_relay_v2() -> (RelayHandle, RelayAddress) {
    let keys = RelayKeys::generate().unwrap();
    let relay = serve_v2(
        TcpListener::bind("127.0.0.1:0").unwrap(),
        RelayConfig {
            canary: Some(CANARY.to_vec()),
            ..RelayConfig::default()
        },
        &keys,
    )
    .unwrap();
    let addr = keys.address("127.0.0.1", relay.addr().port()).unwrap();
    (relay, addr)
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
            .map(|t| String::from_utf8(t.text.0[..t.text.0.len() - CANARY.len()].to_vec()).unwrap())
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
    /// The request never reaches the relay, and the client is answered
    /// with an error; the connection stays open.
    Refuse,
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
        let mode = match cut {
            Cut::Request => 0,
            Cut::Response => 1,
            Cut::Refuse => 2,
        };
        self.mode.store(mode, Ordering::SeqCst);
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
        if hit && mode.load(Ordering::SeqCst) == 2 {
            let refused = relay::protocol::Response::Error(relay::protocol::ErrorCode::Full);
            if write_frame(&mut client, &refused.encode()).is_err() {
                break;
            }
            continue;
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

/// Other X25519 public keys that every clamped scalar maps to the same
/// shared secret as `key`, so a relay can put either in place of an
/// initiator's ephemeral key and the responder derives the same session
/// (review of option B):
/// - `key` with its top bit flipped, which X25519 ignores;
/// - the point plus the point of order 2, whose u-coordinate is `1/u mod p`
///   (on a Montgomery curve, x(P + (0, 0)) = 1/x(P)); a clamped scalar is a
///   multiple of 8 and cancels it.
///
/// Test aid; callers check the claim with a real Diffie-Hellman.
pub fn same_keys_other_encodings(key: [u8; 32]) -> [[u8; 32]; 2] {
    let mut flipped = key;
    flipped[31] ^= 0x80;
    [flipped, field::to_bytes(&field::invert(&field::from_bytes(&key)))]
}

/// Arithmetic modulo p = 2^255 - 19 on four little-endian 64-bit limbs,
/// only what `same_keys_other_encodings` needs. Not constant time.
mod field {
    pub type Fe = [u64; 4];
    const P: Fe = [0xffff_ffff_ffff_ffed, u64::MAX, u64::MAX, 0x7fff_ffff_ffff_ffff];

    pub fn from_bytes(b: &[u8; 32]) -> Fe {
        let mut f = [0u64; 4];
        for (i, limb) in f.iter_mut().enumerate() {
            *limb = u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap());
        }
        f[3] &= 0x7fff_ffff_ffff_ffff;
        reduce(f)
    }

    pub fn to_bytes(f: &Fe) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, limb) in f.iter().enumerate() {
            b[8 * i..8 * i + 8].copy_from_slice(&limb.to_le_bytes());
        }
        b
    }

    fn geq_p(f: &Fe) -> bool {
        for i in (0..4).rev() {
            if f[i] != P[i] {
                return f[i] > P[i];
            }
        }
        true
    }

    fn reduce(mut f: Fe) -> Fe {
        while geq_p(&f) {
            let mut borrow = 0u128;
            for i in 0..4 {
                let d = (f[i] as u128).wrapping_sub(P[i] as u128 + borrow);
                f[i] = d as u64;
                borrow = (d >> 127) & 1;
            }
        }
        f
    }

    pub fn mul(a: &Fe, b: &Fe) -> Fe {
        let mut r = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let cur = r[i + j] as u128 + (a[i] as u128) * (b[j] as u128) + carry;
                r[i + j] = cur as u64;
                carry = cur >> 64;
            }
            r[i + 4] = carry as u64;
        }
        // 2^256 = 38 (mod p).
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let cur = r[i] as u128 + 38 * (r[i + 4] as u128) + carry;
            out[i] = cur as u64;
            carry = cur >> 64;
        }
        while carry > 0 {
            let mut c = 38 * carry;
            for limb in out.iter_mut() {
                let cur = *limb as u128 + c;
                *limb = cur as u64;
                c = cur >> 64;
            }
            carry = c;
        }
        reduce(out)
    }

    /// `a^(p-2)`, the inverse of a non-zero `a`.
    pub fn invert(a: &Fe) -> Fe {
        let e: Fe = [0xffff_ffff_ffff_ffeb, u64::MAX, u64::MAX, 0x7fff_ffff_ffff_ffff];
        let mut acc: Fe = [1, 0, 0, 0];
        for bit in (0..255).rev() {
            acc = mul(&acc, &acc);
            if (e[bit / 64] >> (bit % 64)) & 1 == 1 {
                acc = mul(&acc, a);
            }
        }
        acc
    }
}
