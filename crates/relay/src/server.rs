//! The relay: an untrusted, in-memory store-and-forward mailbox per recipient
//! key, plus one published prekey bundle per owner key.
//!
//! # Retention policy
//!
//! An envelope stays in its recipient's mailbox until the recipient deletes it,
//! it is older than [`RelayConfig::ttl`], or the relay stops: nothing is
//! written to disk, so a restart loses every mailbox. A mailbox holds at most
//! [`RelayConfig::max_mailbox`] envelopes; a SEND to a full mailbox is refused
//! with `FULL`, never by dropping an older envelope. A SEND of bytes identical
//! to an envelope still stored returns the stored sequence number.
//!
//! Delivery does not depend on the relay keeping anything: senders keep every
//! message until the recipient's end-to-end receipt arrives, and retransmit.
//!
//! # What it does not do
//!
//! No authentication: anyone who can reach it can read or delete any mailbox
//! and replace any bundle. None of that exposes plaintext or keys (envelopes
//! are end-to-end encrypted and bundles are verified by the fetcher against an
//! out-of-band identity), but it can withhold, delay, reorder, replay or drop
//! messages. No TLS: a network observer sees what the relay sees.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::protocol::*;

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub max_mailbox: usize,
    pub ttl: Duration,
    /// Test aid: log an alert if a stored envelope contains these bytes, so a
    /// test can assert that a known plaintext never reached the relay.
    pub canary: Option<Vec<u8>>,
    /// Log one line per request (keys shortened, sizes, sequence numbers).
    pub log: bool,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            max_mailbox: 4096,
            ttl: Duration::from_secs(7 * 24 * 3600),
            canary: None,
            log: false,
        }
    }
}

#[derive(Default)]
struct State {
    next_seq: u64,
    mailboxes: HashMap<Key, BTreeMap<u64, (Instant, Vec<u8>)>>,
    bundles: HashMap<Key, Vec<u8>>,
    canary_hits: u64,
}

/// A running relay. Dropping it does not stop it; call [`RelayHandle::stop`].
pub struct RelayHandle {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    conns: Arc<Mutex<Vec<TcpStream>>>,
    state: Arc<Mutex<State>>,
    thread: Option<JoinHandle<()>>,
}

impl RelayHandle {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Envelopes stored for `recipient`, in sequence order.
    pub fn stored(&self, recipient: &Key) -> Vec<(u64, Vec<u8>)> {
        let s = self.state.lock().expect("relay state");
        s.mailboxes
            .get(recipient)
            .map(|m| m.iter().map(|(k, (_, v))| (*k, v.clone())).collect())
            .unwrap_or_default()
    }

    /// How many stored envelopes contained [`RelayConfig::canary`].
    pub fn canary_hits(&self) -> u64 {
        self.state.lock().expect("relay state").canary_hits
    }

    /// Stops accepting, closes every open connection and waits for the
    /// accept loop to end. Stored envelopes are discarded with the relay.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr); // unblock accept()
        for c in self.conns.lock().expect("conns").drain(..) {
            let _ = c.shutdown(Shutdown::Both);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Serves `listener` on a background thread, one thread per connection.
pub fn serve(listener: TcpListener, config: RelayConfig) -> io::Result<RelayHandle> {
    let addr = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let conns = Arc::new(Mutex::new(Vec::new()));
    let state = Arc::new(Mutex::new(State {
        next_seq: 1,
        ..State::default()
    }));
    let config = Arc::new(config);
    let thread = {
        let (stop, conns, state) = (stop.clone(), conns.clone(), state.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                if let Ok(c) = stream.try_clone() {
                    conns.lock().expect("conns").push(c);
                }
                let (state, config, stop) = (state.clone(), config.clone(), stop.clone());
                std::thread::spawn(move || connection(stream, &state, &config, &stop));
            }
        })
    };
    Ok(RelayHandle {
        addr,
        stop,
        conns,
        state,
        thread: Some(thread),
    })
}

fn connection(
    mut stream: TcpStream,
    state: &Mutex<State>,
    config: &RelayConfig,
    stop: &AtomicBool,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
    while !stop.load(Ordering::SeqCst) {
        let body = match read_frame(&mut stream) {
            Ok(Some(b)) => b,
            _ => return,
        };
        let response = match Request::decode(&body) {
            Ok(req) => handle(req, state, config),
            Err(_) => Response::Error(ErrorCode::BadRequest),
        };
        if write_frame(&mut stream, &response.encode()).is_err() {
            return;
        }
    }
}

fn short(k: &Key) -> String {
    k[..4].iter().map(|b| format!("{b:02x}")).collect()
}

fn handle(req: Request, state: &Mutex<State>, config: &RelayConfig) -> Response {
    let mut s = state.lock().expect("relay state");
    let now = Instant::now();
    let log = |line: String| {
        if config.log {
            eprintln!("relay: {line}");
        }
    };
    match req {
        Request::PutBundle { owner, bundle } => {
            if bundle.len() > MAX_BUNDLE {
                return Response::Error(ErrorCode::TooLarge);
            }
            log(format!(
                "PUT_BUNDLE owner={} len={}",
                short(&owner),
                bundle.len()
            ));
            s.bundles.insert(owner, bundle);
            Response::Ok
        }
        Request::GetBundle { owner } => {
            log(format!("GET_BUNDLE owner={}", short(&owner)));
            match s.bundles.get(&owner) {
                Some(b) => Response::Bundle(b.clone()),
                None => Response::NotFound,
            }
        }
        Request::Send {
            recipient,
            envelope,
        } => {
            if envelope.len() > MAX_ENVELOPE {
                return Response::Error(ErrorCode::TooLarge);
            }
            if let Some(canary) = &config.canary {
                if !canary.is_empty() && envelope.windows(canary.len()).any(|w| w == canary) {
                    s.canary_hits += 1;
                    eprintln!("relay: ALERT plaintext canary found in an envelope");
                }
            }
            let seq = s.next_seq;
            let mailbox = s.mailboxes.entry(recipient).or_default();
            mailbox.retain(|_, (t, _)| now.duration_since(*t) < config.ttl);
            if let Some((&existing, _)) = mailbox.iter().find(|(_, (_, e))| *e == envelope) {
                log(format!(
                    "SEND to={} len={} seq={existing} (duplicate)",
                    short(&recipient),
                    envelope.len()
                ));
                return Response::Accepted { seq: existing };
            }
            if mailbox.len() >= config.max_mailbox {
                return Response::Error(ErrorCode::Full);
            }
            log(format!(
                "SEND to={} len={} seq={seq}",
                short(&recipient),
                envelope.len()
            ));
            mailbox.insert(seq, (now, envelope));
            s.next_seq += 1;
            Response::Accepted { seq }
        }
        Request::Fetch { recipient, max } => {
            let max = max.min(MAX_FETCH) as usize;
            let items: Vec<_> = match s.mailboxes.get_mut(&recipient) {
                Some(m) => {
                    m.retain(|_, (t, _)| now.duration_since(*t) < config.ttl);
                    m.iter()
                        .take(max)
                        .map(|(k, (_, v))| (*k, v.clone()))
                        .collect()
                }
                None => Vec::new(),
            };
            log(format!(
                "FETCH for={} returned={}",
                short(&recipient),
                items.len()
            ));
            Response::Items(items)
        }
        Request::Delete { recipient, seqs } => {
            if let Some(m) = s.mailboxes.get_mut(&recipient) {
                for seq in &seqs {
                    m.remove(seq);
                }
            }
            log(format!(
                "DELETE for={} count={}",
                short(&recipient),
                seqs.len()
            ));
            Response::Ok
        }
    }
}
