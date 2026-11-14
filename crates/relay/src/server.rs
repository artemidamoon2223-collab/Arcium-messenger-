//! The relay: an untrusted, in-memory store-and-forward mailbox per recipient
//! key, plus one published prekey bundle per owner key.
//!
//! # Retention policy
//!
//! An envelope stays in its recipient's mailbox until the recipient deletes it
//! or it is older than [`RelayConfig::ttl`]. Without [`RelayConfig::db`],
//! nothing is written to disk and a restart loses every mailbox and bundle.
//! With it, every accepted envelope, deletion and bundle is committed to that
//! SQLite file before the request is answered, and a restart loads what is
//! stored there (`crate::disk`). A mailbox holds at most
//! [`RelayConfig::max_mailbox`] envelopes, at most [`DEFAULT_MAX_MAILBOX`]: a
//! reader's scan of one round covers that many, so a larger mailbox could hide
//! entries behind the ones it keeps (`serve` refuses such a configuration). A
//! SEND to a full mailbox is refused with `FULL`, never by dropping an older
//! envelope. A SEND of bytes identical to an envelope still stored returns the
//! stored sequence number.
//!
//! A full mailbox is a denial of service anyone who can reach the relay can
//! cause, since SEND is not authenticated. Paging with FETCH_AFTER does not
//! change that: it lets a reader get past envelopes it leaves in place, not
//! receive envelopes the relay refused to store.
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
//! messages. No TLS: a network observer sees what the relay sees. Stored
//! envelopes are kept as received, not encrypted again at rest. No limit on
//! connections: each open one holds a thread and two descriptors until it
//! closes or stays idle for 60 s, so anyone can hold enough of them open to
//! keep others out. A closed connection releases both; when no descriptor is
//! left, the accept loop waits instead of spinning.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::ops::Bound;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::disk::{now_ms, Disk};
use crate::protocol::*;

#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Envelopes one mailbox holds: 1 to [`DEFAULT_MAX_MAILBOX`] (the
    /// default). [`serve`] refuses any other value.
    pub max_mailbox: usize,
    pub ttl: Duration,
    /// Test aid: log an alert if a stored envelope contains these bytes, so a
    /// test can assert that a known plaintext never reached the relay.
    pub canary: Option<Vec<u8>>,
    /// Log one line per request (keys shortened, sizes, sequence numbers).
    pub log: bool,
    /// SQLite file that keeps mailboxes and bundles across restarts; `None`
    /// keeps everything in memory only.
    pub db: Option<PathBuf>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            max_mailbox: DEFAULT_MAX_MAILBOX,
            ttl: Duration::from_secs(7 * 24 * 3600),
            canary: None,
            log: false,
            db: None,
        }
    }
}

#[derive(Default)]
struct State {
    next_seq: u64,
    mailboxes: HashMap<Key, BTreeMap<u64, (Instant, Vec<u8>)>>,
    bundles: HashMap<Key, Vec<u8>>,
    canary_hits: u64,
    /// Written through when [`RelayConfig::db`] is set.
    disk: Option<Disk>,
}

impl State {
    /// Deletes from the disk the envelopes of `recipient` that expired from
    /// memory. Best effort: an envelope left behind is older than the TTL and
    /// is dropped when the file is next loaded.
    fn forget_expired(&mut self, recipient: &Key, expired: &[u64], log: &dyn Fn(String)) {
        if let Some(disk) = self.disk.as_mut() {
            if let Err(e) = disk.delete_envelopes(recipient, expired) {
                log(format!("could not delete expired envelopes: {e}"));
            }
        }
    }
}

/// Drops `mailbox`'s envelopes older than `ttl`; returns their numbers.
fn expire(mailbox: &mut BTreeMap<u64, (Instant, Vec<u8>)>, now: Instant, ttl: Duration) -> Vec<u64> {
    let expired: Vec<u64> = mailbox
        .iter()
        .filter(|(_, (t, _))| now.duration_since(*t) >= ttl)
        .map(|(k, _)| *k)
        .collect();
    for k in &expired {
        mailbox.remove(k);
    }
    expired
}

/// A running relay. Dropping it does not stop it; call [`RelayHandle::stop`].
pub struct RelayHandle {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    /// A clone of every open connection, so `stop` can close it. Each one
    /// leaves the map when its connection ends.
    conns: Arc<Mutex<HashMap<u64, TcpStream>>>,
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

    /// Connections open now, as tracked for [`RelayHandle::stop`].
    #[cfg(test)]
    pub(crate) fn open_connections(&self) -> usize {
        self.conns.lock().expect("conns").len()
    }

    /// How many stored envelopes contained [`RelayConfig::canary`].
    pub fn canary_hits(&self) -> u64 {
        self.state.lock().expect("relay state").canary_hits
    }

    /// Stops accepting, closes every open connection and waits for the
    /// accept loop to end. Without [`RelayConfig::db`], stored envelopes are
    /// discarded with the relay.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr); // unblock accept()
        for (_, c) in self.conns.lock().expect("conns").drain() {
            let _ = c.shutdown(Shutdown::Both);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Serves `listener` on a background thread, one thread per connection.
///
/// Refuses, with [`io::ErrorKind::InvalidInput`] and without starting
/// anything, a `max_mailbox` outside 1 to [`DEFAULT_MAX_MAILBOX`]. Nothing is
/// clamped. With [`RelayConfig::db`], opens (or creates) that file and loads
/// it first; an error there also starts nothing.
pub fn serve(listener: TcpListener, config: RelayConfig) -> io::Result<RelayHandle> {
    if !(1..=DEFAULT_MAX_MAILBOX).contains(&config.max_mailbox) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "max_mailbox must be between 1 and {DEFAULT_MAX_MAILBOX}, got {}",
                config.max_mailbox
            ),
        ));
    }
    let mut initial = State {
        next_seq: 1,
        ..State::default()
    };
    if let Some(path) = &config.db {
        let disk = Disk::open(path)?;
        let loaded = disk.load(config.ttl)?;
        let now = Instant::now();
        initial.next_seq = loaded.next_seq;
        for (recipient, seq, age, bytes) in loaded.envelopes {
            let at = now.checked_sub(age).unwrap_or(now);
            initial.mailboxes.entry(recipient).or_default().insert(seq, (at, bytes));
        }
        initial.bundles.extend(loaded.bundles);
        initial.disk = Some(disk);
    }
    let addr = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let conns = Arc::new(Mutex::new(HashMap::new()));
    let state = Arc::new(Mutex::new(initial));
    let config = Arc::new(config);
    let thread = {
        let (stop, conns, state) = (stop.clone(), conns.clone(), state.clone());
        std::thread::spawn(move || {
            let mut next_id = 0u64;
            for stream in listener.incoming() {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let stream = match stream {
                    Ok(s) => s,
                    // Out of descriptors (or another accept error): the
                    // pending connection stays in the backlog, so retrying
                    // at once would spin. Wait for a connection to end.
                    Err(_) => {
                        std::thread::sleep(ACCEPT_RETRY);
                        continue;
                    }
                };
                let id = next_id;
                next_id += 1;
                // Untracked if no descriptor is left for the clone: it is
                // still served, and ends on its own (close or read timeout).
                if let Ok(c) = stream.try_clone() {
                    conns.lock().expect("conns").insert(id, c);
                }
                let (state, config, stop, conns) =
                    (state.clone(), config.clone(), stop.clone(), conns.clone());
                std::thread::spawn(move || {
                    connection(stream, &state, &config, &stop);
                    // Release the clone with the connection, or every
                    // connection would keep a descriptor until `stop`.
                    conns.lock().expect("conns").remove(&id);
                });
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

/// How long the accept loop waits after a failed accept before the next.
const ACCEPT_RETRY: Duration = Duration::from_millis(50);

fn connection(
    mut stream: TcpStream,
    state: &Mutex<State>,
    config: &RelayConfig,
    stop: &AtomicBool,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
    // A response is written as length, then body; without this the body waits
    // for the client's delayed ACK of the length (tens of ms per request).
    let _ = stream.set_nodelay(true);
    while !stop.load(Ordering::SeqCst) {
        let body = match read_frame(&mut stream) {
            Ok(Some(b)) => b,
            _ => return,
        };
        let response = match Request::decode(&body) {
            Ok(req) => match handle(req, state, config) {
                Ok(r) => r,
                // Not committed, so not answered: the client sees the
                // connection close and retries, as after a lost answer.
                Err(e) => {
                    eprintln!("relay: request not stored, closing the connection: {e}");
                    return;
                }
            },
            Err(_) => Response::Error(ErrorCode::BadRequest),
        };
        if write_frame(&mut stream, &response.encode()).is_err() {
            return;
        }
    }
}

/// The unexpired envelopes of `recipient`'s mailbox with a sequence number
/// greater than `after`, in ascending order, at most `max` (and
/// [`MAX_FETCH`]) of them, and no more than fit in one response frame: the
/// page stops before the first envelope that would not fit, so it holds at
/// least [`MIN_PAGE`] when more follow.
fn fetch_after(
    s: &mut State,
    recipient: &Key,
    after: u64,
    max: u16,
    now: Instant,
    config: &RelayConfig,
    log: &dyn Fn(String),
) -> Vec<(u64, Vec<u8>)> {
    let max = max.min(MAX_FETCH) as usize;
    let Some(m) = s.mailboxes.get_mut(recipient) else {
        return Vec::new();
    };
    let expired = expire(m, now, config.ttl);
    s.forget_expired(recipient, &expired, log);
    let m = s.mailboxes.get(recipient).expect("present above");
    // status(1) count(2), then seq(8) len(4) envelope per entry.
    let mut size = 3;
    m.range((Bound::Excluded(after), Bound::Unbounded))
        .take(max)
        .take_while(|(_, (_, v))| {
            size += 12 + v.len();
            size <= MAX_FRAME
        })
        .map(|(k, (_, v))| (*k, v.clone()))
        .collect()
}

fn short(k: &Key) -> String {
    k[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Answers one request. An error means a change could not be committed to
/// [`RelayConfig::db`]: nothing changed in memory either, and the request
/// must not be answered.
fn handle(req: Request, state: &Mutex<State>, config: &RelayConfig) -> io::Result<Response> {
    let mut s = state.lock().expect("relay state");
    let now = Instant::now();
    let log = |line: String| {
        if config.log {
            eprintln!("relay: {line}");
        }
    };
    Ok(match req {
        Request::PutBundle { owner, bundle } => {
            if bundle.len() > MAX_BUNDLE {
                return Ok(Response::Error(ErrorCode::TooLarge));
            }
            log(format!(
                "PUT_BUNDLE owner={} len={}",
                short(&owner),
                bundle.len()
            ));
            if let Some(disk) = s.disk.as_mut() {
                disk.put_bundle(&owner, &bundle)?;
            }
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
                return Ok(Response::Error(ErrorCode::TooLarge));
            }
            if let Some(canary) = &config.canary {
                if !canary.is_empty() && envelope.windows(canary.len()).any(|w| w == canary) {
                    s.canary_hits += 1;
                    eprintln!("relay: ALERT plaintext canary found in an envelope");
                }
            }
            let seq = s.next_seq;
            let mailbox = s.mailboxes.entry(recipient).or_default();
            let expired = expire(mailbox, now, config.ttl);
            s.forget_expired(&recipient, &expired, &log);
            let mailbox = s.mailboxes.get_mut(&recipient).expect("inserted above");
            if let Some((&existing, _)) = mailbox.iter().find(|(_, (_, e))| *e == envelope) {
                log(format!(
                    "SEND to={} len={} seq={existing} (duplicate)",
                    short(&recipient),
                    envelope.len()
                ));
                return Ok(Response::Accepted { seq: existing });
            }
            if mailbox.len() >= config.max_mailbox {
                return Ok(Response::Error(ErrorCode::Full));
            }
            // Sequence numbers never wrap: a relay that has used them all
            // stores nothing more.
            let Some(next) = seq.checked_add(1) else {
                return Ok(Response::Error(ErrorCode::Full));
            };
            log(format!(
                "SEND to={} len={} seq={seq}",
                short(&recipient),
                envelope.len()
            ));
            // Committed before it is stored in memory and answered.
            if let Some(disk) = s.disk.as_mut() {
                disk.store_envelope(seq, &recipient, now_ms(), &envelope, next)?;
            }
            s.mailboxes
                .get_mut(&recipient)
                .expect("inserted above")
                .insert(seq, (now, envelope));
            s.next_seq = next;
            Response::Accepted { seq }
        }
        Request::Fetch { recipient, max } => {
            let items = fetch_after(&mut s, &recipient, 0, max, now, config, &log);
            log(format!(
                "FETCH for={} returned={}",
                short(&recipient),
                items.len()
            ));
            Response::Items(items)
        }
        Request::FetchAfter {
            recipient,
            after,
            max,
        } => {
            let items = fetch_after(&mut s, &recipient, after, max, now, config, &log);
            log(format!(
                "FETCH_AFTER for={} after={after} returned={}",
                short(&recipient),
                items.len()
            ));
            Response::Items(items)
        }
        Request::Delete { recipient, seqs } => {
            // Committed before memory changes and the request is answered.
            if let Some(disk) = s.disk.as_mut() {
                disk.delete_envelopes(&recipient, &seqs)?;
            }
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_numbers_never_wrap() {
        let state = Mutex::new(State {
            next_seq: u64::MAX,
            ..State::default()
        });
        let config = RelayConfig::default();
        let send = |e: u8| {
            handle(
                Request::Send {
                    recipient: [1; 32],
                    envelope: vec![e],
                },
                &state,
                &config,
            )
            .unwrap()
        };
        assert_eq!(send(1), Response::Error(ErrorCode::Full));
        assert!(state.lock().unwrap().mailboxes[&[1u8; 32]].is_empty());
        state.lock().unwrap().next_seq = u64::MAX - 1;
        assert_eq!(send(2), Response::Accepted { seq: u64::MAX - 1 });
        assert_eq!(send(3), Response::Error(ErrorCode::Full));
        assert_eq!(
            send(2),
            Response::Accepted { seq: u64::MAX - 1 },
            "duplicate"
        );
    }

    /// A change the database refuses is not answered and not made in
    /// memory either: no envelope, no sequence number used, no bundle, and a
    /// stored envelope is not deleted.
    #[test]
    fn a_change_that_cannot_be_stored_is_neither_answered_nor_made() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.db");
        let mut mailbox = BTreeMap::new();
        mailbox.insert(1u64, (Instant::now(), vec![9u8]));
        let state = Mutex::new(State {
            next_seq: 2,
            mailboxes: HashMap::from([([1u8; 32], mailbox)]),
            disk: Some(Disk::read_only(&path).unwrap()),
            ..State::default()
        });
        let config = RelayConfig::default();
        let send = handle(
            Request::Send {
                recipient: [1; 32],
                envelope: vec![7],
            },
            &state,
            &config,
        );
        assert!(send.is_err(), "{send:?}");
        let put = handle(
            Request::PutBundle {
                owner: [1; 32],
                bundle: vec![1],
            },
            &state,
            &config,
        );
        assert!(put.is_err(), "{put:?}");
        let delete = handle(
            Request::Delete {
                recipient: [1; 32],
                seqs: vec![1],
            },
            &state,
            &config,
        );
        assert!(delete.is_err(), "{delete:?}");
        let s = state.lock().unwrap();
        assert_eq!(s.next_seq, 2);
        assert_eq!(s.mailboxes[&[1u8; 32]].len(), 1, "nothing added, nothing deleted");
        assert!(s.bundles.is_empty());
    }
}
