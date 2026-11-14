//! The relay: an untrusted store-and-forward mailbox per recipient key, plus
//! one published prekey bundle per owner key. It serves from memory, and
//! optionally keeps everything in a SQLite file ([`RelayConfig::db`]).
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
//! envelope, and so is a SEND that would take the relay's stored envelopes
//! past [`RelayConfig::max_total_bytes`] in all, so a flood of SENDs to many
//! keys cannot exhaust its memory or disk. A SEND of bytes identical to an envelope still stored returns the
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
//! # Versions
//!
//! [`serve`] speaks `RELAY_PROTOCOL_V1` on plain TCP. No authentication:
//! anyone who can reach it can read or delete any mailbox and replace any
//! bundle. No TLS: a network observer sees what the relay sees. It is for
//! development and tests only, and will be removed once the app uses V2.
//!
//! [`serve_v2`] speaks `RELAY_PROTOCOL_V2` (`crate::protocol`): TLS 1.3 with
//! the relay's pinned key (`crate::tls`), and FETCH, FETCH_AFTER, DELETE and
//! PUT_BUNDLE only for the owner who authenticated on that connection
//! (`crate::auth`). Same state, same limits, same persistence.
//!
//! # What it does not do
//!
//! Neither version keeps anything from the relay's operator, who can read or
//! delete any mailbox and replace any bundle. None of that exposes plaintext
//! or keys (envelopes are end-to-end encrypted and bundles are verified by the
//! fetcher against an out-of-band identity), but it can withhold, delay,
//! reorder, replay or drop messages. Stored envelopes are kept as received,
//! not encrypted again at rest. No limit on connections: each open one holds
//! a thread and two descriptors until it closes or stays idle for 60 s (in
//! V2, the TLS handshake included), so anyone can hold enough of them open to
//! keep others out. A closed connection releases both; when no descriptor is
//! left, the accept loop waits instead of spinning. Log lines name keys by
//! their first four bytes, and never contain a challenge, an exported key or
//! an AUTH tag.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::ops::Bound;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

use crate::auth::{verify_auth_tag, RelayKeys, AUTH_LEN, EXPORTER_LABEL};
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
    /// Most envelope bytes stored in all mailboxes together; a SEND beyond it
    /// is refused with `FULL`. At least [`MAX_ENVELOPE`] ([`serve`] refuses
    /// less).
    pub max_total_bytes: usize,
}

/// The default [`RelayConfig::max_total_bytes`]: 1 GiB.
pub const DEFAULT_MAX_TOTAL_BYTES: usize = 1 << 30;

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            max_mailbox: DEFAULT_MAX_MAILBOX,
            ttl: Duration::from_secs(7 * 24 * 3600),
            canary: None,
            log: false,
            db: None,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
        }
    }
}

#[derive(Default)]
struct State {
    next_seq: u64,
    mailboxes: HashMap<Key, BTreeMap<u64, (Instant, Vec<u8>)>>,
    bundles: HashMap<Key, Vec<u8>>,
    canary_hits: u64,
    /// Bytes of all stored envelopes, for [`RelayConfig::max_total_bytes`].
    total_bytes: usize,
    /// Written through when [`RelayConfig::db`] is set.
    disk: Option<Disk>,
}

impl State {
    /// Deletes from the disk the envelopes of `recipient` that expired from
    /// memory. Best effort: an envelope left behind is older than the TTL and
    /// is dropped when the file is next loaded.
    fn forget_expired(&mut self, recipient: &Key, expired: &[(u64, usize)], log: &dyn Fn(String)) {
        self.total_bytes -= expired.iter().map(|(_, len)| len).sum::<usize>();
        if let Some(disk) = self.disk.as_mut() {
            let seqs: Vec<u64> = expired.iter().map(|(seq, _)| *seq).collect();
            if let Err(e) = disk.delete_envelopes(recipient, &seqs) {
                log(format!("could not delete expired envelopes: {e}"));
            }
        }
    }
}

/// Drops `mailbox`'s envelopes older than `ttl`; returns their numbers and
/// sizes.
fn expire(mailbox: &mut BTreeMap<u64, (Instant, Vec<u8>)>, now: Instant, ttl: Duration) -> Vec<(u64, usize)> {
    let expired: Vec<u64> = mailbox
        .iter()
        .filter(|(_, (t, _))| now.duration_since(*t) >= ttl)
        .map(|(k, _)| *k)
        .collect();
    expired
        .into_iter()
        .filter_map(|k| mailbox.remove(&k).map(|(_, v)| (k, v.len())))
        .collect()
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

/// What a V2 relay needs for every connection.
struct V2 {
    tls: Arc<ServerConfig>,
    auth_sk: StaticSecret,
}

/// Serves `RELAY_PROTOCOL_V1` on `listener`, on a background thread, one
/// thread per connection. For development and tests only: see the module
/// documentation.
///
/// Refuses, with [`io::ErrorKind::InvalidInput`] and without starting
/// anything, a `max_mailbox` outside 1 to [`DEFAULT_MAX_MAILBOX`] or a
/// `max_total_bytes` below [`MAX_ENVELOPE`]. Nothing is clamped. With
/// [`RelayConfig::db`], opens (or creates) that file and loads it first; an
/// error there also starts nothing.
pub fn serve(listener: TcpListener, config: RelayConfig) -> io::Result<RelayHandle> {
    start(listener, config, None)
}

/// Serves `RELAY_PROTOCOL_V2` on `listener` with `keys`: every connection is
/// TLS 1.3 with the relay's TLS key, and mailbox operations need AUTH
/// (`crate::protocol`). Refuses what [`serve`] refuses, and starts nothing
/// if the TLS configuration cannot be built.
pub fn serve_v2(listener: TcpListener, config: RelayConfig, keys: &RelayKeys) -> io::Result<RelayHandle> {
    let key = crate::tls::signing_key(keys.tls_seed()).map_err(io::Error::other)?;
    let v2 = V2 {
        tls: crate::tls::server_config(key).map_err(io::Error::other)?,
        auth_sk: keys.auth_secret().clone(),
    };
    start(listener, config, Some(Arc::new(v2)))
}

fn start(listener: TcpListener, config: RelayConfig, v2: Option<Arc<V2>>) -> io::Result<RelayHandle> {
    if config.max_total_bytes < MAX_ENVELOPE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "max_total_bytes must be at least {MAX_ENVELOPE}, got {}",
                config.max_total_bytes
            ),
        ));
    }
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
            initial.total_bytes += bytes.len();
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
                let (state, config, stop, conns, v2) =
                    (state.clone(), config.clone(), stop.clone(), conns.clone(), v2.clone());
                std::thread::spawn(move || {
                    connection(stream, &state, &config, &stop, v2.as_deref());
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
    stream: TcpStream,
    state: &Mutex<State>,
    config: &RelayConfig,
    stop: &AtomicBool,
    v2: Option<&V2>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
    // A response is written as length, then body; without this the body waits
    // for the client's delayed ACK of the length (tens of ms per request).
    let _ = stream.set_nodelay(true);
    match v2 {
        None => requests(stream, state, config, stop, None),
        Some(v2) => {
            if let Some((tls, session)) = accept_v2(stream, v2) {
                requests(tls, state, config, stop, Some(session));
            }
        }
    }
}

/// The TLS handshake and the HELLO frame of a V2 connection; `None`, and the
/// connection closes, if either fails.
fn accept_v2(stream: TcpStream, v2: &V2) -> Option<(StreamOwned<ServerConnection, TcpStream>, Session<'_>)> {
    let mut tls = StreamOwned::new(ServerConnection::new(v2.tls.clone()).ok()?, stream);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock).ok()?;
    }
    let mut challenge = [0u8; CHALLENGE_LEN];
    if let Err(e) = OsRng.try_fill_bytes(&mut challenge) {
        eprintln!("relay: no randomness for a challenge, closing the connection: {e}");
        return None;
    }
    let exporter = tls
        .conn
        .export_keying_material(Zeroizing::new([0u8; AUTH_LEN]), EXPORTER_LABEL, None)
        .ok()?;
    write_frame(&mut tls, &encode_hello(&challenge)).ok()?;
    let session = Session {
        auth_sk: &v2.auth_sk,
        challenge,
        exporter,
        auth: Auth::None,
    };
    Some((tls, session))
}

/// Answers requests until the connection closes or the relay stops. With a
/// `session` (V2), every request passes [`Session::screen`] first.
fn requests(
    mut stream: impl Read + Write,
    state: &Mutex<State>,
    config: &RelayConfig,
    stop: &AtomicBool,
    mut session: Option<Session<'_>>,
) {
    while !stop.load(Ordering::SeqCst) {
        let body = match read_frame(&mut stream) {
            Ok(Some(b)) => b,
            _ => return,
        };
        let response = match Request::decode(&body) {
            Ok(req) => match session.as_mut().and_then(|s| s.screen(&req, config)) {
                Some(answer) => answer,
                None => match handle(req, state, config) {
                    Ok(r) => r,
                    // Not committed, so not answered: the client sees the
                    // connection close and retries, as after a lost answer.
                    Err(e) => {
                        eprintln!("relay: request not stored, closing the connection: {e}");
                        return;
                    }
                },
            },
            Err(_) => Response::Error(ErrorCode::BadRequest),
        };
        if write_frame(&mut stream, &response.encode()).is_err() {
            return;
        }
    }
}

/// What a V2 connection has proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Auth {
    /// No AUTH yet.
    None,
    /// A valid AUTH: the connection acts for this owner until it closes.
    Owner(Key),
    /// A wrong AUTH. No later AUTH is checked.
    Refused,
}

/// The authentication state of one V2 connection.
struct Session<'a> {
    auth_sk: &'a StaticSecret,
    /// Sent in HELLO; fresh for this connection.
    challenge: [u8; CHALLENGE_LEN],
    /// This connection's TLS exported keying material.
    exporter: Zeroizing<[u8; AUTH_LEN]>,
    auth: Auth,
}

impl Session<'_> {
    /// The answer to `req` if this connection may not have it handled: AUTH
    /// is always answered here, and so is an owner operation for any key but
    /// the authenticated owner's. `None` lets [`handle`] answer.
    fn screen(&mut self, req: &Request, config: &RelayConfig) -> Option<Response> {
        let (op, key) = match req {
            Request::Auth { owner, tag } => return Some(self.authenticate(owner, tag, config)),
            Request::Send { .. } | Request::GetBundle { .. } => return None,
            Request::PutBundle { owner, .. } => ("PUT_BUNDLE", owner),
            Request::Fetch { recipient, .. } => ("FETCH", recipient),
            Request::FetchAfter { recipient, .. } => ("FETCH_AFTER", recipient),
            Request::Delete { recipient, .. } => ("DELETE", recipient),
        };
        if self.auth == Auth::Owner(*key) {
            return None;
        }
        log(config, || format!("{op} for={} refused: not authenticated for it", short(key)));
        Some(Response::Error(ErrorCode::Unauthorized))
    }

    /// Checks one AUTH; any AUTH after the first is refused unchecked.
    fn authenticate(&mut self, owner: &Key, tag: &[u8; AUTH_LEN], config: &RelayConfig) -> Response {
        if self.auth != Auth::None {
            log(config, || format!("AUTH owner={} refused: not the first AUTH", short(owner)));
            return Response::Error(ErrorCode::Unauthorized);
        }
        if verify_auth_tag(self.auth_sk, &self.challenge, &self.exporter, owner, tag) {
            self.auth = Auth::Owner(*owner);
            log(config, || format!("AUTH owner={} ok", short(owner)));
            Response::Ok
        } else {
            self.auth = Auth::Refused;
            log(config, || format!("AUTH owner={} refused: wrong tag", short(owner)));
            Response::Error(ErrorCode::Unauthorized)
        }
    }
}

/// One log line, if [`RelayConfig::log`] is set.
fn log(config: &RelayConfig, line: impl FnOnce() -> String) {
    if config.log {
        eprintln!("relay: {}", line());
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
            // The same bundle again (every sync round publishes it) needs no
            // write: answering it does not depend on the disk.
            if s.bundles.get(&owner) != Some(&bundle) {
                if let Some(disk) = s.disk.as_mut() {
                    disk.put_bundle(&owner, &bundle)?;
                }
                s.bundles.insert(owner, bundle);
            }
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
            let mailbox_len = mailbox.len();
            if mailbox_len >= config.max_mailbox
                || s.total_bytes + envelope.len() > config.max_total_bytes
            {
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
            s.total_bytes += envelope.len();
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
            let mut freed = 0;
            if let Some(m) = s.mailboxes.get_mut(&recipient) {
                for seq in &seqs {
                    if let Some((_, v)) = m.remove(seq) {
                        freed += v.len();
                    }
                }
            }
            s.total_bytes -= freed;
            log(format!(
                "DELETE for={} count={}",
                short(&recipient),
                seqs.len()
            ));
            Response::Ok
        }
        // A V2 connection answers AUTH in `Session::screen`; V1 has no AUTH
        // and answers it as any operation it does not know.
        Request::Auth { .. } => Response::Error(ErrorCode::BadRequest),
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

    /// Every sync round publishes the device's bundle. The same bundle again
    /// is answered without a write, so a disk that refuses writes does not
    /// stop every round at its first request; a changed bundle still needs
    /// the disk.
    #[test]
    fn the_same_bundle_again_needs_no_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.db");
        let state = Mutex::new(State {
            next_seq: 1,
            bundles: HashMap::from([([1u8; 32], vec![1u8, 2, 3])]),
            disk: Some(Disk::read_only(&path).unwrap()),
            ..State::default()
        });
        let config = RelayConfig::default();
        let put = |bundle: Vec<u8>| {
            handle(
                Request::PutBundle {
                    owner: [1; 32],
                    bundle,
                },
                &state,
                &config,
            )
        };
        assert_eq!(put(vec![1, 2, 3]).unwrap(), Response::Ok);
        assert!(put(vec![4]).is_err());
        assert_eq!(state.lock().unwrap().bundles[&[1u8; 32]], vec![1, 2, 3]);
    }

    /// The relay's stored envelopes in all mailboxes together never exceed
    /// `max_total_bytes`: a SEND beyond it is refused with FULL, and space
    /// freed by a DELETE can be used again.
    #[test]
    fn envelopes_in_all_mailboxes_are_capped() {
        let state = Mutex::new(State {
            next_seq: 1,
            ..State::default()
        });
        let config = RelayConfig {
            max_total_bytes: 10,
            ..RelayConfig::default()
        };
        let send = |to: u8, len: usize, fill: u8| {
            handle(
                Request::Send {
                    recipient: [to; 32],
                    envelope: vec![fill; len],
                },
                &state,
                &config,
            )
            .unwrap()
        };
        assert_eq!(send(1, 6, 1), Response::Accepted { seq: 1 });
        assert_eq!(send(2, 5, 2), Response::Error(ErrorCode::Full), "another mailbox, same cap");
        assert_eq!(send(2, 4, 3), Response::Accepted { seq: 2 });
        handle(
            Request::Delete {
                recipient: [1; 32],
                seqs: vec![1, 77],
            },
            &state,
            &config,
        )
        .unwrap();
        assert_eq!(state.lock().unwrap().total_bytes, 4);
        assert_eq!(send(3, 6, 4), Response::Accepted { seq: 3 });
    }
}
