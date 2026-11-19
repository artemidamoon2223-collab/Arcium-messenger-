//! End-to-end encrypted messaging over an untrusted relay.
//! Specification: `docs/NET-MESSAGING.md`.
//!
//! [`NetworkMessenger`] moves what the durable layer (S2-B2) already committed:
//! it publishes stored bytes and feeds received bytes to it, and never
//! encrypts or decrypts on its own. So a retry, a crash or a lost connection
//! can repeat a transmission but never produce a second ciphertext for a
//! logical message or a second acceptance of one.
//!
//! Delivery is decided end to end. A text leaves the outbox as delivered only
//! when the recipient's receipt arrives inside the ratchet, naming its exact
//! message id; the relay accepting it proves nothing. (The recipient can also
//! name it in a GONE message, when it can never read it: the text is then
//! abandoned.) Receipts and GONE messages themselves are not acknowledged:
//! they leave the outbox once the relay has accepted them, and if one is lost
//! the sender retransmits the text, which is received again and answered
//! again.
//!
//! The relay is either `RELAY_PROTOCOL_V2` (TLS 1.3 to its pinned key, and
//! mailbox authentication with this device's identity key, which stays in
//! [`ArciumCore`]) or, for development and the failure-injection tests only,
//! `RELAY_PROTOCOL_V1` (plain TCP, no authentication); see [`Relay`].

pub(crate) mod chat;
pub(crate) mod wire;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use core_crypto::spk_id::spk_id;
use core_storage::StorageError;
use relay::address::{AddressError, RelayAddress, ADDRESS_PREFIX};
use relay::client::{ClientError, Connection};
use relay::protocol::{ErrorCode, DEFAULT_MAX_MAILBOX, MAX_FETCH, MIN_PAGE};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::contacts::{pinned, Card};
use core_protocol::messaging::{message_id, MessageId, Received};

use crate::{
    handshake_hash, unpack_prekey_bundle, ArciumCore, CoreError, PlaintextBytes,
    RefusalReason, SendResult,
};
use wire::{client_id, Envelope, Payload};

/// What one [`NetworkMessenger::sync`] did. Counters only; nothing here is a
/// delivery guarantee.
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct SyncReport {
    /// Envelopes the relay accepted (handshakes, texts, receipts, retries).
    pub published: u32,
    /// Envelopes in the part of the mailbox this round scanned (each counted
    /// once, however many passes read it).
    pub fetched: u32,
    /// Messages newly accepted by the ratchet and committed.
    pub accepted: u32,
    pub duplicates: u32,
    /// Sessions created as responder: a recorded handshake whose first
    /// message authenticated in this round. A handshake alone creates none.
    pub sessions_accepted: u32,
    /// Own texts confirmed by the peer's receipt in this round.
    pub delivered: u32,
    /// Envelopes discarded: malformed, from an unknown sender, or not
    /// decryptable.
    pub dropped: u32,
    /// Envelopes left on the relay to retry later (e.g. a message that
    /// arrived before its session's handshake).
    pub deferred: u32,
    /// Failures, including an unreachable relay.
    pub errors: Vec<String>,
}

/// A received text not yet marked read. `text` is the application's copy.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct ReceivedText {
    pub message_id: Vec<u8>,
    pub text: PlaintextBytes,
}

/// Shows the id and hides the text: accidental formatting and logging only.
impl std::fmt::Debug for ReceivedText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceivedText")
            .field("message_id", &self.message_id)
            .field("text", &"<redacted>")
            .finish()
    }
}

/// Where an outgoing text stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TextState {
    /// Committed; waiting for the peer's receipt. `sync` (re)sends it.
    Pending,
    /// The peer's authenticated receipt arrived.
    Delivered,
    /// Given up on by this device; the peer may or may not have it.
    Abandoned,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SentText {
    pub message_id: Vec<u8>,
    pub state: TextState,
}

/// The relay a [`NetworkMessenger`] talks to, read from the string it was
/// given (docs/NET-MESSAGING.md, sections 1 and 3).
enum Relay {
    /// `RELAY_PROTOCOL_V1` at `host:port`, as given: plain TCP, no
    /// authentication. For development builds and the failure-injection
    /// tests only; a release build of the app never passes one.
    V1(String),
    /// `RELAY_PROTOCOL_V2`: TLS 1.3 to the pinned key, and AUTH as this
    /// device's identity key before any operation on its own mailbox or
    /// bundle.
    V2(RelayAddress),
    /// A string with the V2 prefix that does not parse. Every connection
    /// fails with this error; it is never tried as V1.
    Invalid(AddressError),
}

impl Relay {
    fn parse(s: String) -> Self {
        if !s.starts_with(ADDRESS_PREFIX) {
            return Relay::V1(s);
        }
        match RelayAddress::parse(&s) {
            Ok(addr) => Relay::V2(addr),
            Err(e) => Relay::Invalid(e),
        }
    }
}

#[derive(uniffi::Object)]
pub struct NetworkMessenger {
    core: Arc<ArciumCore>,
    relay: Relay,
    timeout: Duration,
    retransmit_after: Duration,
    /// When each message or handshake was last accepted by the relay, and
    /// how often it was. In memory only: after a restart everything pending
    /// is sent once more, and the backoff starts again. Each round drops the
    /// entries nothing reads any more ([`Self::prune_sent`]; tracker R-22).
    last_sent: Mutex<HashMap<[u8; 32], (Instant, u32)>>,
    /// Recipients the relay last refused to store an envelope for (a full
    /// mailbox): when, and how many times in a row. Nothing is sent to one
    /// while its wait runs; the wait is that of a retransmission
    /// ([`Self::retransmit_wait`]). The first envelope the relay stores for
    /// the recipient removes it. In memory only, like `last_sent`.
    refused: Mutex<HashMap<[u8; 32], (Instant, u32)>>,
    limits: Mutex<Limits>,
    /// Where the mailbox passes of the next round start, after a round the
    /// budget cut short. In memory only; `(0, 0)` otherwise.
    resume: Mutex<Resume>,
    /// Handshake refusals to send, and which were sent. In memory only.
    refusals: Mutex<Refusals>,
    /// Per session, messages that arrived after their key was gone (R-21),
    /// collected during a round and named to the peer in GONE messages at
    /// its end ([`Self::commit_gone`]). In memory only, and emptied after
    /// every round: a message not named (a crash, a round that failed) is
    /// sent again by the peer and found again.
    gone: Mutex<HashMap<u64, Vec<[u8; 32]>>>,
    /// Per session and per chain (the ratchet key a header names), when a
    /// message far ahead in that chain was first seen since the session
    /// last accepted a message (tracker R-14): a far skip is tried only once
    /// that is `Limits::far_skip_wait` ago. Keyed by chain, so a forged far
    /// message naming a key of its own starts no genuine chain's wait. At
    /// most [`FAR_CHAINS_PER_SESSION`] chains per session; the one seen
    /// least recently is dropped first. Kept in the store too
    /// ([`far_wait_key`]), so a wait goes on across a restart of the
    /// process; this map holds the sessions read from it or written to it
    /// since the process started.
    far_seen: Mutex<HashMap<u64, FarWaits>>,
    /// This round's far skips to try once the message pass is over, and the
    /// sessions that accepted a message in it. Emptied after every round.
    far_round: Mutex<FarRound>,
    /// Test aid: the minute [`Self::this_minute`] reads instead of the clock.
    #[cfg(test)]
    minute: Mutex<Option<u64>>,
    /// Test aid: the second [`Self::this_second`] reads instead of the clock.
    #[cfg(test)]
    now: Mutex<Option<u64>>,
    /// Test aid: how many far skips this instance tried.
    #[cfg(test)]
    far_tries: std::sync::atomic::AtomicU32,
}

/// Refusals this process owes or sent (docs/NET-MESSAGING.md, section 6).
struct Refusals {
    /// Refusals not yet stored by the relay: recipient, envelope
    /// body, refused handshake's hash.
    queued: Vec<([u8; 32], Vec<u8>, [u8; 32])>,
    /// When a refusal was last sent to each contact. It alone limits a
    /// retransmitted handshake too: refused again once the interval has
    /// passed, so a refusal the relay lost after storing it is replaced.
    last_to: HashMap<[u8; 32], Instant>,
    /// Least time between two refusals to one contact.
    interval: Duration,
}

impl Default for Refusals {
    fn default() -> Self {
        Self {
            queued: Vec::new(),
            last_to: HashMap::new(),
            interval: REFUSAL_INTERVAL,
        }
    }
}

/// The relay sequence numbers after which the two mailbox passes of the next
/// round start. Both are zero (the beginning) unless the last round was cut
/// short by its budget. They are positions chosen by the untrusted relay and
/// are used only as a starting point: any error, and every round that runs
/// to the end, puts them back to zero, so everything skipped is read again.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Resume {
    handshakes: u64,
    messages: u64,
}

/// The part of the mailbox one pass reads: sequence numbers after `from`, up
/// to and including `until`.
#[derive(Debug, Clone, Copy)]
struct Span {
    from: u64,
    until: u64,
}

/// How one mailbox pass ended.
#[derive(Debug, Clone, Copy)]
struct ScanEnd {
    /// The last sequence number the pass reached (where it started, if it
    /// saw nothing).
    reached: u64,
    /// Whether it ran to the end of its part of the mailbox. False only when
    /// the round's budget stopped it.
    complete: bool,
}

/// Time bounds of the network layer (docs/NET-MESSAGING.md, section 7).
#[derive(Debug, Clone, Copy)]
struct Limits {
    /// Bound of one relay request as a whole.
    request_deadline: Duration,
    /// Time one round may spend on relay requests before it stops starting
    /// new ones.
    round_budget: Duration,
    /// Longest wait between two retransmissions of one message.
    retransmit_cap: Duration,
    /// How long a session sees messages far ahead in its chain, accepting
    /// nothing, before a far skip is tried (tracker R-14).
    far_skip_wait: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            request_deadline: relay::client::REQUEST_DEADLINE,
            round_budget: ROUND_BUDGET,
            retransmit_cap: RETRANSMIT_CAP,
            far_skip_wait: FAR_SKIP_WAIT,
        }
    }
}

/// One session's far-skip waits (tracker R-14): per chain, the ratchet key
/// a far message named, and when one was first and last seen.
type FarWaits = Vec<FarWait>;

/// Times are milliseconds of this device's clock since the Unix epoch
/// ([`NetworkMessenger::this_millis`]).
#[derive(Clone, Debug, PartialEq, Eq)]
struct FarWait {
    chain: [u8; 32],
    first: u64,
    last: u64,
    /// The `last` the store holds (not stored itself).
    stored_last: u64,
}

/// The store key of the far-skip waits of the session `handle` (tracker
/// R-14): `FAR_WAIT_RECORD_V1`. Written only by the network layer, deleted
/// when the session accepts a message, when it is given up, and with the
/// contact.
pub(crate) fn far_wait_key(handle: u64) -> String {
    format!("farwait:v1/{handle:016x}")
}

/// `FAR_WAIT_RECORD_V1`: version (1) = 1, count (1) at most
/// [`FAR_CHAINS_PER_SESSION`], then per chain its ratchet key (32), first
/// and last seen (8 each, big-endian milliseconds). Local, never sent.
const FAR_WAIT_RECORD_VERSION: u8 = 1;
const FAR_WAIT_ENTRY_LEN: usize = 32 + 8 + 8;

/// How much later a sighting must be to be stored as the chain's last one:
/// it only orders the chains for dropping, so a minute is precise enough,
/// and a far message repeated many times a minute writes once.
const FAR_WAIT_LAST_STEP_MS: u64 = 60_000;

fn pack_far_waits(waits: &[FarWait]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + FAR_WAIT_ENTRY_LEN * waits.len());
    out.push(FAR_WAIT_RECORD_VERSION);
    out.push(u8::try_from(waits.len()).unwrap_or(u8::MAX));
    for w in waits {
        out.extend_from_slice(&w.chain);
        out.extend_from_slice(&w.first.to_be_bytes());
        out.extend_from_slice(&w.last.to_be_bytes());
    }
    out
}

/// `None` for anything but a well-formed record: it is then read as no
/// wait, and replaced at the next write.
fn unpack_far_waits(bytes: &[u8]) -> Option<FarWaits> {
    let (&version, rest) = bytes.split_first()?;
    let (&count, rest) = rest.split_first()?;
    if version != FAR_WAIT_RECORD_VERSION
        || usize::from(count) > FAR_CHAINS_PER_SESSION
        || rest.len() != FAR_WAIT_ENTRY_LEN * usize::from(count)
    {
        return None;
    }
    let u64_at = |b: &[u8]| u64::from_be_bytes(b.try_into().expect("8 bytes"));
    let mut waits: FarWaits = Vec::with_capacity(usize::from(count));
    for e in rest.chunks_exact(FAR_WAIT_ENTRY_LEN) {
        let chain: [u8; 32] = e[..32].try_into().expect("32 bytes");
        if waits.iter().any(|w| w.chain == chain) {
            return None;
        }
        let last = u64_at(&e[40..48]);
        waits.push(FarWait {
            chain,
            first: u64_at(&e[32..40]),
            last,
            stored_last: last,
        });
    }
    Some(waits)
}

/// Records a far message of `chain` seen at `now` in `waits`: since when
/// the chain has waited, and whether `waits` changed so that it must be
/// stored. A new chain starts waiting now, in place of the chain seen least
/// recently once [`FAR_CHAINS_PER_SESSION`] wait. A clock read before the
/// chain's first sighting (set back) starts its wait again. The last
/// sighting is kept exact in memory and stored at most once per
/// [`FAR_WAIT_LAST_STEP_MS`]: once `waits` is stored, the caller sets each
/// `stored_last` to its `last`.
fn note_far_sighting(waits: &mut FarWaits, chain: [u8; 32], now: u64) -> (u64, bool) {
    if let Some(w) = waits.iter_mut().find(|w| w.chain == chain) {
        if now < w.first {
            w.first = now;
            w.last = now;
            return (now, true);
        }
        w.last = w.last.max(now);
        return (w.first, w.last.saturating_sub(w.stored_last) >= FAR_WAIT_LAST_STEP_MS);
    }
    if waits.len() >= FAR_CHAINS_PER_SESSION {
        if let Some(stale) = (0..waits.len()).min_by_key(|&i| waits[i].last) {
            waits.remove(stale);
        }
    }
    waits.push(FarWait {
        chain,
        first: now,
        last: now,
        stored_last: now,
    });
    (now, true)
}

/// One round's far skips (tracker R-14): the messages to try once the
/// message pass is over, one per session and at most
/// [`FAR_TRIES_PER_ROUND`]; the sessions that accepted a message in the
/// pass, which try none; and the sessions whose first far message in the
/// pass was judged without being kept, which keep none (a session is judged
/// once per pass).
#[derive(Default)]
struct FarRound {
    candidates: Vec<(u64, Vec<u8>)>,
    progressed: HashSet<u64>,
    judged: HashSet<u64>,
}

/// Least time between two refusals to one contact.
pub(crate) const REFUSAL_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// Time one sync round may spend on relay requests (L2). Checked before every
/// page of a mailbox pass after its first and before every send. Each pass
/// still reads its first page and deletes what it processed, so a round
/// that ran out ends within this budget plus a few request deadlines
/// (the request in flight, each pass's first page and deletion).
pub(crate) const ROUND_BUDGET: Duration = Duration::from_secs(120);

/// Longest wait between two retransmissions of one message or handshake
/// (L3). The wait starts at `retransmit_after` and doubles with every send.
pub(crate) const RETRANSMIT_CAP: Duration = Duration::from_secs(5 * 60);

/// Far skips tried per sync round, over all sessions (tracker R-14). Each
/// may derive up to `MAX_FAR_SKIP` chain keys per chain before its message
/// authenticates; a session gets at most one of them.
pub(crate) const FAR_TRIES_PER_ROUND: usize = 4;

/// How long a session must see messages far ahead in its chain without
/// accepting one before a far skip is tried (tracker R-14): two of the
/// longest waits between retransmissions. A gap that the sender's
/// retransmissions fill, as after a relay lost or expired the start of a
/// long run of texts, is then filled first, and its texts are delivered
/// rather than skipped: with an honest relay and a sender that keeps
/// syncing, only a gap nothing fills is skipped. A relay that withholds
/// the start of a run for longer can still have it skipped
/// (`docs/NET-MESSAGING.md` section 8).
pub(crate) const FAR_SKIP_WAIT: Duration = Duration::from_secs(2 * 5 * 60);

/// Chains per session whose far-skip wait is kept (tracker R-14). Whoever
/// can write to the mailbox can name more keys than this "from" a contact,
/// so a genuine chain's wait may be dropped and start again once that many
/// forged keys are judged between two passes in which the genuine chain is
/// (its message being the session's first far message of the pass; a
/// forgery placed ahead of it takes that). A far skip is then held back for
/// as long as the writer keeps doing it, and for up to `FAR_SKIP_WAIT`
/// after it stops.
pub(crate) const FAR_CHAINS_PER_SESSION: usize = 4;

/// The deadline of one round's relay requests, and whether it stopped any
/// work in this round.
#[derive(Debug)]
struct Budget {
    deadline: Instant,
    cut: std::cell::Cell<bool>,
}

impl Budget {
    fn new(budget: Duration) -> Self {
        Self {
            deadline: Instant::now() + budget,
            cut: std::cell::Cell::new(false),
        }
    }

    /// Whether more work may start. A `false` is remembered: the round then
    /// reports that it was cut short.
    fn left(&self) -> bool {
        let left = Instant::now() < self.deadline;
        if !left {
            self.cut.set(true);
        }
        left
    }
}

/// The report line of a round its budget cut short. Not a network error: the
/// relay was reached, and the next round continues.
pub(crate) const BUDGET_EXHAUSTED: &str = "round budget exhausted: the rest follows in the next round";

/// The recipients the relay refused to store an envelope for in one round,
/// and with which codes.
#[derive(Debug, Default)]
struct RelayRefusals {
    recipients: Vec<[u8; 32]>,
    codes: Vec<ErrorCode>,
}

impl RelayRefusals {
    fn note(&mut self, recipient: [u8; 32], code: ErrorCode) {
        if !self.recipients.contains(&recipient) {
            self.recipients.push(recipient);
        }
        if !self.codes.contains(&code) {
            self.codes.push(code);
        }
    }

    /// The round's report line, if the relay refused anything. Not a network
    /// error: the relay was reached. It names no recipient.
    fn line(&self) -> Option<String> {
        let n = self.recipients.len();
        (n > 0).then(|| {
            let codes: Vec<String> = self.codes.iter().map(|c| format!("{c:?}")).collect();
            let noun = if n == 1 { "recipient" } else { "recipients" };
            format!("relay refused {n} {noun}: {}", codes.join(", "))
        })
    }
}

/// A received text and its message id, the text in a wiping owner.
pub(crate) type PendingText = (MessageId, Zeroizing<Vec<u8>>);

fn peer_key(peer: &[u8]) -> Result<[u8; 32], CoreError> {
    peer.try_into().map_err(|_| CoreError::InvalidKey {
        msg: "expected a 32-byte peer identity key".into(),
    })
}

fn handle_of(peer: &[u8; 32]) -> u64 {
    core_crypto::session_handle::local_session_handle(peer)
}

fn network(e: ClientError) -> CoreError {
    CoreError::Network { msg: e.to_string() }
}

enum Fate {
    Delete,
    Keep,
}

/// Most envelopes one pass over the mailbox considers: a whole mailbox of this
/// repository's relay, whose capacity is at most this (`serve` refuses more).
/// Senders that delete what a round read and append as fast as it reads, or
/// a relay that is not this one, can keep the rest out of this round's reach,
/// as a relay can by withholding them.
pub(crate) const MAX_SCAN_ENVELOPES: usize = DEFAULT_MAX_MAILBOX;

/// Most pages one pass reads: enough for [`MAX_SCAN_ENVELOPES`] in pages of
/// [`MIN_PAGE`], the fewest a relay returns while more follow (4096 / 15,
/// rounded up: 274). With two passes, a round makes at most
/// `2 * MAX_SCAN_PAGES` FETCH_AFTER requests.
pub(crate) const MAX_SCAN_PAGES: usize = MAX_SCAN_ENVELOPES.div_ceil(MIN_PAGE);

/// Which envelopes a pass over the mailbox processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pass {
    Handshakes,
    /// Everything that is not a handshake.
    Messages,
}

#[uniffi::export]
impl NetworkMessenger {
    /// `relay_address` is a V2 connection string,
    /// `arcium-relay-v2:<host>:<port>:<tls_pin>:<auth_pk>` (TLS to the pinned
    /// key; this device authenticates for its own mailbox and bundle), or,
    /// for development and tests only, `host:port` of a V1 relay (no TLS, no
    /// authentication). A string with the V2 prefix that does not parse is
    /// never tried as V1: every network call then fails with `Network`, as it
    /// does for an address that cannot be reached. A failed TLS handshake (a
    /// key other than the pinned one) and a refused AUTH are `Network` errors
    /// too. A pending message or handshake is sent
    /// again by `sync` once `retransmit_after_ms` has passed without its
    /// receipt, and again after twice as long each time, up to 5 minutes.
    /// Every single read and write on the relay connection times out after
    /// `timeout_ms`, every request as a whole after 30 s, and a round stops
    /// starting requests after 120 s (docs/NET-MESSAGING.md, section 7).
    #[uniffi::constructor]
    pub fn new(
        core: Arc<ArciumCore>,
        relay_address: String,
        retransmit_after_ms: u64,
        timeout_ms: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            core,
            relay: Relay::parse(relay_address),
            timeout: Duration::from_millis(timeout_ms),
            retransmit_after: Duration::from_millis(retransmit_after_ms),
            last_sent: Mutex::new(HashMap::new()),
            refused: Mutex::new(HashMap::new()),
            refusals: Mutex::new(Refusals::default()),
            gone: Mutex::new(HashMap::new()),
            far_seen: Mutex::new(HashMap::new()),
            far_round: Mutex::new(FarRound::default()),
            #[cfg(test)]
            minute: Mutex::new(None),
            #[cfg(test)]
            now: Mutex::new(None),
            #[cfg(test)]
            far_tries: std::sync::atomic::AtomicU32::new(0),
            limits: Mutex::new(Limits::default()),
            resume: Mutex::new(Resume::default()),
        })
    }

    /// Publishes this device's prekey bundle, creating prekeys first if none
    /// exist yet, and rotating the signed prekey first if that is due
    /// (`ArciumCore::maintain_prekeys`, tracker R-6). The one-time prekey is
    /// not replaced here, except once, the first time on a store an earlier
    /// build wrote (`ArciumCore::replace_prekey_once`).
    pub fn publish_prekeys(&self) -> Result<(), CoreError> {
        let mut conn = self.connect_owner()?;
        self.put_bundle(&mut conn)
    }

    /// Starts a session with the pinned contact `peer`: fetches its bundle,
    /// refuses it with `PeerIdentityMismatch` unless both identity keys equal
    /// the pinned card, runs X3DH, and commits the session with an OPEN
    /// message. The handshake and the OPEN message are sent by `sync`.
    pub fn start_session(&self, peer: Vec<u8>) -> Result<(), CoreError> {
        let peer = peer_key(&peer)?;
        let card = self.require_contact(&peer)?;
        let handle = handle_of(&peer);
        if self.core.has_session(handle)? {
            return Err(CoreError::SessionAlreadyExists { session_id: handle });
        }
        // GET_BUNDLE needs no AUTH, and this connection makes none.
        let bundle = self
            .connect()?
            .get_bundle(peer)
            .map_err(network)?
            .ok_or(CoreError::PeerBundleUnavailable)?;
        let parsed = unpack_prekey_bundle(&bundle)?;
        if parsed.identity_pk.to_bytes() != card.dh_pk
            || parsed.signing_pk.to_bytes() != card.signing_pk
        {
            return Err(CoreError::PeerIdentityMismatch);
        }
        let handshake = self.core.establish_session_initiator(handle, bundle)?;
        // The OPEN message's id names the handshake: a session that replaces
        // an abandoned one (after a refusal) needs an OPEN of its own, and
        // the abandoned one's send record would answer for a shared id.
        self.core
            .send_committed(handle, &client_id::open(&handshake), &Payload::Open.encode())?;
        Ok(())
    }

    /// Commits the text `text` for `peer` under the application's own id for
    /// it (1 to 63 bytes). Repeating a call with the same id sends nothing new
    /// and reports where the first one stands. `sync` transmits it. An id
    /// already used by `chat_send` for this peer is refused, and an id used
    /// here is then refused by `chat_send`: both commit under the same client
    /// id, and the history must only follow its own messages. The id stays
    /// taken by `send_text` even if this call then fails (for example with
    /// no session yet); repeating it is how to send.
    pub fn send_text(
        &self,
        peer: Vec<u8>,
        client_message_id: Vec<u8>,
        text: Vec<u8>,
    ) -> Result<SentText, CoreError> {
        let text = Zeroizing::new(text);
        let peer = peer_key(&peer)?;
        self.require_contact(&peer)?;
        if client_message_id.is_empty() || client_message_id.len() > 63 {
            return Err(CoreError::InvalidClientMessageId);
        }
        self.claim_for_send_text(&peer, &client_message_id)?;
        self.send_committed_text(&peer, &client_message_id, text)
    }

    /// Texts from `peer` accepted and not yet marked read, in order. The same
    /// text can appear again after a crash if it was not marked read:
    /// delivery to the application is at least once, and `message_id`
    /// identifies a repeat.
    pub fn received_texts(&self, peer: Vec<u8>) -> Result<Vec<ReceivedText>, CoreError> {
        // The application's copy of each text is made here, at the boundary,
        // and nowhere earlier.
        Ok(self
            .pending_texts(&peer_key(&peer)?)?
            .into_iter()
            .map(|(message_id, text)| ReceivedText {
                message_id: message_id.to_vec(),
                text: PlaintextBytes(text.to_vec()),
            })
            .collect())
    }

    /// Marks a received text as durably processed by the application.
    ///
    /// Its receipt is committed first if it has none yet. `settle` commits
    /// it when the text is accepted, but a crash between the two leaves the
    /// text in the inbox without one, and the application may read and mark
    /// it before any sync round runs. A text marked read without a receipt
    /// would leave its sender waiting, since a repeated message is answered
    /// only if the original was (`receipt_again`).
    pub fn mark_read(&self, peer: Vec<u8>, message_id: Vec<u8>) -> Result<bool, CoreError> {
        let key = peer_key(&peer)?;
        let handle = handle_of(&key);
        if let Ok(id) = <[u8; 32]>::try_from(message_id.as_slice()) {
            // One read in the usual case; the inbox only after a crash.
            if self.core.prior_send(&key, &client_id::receipt(&id, 0))?.is_none()
                && self
                    .pending_texts(&key)?
                    .iter()
                    .any(|(m, _)| m.as_slice() == id.as_slice())
            {
                self.receipt(handle, &id, 0)?;
            }
        }
        self.core.acknowledge_incoming(handle, message_id)
    }

    /// Ids of own texts to `peer` still waiting for the peer's receipt.
    pub fn undelivered(&self, peer: Vec<u8>) -> Result<Vec<Vec<u8>>, CoreError> {
        let handle = handle_of(&peer_key(&peer)?);
        Ok(self
            .core
            .pending_outgoing(handle)?
            .into_iter()
            .filter(|m| m.client_message_id.first() == Some(&client_id::TEXT))
            .map(|m| m.message_id)
            .collect())
    }

    /// One round with the relay: publish the bundle, (re)send whatever is
    /// pending, fetch this device's mailbox and process it, send the receipts
    /// that produced. Local state stays consistent whatever fails; the report
    /// lists the failures.
    pub fn sync(&self) -> SyncReport {
        let mut report = SyncReport::default();
        let mut relay_refusals = RelayRefusals::default();
        if let Err(e) = self.sync_round(&mut report, &mut relay_refusals) {
            report.errors.push(e.to_string());
        }
        // After every round, also one that failed part way: a relay that
        // breaks each round must not keep this record growing (R-22).
        if let Err(e) = self.prune_sent() {
            report.errors.push(e.to_string());
        }
        // Nor the messages found beyond recall in a round that failed before
        // naming them: the contact sends them again, and they are found again.
        self.gone.lock().expect("gone").clear();
        *self.far_round.lock().expect("far_round") = FarRound::default();
        report.errors.extend(relay_refusals.line());
        report
    }
}

impl NetworkMessenger {
    /// [`send_text`](Self::send_text) for a text already held in a wiping
    /// owner, which it takes. The text moves into the payload (wiped once
    /// encoded); `send_committed` borrows the encoded payload, a wiping owner
    /// wiped when this returns, on every exit.
    pub(super) fn send_committed_text(
        &self,
        peer: &[u8; 32],
        client_message_id: &[u8],
        text: Zeroizing<Vec<u8>>,
    ) -> Result<SentText, CoreError> {
        self.require_contact(peer)?;
        let payload = Payload::Text(text).encode();
        let sent = self.core.send_committed(
            handle_of(peer),
            &client_id::text(client_message_id),
            &payload,
        )?;
        Ok(match sent {
            SendResult::Sent { message } | SendResult::AlreadyPending { message } => SentText {
                message_id: message.message_id,
                state: TextState::Pending,
            },
            SendResult::AlreadyAcknowledged { message_id } => SentText {
                message_id,
                state: TextState::Delivered,
            },
            SendResult::Abandoned { message_id } => SentText {
                message_id,
                state: TextState::Abandoned,
            },
        })
    }

    /// A connection to the relay that makes no AUTH: enough for GET_BUNDLE.
    /// A V2 relay stores a SEND only from a connection authenticated as the
    /// envelope's sender (tracker R-9), so every SEND goes on
    /// [`Self::connect_owner`].
    fn connect(&self) -> Result<Connection, CoreError> {
        let mut conn = match &self.relay {
            Relay::V1(addr) => Connection::connect(addr, self.timeout),
            Relay::V2(addr) => Connection::connect_v2(addr, self.timeout),
            Relay::Invalid(e) => return Err(CoreError::Network { msg: e.to_string() }),
        }
        .map_err(network)?;
        conn.set_request_deadline(self.limits().request_deadline);
        Ok(conn)
    }

    /// A connection that acts for this device's own mailbox and bundle
    /// (FETCH, FETCH_AFTER, DELETE, PUT_BUNDLE). On a V2 relay it makes AUTH
    /// as this device's identity key right after connecting; a V1 relay has
    /// no authentication.
    fn connect_owner(&self) -> Result<Connection, CoreError> {
        let mut conn = self.connect()?;
        if matches!(self.relay, Relay::V2(_)) {
            self.authenticate(&mut conn)?;
        }
        Ok(conn)
    }

    /// AUTH on `conn` as this device's identity key, once. The identity
    /// secret stays in [`ArciumCore`]: it writes the DH output with the
    /// relay's auth key into the relay client's buffer, and the client
    /// derives the tag from it and wipes it. A refused AUTH (the relay's
    /// answer, or no usable DH output) is a `Network` error and is not
    /// retried: the caller's operation, or the round, ends with it. Its text
    /// names authentication, so it reads apart from a later operation the
    /// relay refuses.
    fn authenticate(&self, conn: &mut Connection) -> Result<(), CoreError> {
        let our = self.core.our_identity_pk()?;
        let mut failed = None;
        // Without a usable DH output the buffer stays all zeros, which the
        // client refuses without sending anything; `failed` says why.
        let authenticated = conn.authenticate(our, |auth_pk, out| match self.core.identity_dh(auth_pk, out) {
            Ok(true) => {}
            Ok(false) => {
                failed = Some(CoreError::Network {
                    msg: "cannot authenticate to the relay: its auth key is of low order".into(),
                });
            }
            Err(e) => failed = Some(e),
        });
        if let Some(e) = failed {
            return Err(e);
        }
        authenticated.map_err(|e| CoreError::Network { msg: format!("relay authentication failed: {e}") })
    }

    fn limits(&self) -> Limits {
        *self.limits.lock().expect("limits")
    }

    /// Test aid: the bounds of `docs/NET-MESSAGING.md` section 7, scaled.
    #[cfg(test)]
    pub(crate) fn set_limits(&self, request_deadline: Duration, round_budget: Duration, retransmit_cap: Duration) {
        let mut limits = self.limits.lock().expect("limits");
        *limits = Limits {
            request_deadline,
            round_budget,
            retransmit_cap,
            ..*limits
        };
    }

    /// Test aid: the wait before a far skip ([`FAR_SKIP_WAIT`]).
    #[cfg(test)]
    pub(crate) fn set_far_skip_wait(&self, wait: Duration) {
        self.limits.lock().expect("limits").far_skip_wait = wait;
    }

    fn require_contact(&self, peer: &[u8; 32]) -> Result<Card, CoreError> {
        let store = self.core.store.lock().map_err(|_| CoreError::Storage {
            msg: "mutex poisoned".into(),
        })?;
        pinned(&store, peer)?.ok_or(CoreError::UnknownContact)
    }

    /// Publishes the bundle: the one-time prekey replaced once for option B,
    /// then the prekey record created or its signed prekey rotated if due
    /// (tracker R-6), then the bundle exported and stored by the relay, then
    /// that acceptance recorded, from which the signed prekey ages. The
    /// bundle is exported only here, right after the rotation check (the
    /// rotation after a one-time-prekey change relies on it,
    /// `export_prekey_bundle`). Any failure ends the round.
    fn put_bundle(&self, conn: &mut Connection) -> Result<(), CoreError> {
        self.core.replace_prekey_once()?;
        let now = self.this_second();
        self.core.maintain_prekeys(now)?;
        crash_point("bundle_after_maintain");
        let bundle = self.core.export_prekey_bundle()?;
        let spk = bundle
            .get(68..100)
            .and_then(|pk| <[u8; 32]>::try_from(pk).ok())
            .map(|pk| spk_id(&pk))
            .ok_or_else(|| CoreError::Storage {
                msg: "exported bundle is malformed".into(),
            })?;
        conn.put_bundle(self.core.our_identity_pk()?, bundle)
            .map_err(network)?;
        crash_point("bundle_after_put");
        self.core.note_prekeys_published(&spk, now)
    }

    /// Contacts that have a session, with its handle.
    fn sessions(&self) -> Result<Vec<([u8; 32], u64)>, CoreError> {
        let mut out = Vec::new();
        for peer in self.core.contacts()? {
            let peer = peer_key(&peer)?;
            let handle = handle_of(&peer);
            if self.core.has_session(handle)? {
                out.push((peer, handle));
            }
        }
        Ok(out)
    }

    fn sync_round(&self, report: &mut SyncReport, relay_refusals: &mut RelayRefusals) -> Result<(), CoreError> {
        let budget = Budget::new(self.limits().round_budget);
        // Taken, so that a round that fails anywhere starts the next one
        // from the beginning; set again below only by a round cut short.
        let from = std::mem::take(&mut *self.resume.lock().expect("resume"));
        // A commit whose outcome is unknown leaves its session unresolved,
        // and every send on it is refused until `recover_session`. Receiving
        // recovers it (`process`), but the sends below come first, and one
        // refusal ends the round for every contact; so recover here.
        for peer in self.core.contacts()? {
            self.core.recover_if_unresolved(handle_of(&peer_key(&peer)?))?;
        }
        let sessions = self.sessions()?;
        // Local recovery first: receipts or OPEN messages committed before a
        // crash, and receipts for texts accepted before one.
        for (_, handle) in &sessions {
            self.settle_inbox(*handle, report)?;
        }
        // One connection for the whole round, authenticated on V2: the round
        // publishes the bundle and reads and deletes from the mailbox.
        let mut conn = self.connect_owner()?;
        // Before anything is read from the mailbox, and fatal: no handshake
        // or message is processed in a round whose bundle publication and
        // its record did not both succeed. A handshake is answered only
        // under a signed prekey that is current or the previous one, and
        // only a published one ages into rotation (tracker R-6).
        self.put_bundle(&mut conn)?;
        self.publish_pending(&mut conn, &sessions, &budget, relay_refusals, report)?;

        let our = self.core.our_identity_pk()?;
        // Handshakes before messages, so a session exists for what follows:
        // first every handshake in the part of the mailbox scanned, then
        // everything else in that same part.
        let all = Span {
            from: from.handshakes,
            until: u64::MAX,
        };
        let handshakes = self.scan(&mut conn, our, Pass::Handshakes, all, &budget, report)?;
        // Messages only as far as the handshakes were read (in this round or,
        // after a cut, in the rounds before it).
        let messages = if handshakes.reached > 0 {
            let read = Span {
                from: from.messages,
                until: handshakes.reached,
            };
            self.scan(&mut conn, our, Pass::Messages, read, &budget, report)?
        } else {
            ScanEnd {
                reached: from.messages,
                complete: true,
            }
        };
        if !(handshakes.complete && messages.complete) {
            // Cut short: the next round continues where each pass stopped,
            // so both move on even when a page holds nothing but kept
            // envelopes. Once both reach the end, a round starts over.
            *self.resume.lock().expect("resume") = Resume {
                handshakes: handshakes.reached,
                messages: messages.reached,
            };
        }
        self.far_pass(report);
        self.send_refusals(&mut conn, &budget, relay_refusals, report)?;
        self.commit_gone(report);
        // Receipts and GONE messages produced above, and the first messages
        // of new sessions.
        let sessions = self.sessions()?;
        self.publish_pending(&mut conn, &sessions, &budget, relay_refusals, report)?;
        if budget.cut.get() {
            // What this round processed is committed and deleted; the rest
            // stays on the relay (or in the outbox) for the next round.
            report.errors.push(BUDGET_EXHAUSTED.into());
        }
        Ok(())
    }

    /// One pass over this device's mailbox: pages through it in ascending
    /// relay order with FETCH_AFTER, processes the envelopes `pass` selects
    /// among those numbered up to `until`, and deletes from the relay exactly
    /// those whose fate is [`Fate::Delete`]. Envelopes kept, and envelopes the
    /// pass does not select, stay on the relay, and paging moves past them:
    /// a retained prefix cannot hide what follows it.
    ///
    /// At most [`MAX_SCAN_PAGES`] pages and [`MAX_SCAN_ENVELOPES`] envelopes;
    /// the pass ends early on a page shorter than [`MIN_PAGE`], which the relay
    /// only returns when nothing follows, and on reaching `until`. The pass
    /// starts after `from`: zero, the beginning, except in the round after
    /// one its budget cut short (see [`Resume`]). Sequence numbers are
    /// transport positions chosen by the untrusted relay, never evidence of
    /// anything. A relay that does not return strictly increasing numbers
    /// after the cursor ends the round with an error.
    ///
    /// The first page is always read; before each later one the round's
    /// budget is checked, and a pass it stops returns `complete: false`.
    fn scan(
        &self,
        conn: &mut Connection,
        our: [u8; 32],
        pass: Pass,
        span: Span,
        budget: &Budget,
        report: &mut SyncReport,
    ) -> Result<ScanEnd, CoreError> {
        let Span { from, until } = span;
        let mut after = from;
        let mut complete = true;
        let mut seen = 0usize;
        let mut delete = Vec::new();
        'pages: for page in 0..MAX_SCAN_PAGES {
            // Out of time: stop after the page in hand and delete what was
            // processed. The first page of a pass is always read, so each
            // round moves both passes on by at least a page; the next round
            // starts after it.
            if page > 0 && !budget.left() {
                complete = false;
                break;
            }
            let items = conn.fetch_after(our, after, MAX_FETCH).map_err(network)?;
            if items.len() > MAX_FETCH as usize {
                return Err(CoreError::Network {
                    msg: "relay returned more envelopes than asked for".into(),
                });
            }
            if items.is_empty() {
                break;
            }
            #[cfg(test)]
            scan_hook::run(pass, page);
            let last = items.len() < MIN_PAGE;
            for (seq, bytes) in items {
                if seq <= after {
                    return Err(CoreError::Network {
                        msg: "relay returned envelopes out of order".into(),
                    });
                }
                if seq > until {
                    break 'pages;
                }
                after = seq;
                seen += 1;
                if pass == Pass::Handshakes {
                    report.fetched += 1;
                }
                let env = Envelope::decode(&bytes);
                let handshake = matches!(env, Some(Envelope::Handshake { .. }));
                if handshake == (pass == Pass::Handshakes) {
                    let fate = match env {
                        None => {
                            report.dropped += 1;
                            Fate::Delete
                        }
                        Some(env) => self.process(env, report)?,
                    };
                    match fate {
                        Fate::Delete => delete.push(seq),
                        Fate::Keep => report.deferred += 1,
                    }
                }
                if seen == MAX_SCAN_ENVELOPES || seq == until {
                    break 'pages;
                }
            }
            if pass == Pass::Messages {
                crash_point("after_page");
            }
            if last {
                break;
            }
        }
        if !delete.is_empty() {
            conn.delete(our, delete).map_err(network)?;
            if pass == Pass::Messages {
                crash_point("after_delete");
            }
        }
        Ok(ScanEnd {
            reached: after,
            complete,
        })
    }

    /// Whether the session under `handle` has accepted a message from the
    /// peer, which then holds it too.
    fn confirmed(&self, handle: u64) -> Result<bool, CoreError> {
        let our = self.core.our_identity_pk()?;
        let (mut store, messenger) = self.core.lock()?;
        messenger
            .has_received(&mut store, our, handle)
            .map_err(|e| CoreError::messaging(handle, e))
    }

    /// Whether the relay accepted the pending message `id` in this process's
    /// lifetime (entries of messages no longer pending are dropped:
    /// [`Self::prune_sent`]).
    fn was_sent(&self, id: &[u8]) -> bool {
        let Ok(id) = <[u8; 32]>::try_from(id) else {
            return false;
        };
        self.last_sent.lock().expect("last_sent").contains_key(&id)
    }

    /// Whether `key` may be sent now: never sent in this process, or the
    /// wait after its last send passed. The wait is `retransmit_after` after
    /// the first send and doubles with each further one, up to the cap.
    fn due(&self, key: &[u8; 32]) -> bool {
        let cap = self.limits().retransmit_cap;
        let sent = self.last_sent.lock().expect("last_sent");
        sent.get(key)
            .is_none_or(|(t, sends)| t.elapsed() >= self.retransmit_wait(*sends, cap))
    }

    /// The wait after the `sends`-th send (`sends` >= 1).
    pub(crate) fn retransmit_wait(&self, sends: u32, cap: Duration) -> Duration {
        let doublings = sends.saturating_sub(1).min(31);
        self.retransmit_after
            .checked_mul(1u32 << doublings)
            .unwrap_or(cap)
            .min(cap)
    }

    /// Drops the `last_sent` entries nothing reads any more (tracker R-22).
    /// Its two readers, [`Self::due`] and [`Self::was_sent`], only ask about
    /// messages still in an outbox and about a session's own handshake: an
    /// acknowledged or abandoned message, a receipt (acknowledged as it is
    /// sent) and anything of a contact without a session are never asked
    /// about again. So an entry stays while its key is the id of a pending
    /// outgoing message or the hash of the initiator handshake of a session
    /// read here, and also when it was written after this pass began, by a
    /// send (possibly on a session created meanwhile) it may not have seen.
    fn prune_sent(&self) -> Result<(), CoreError> {
        let since = Instant::now();
        // One listing of the outbox's key names, for every contact: no
        // outbox record is read or decrypted (tracker R-22).
        let mut live: HashSet<[u8; 32]> = self.core.pending_outgoing_ids()?.into_iter().collect();
        for (_, handle) in self.sessions()? {
            if let Some(hs) = self.core.initiator_handshake(handle)? {
                live.insert(<[u8; 32]>::from(Sha256::digest(&hs)));
            }
        }
        self.last_sent
            .lock()
            .expect("last_sent")
            .retain(|key, (sent_at, _)| live.contains(key) || *sent_at >= since);
        Ok(())
    }

    fn mark_sent(&self, key: [u8; 32]) {
        let mut sent = self.last_sent.lock().expect("last_sent");
        let sends = sent.get(&key).map_or(0, |(_, n)| *n);
        sent.insert(key, (Instant::now(), sends.saturating_add(1)));
    }

    /// Whether sends to `peer` wait after a relay refusal.
    fn held(&self, peer: &[u8; 32]) -> bool {
        let cap = self.limits().retransmit_cap;
        let refused = self.refused.lock().expect("refused");
        refused
            .get(peer)
            .is_some_and(|(t, times)| t.elapsed() < self.retransmit_wait(*times, cap))
    }

    /// Test aid: how many times in a row the relay refused `peer`.
    #[cfg(test)]
    pub(crate) fn refusals_in_a_row(&self, peer: &[u8; 32]) -> u32 {
        self.refused.lock().expect("refused").get(peer).map_or(0, |(_, n)| *n)
    }

    /// Asks the relay to store `envelope` for `peer`. `Ok(false)`: the relay
    /// refused (a full mailbox; on V2 also an envelope that does not name the
    /// connection's authenticated owner as its sender, which this layer never
    /// sends). It read the request and answered, so the
    /// connection is still in step and the round goes on; the recipient
    /// starts or prolongs its wait. Any other failure ends the round, as the
    /// connection's state is then unknown.
    fn send_to(
        &self,
        conn: &mut Connection,
        peer: [u8; 32],
        envelope: Vec<u8>,
        relay_refusals: &mut RelayRefusals,
    ) -> Result<bool, CoreError> {
        match conn.send(peer, envelope) {
            Ok(_) => {
                self.refused.lock().expect("refused").remove(&peer);
                Ok(true)
            }
            Err(ClientError::Refused(code)) => {
                let mut refused = self.refused.lock().expect("refused");
                let times = refused.get(&peer).map_or(0, |(_, n)| *n);
                refused.insert(peer, (Instant::now(), times.saturating_add(1)));
                relay_refusals.note(peer, code);
                Ok(false)
            }
            Err(e) => Err(network(e)),
        }
    }

    /// Sends what is due to every session's peer. A peer the relay refuses
    /// gets nothing more in this round and nothing until its wait is over
    /// ([`Self::held`]), so its envelopes stay in their order; the other
    /// peers are not affected.
    fn publish_pending(
        &self,
        conn: &mut Connection,
        sessions: &[([u8; 32], u64)],
        budget: &Budget,
        relay_refusals: &mut RelayRefusals,
        report: &mut SyncReport,
    ) -> Result<(), CoreError> {
        let our = self.core.our_identity_pk()?;
        for (peer, handle) in sessions {
            // Out of time: the rest is sent next round.
            if !budget.left() {
                return Ok(());
            }
            if relay_refusals.recipients.contains(peer) || self.held(peer) {
                continue;
            }
            if !self.confirmed(*handle)? {
                if let Some(hs) = self.core.initiator_handshake(*handle)? {
                    let key: [u8; 32] = Sha256::digest(&hs).into();
                    if self.due(&key) {
                        let env = Envelope::Handshake {
                            sender: our,
                            handshake: hs,
                        };
                        if !self.send_to(conn, *peer, env.encode(), relay_refusals)? {
                            continue;
                        }
                        self.mark_sent(key);
                        report.published += 1;
                    }
                }
            }
            for m in self.core.pending_outgoing(*handle)? {
                // A text the user cancelled is never sent again: abandoned
                // here instead (`chat::cancel_text`; R-15).
                if let Some((&client_id::TEXT, app_id)) = m.client_message_id.split_first() {
                    if self.cancelled_text(peer, app_id)? {
                        self.core.abandon_outgoing(*handle, m.message_id)?;
                        continue;
                    }
                }
                let id: [u8; 32] = m.message_id.as_slice().try_into().expect("32-byte id");
                if !self.due(&id) {
                    continue;
                }
                if !budget.left() {
                    return Ok(());
                }
                let env = Envelope::Message {
                    sender: our,
                    wire: m.wire,
                };
                if !self.send_to(conn, *peer, env.encode(), relay_refusals)? {
                    break;
                }
                self.mark_sent(id);
                report.published += 1;
                // Receipts and GONE messages are not answered: each leaves
                // the outbox once the relay accepted it.
                if matches!(
                    m.client_message_id.first(),
                    Some(&client_id::RECEIPT) | Some(&client_id::GONE)
                ) {
                    self.core.acknowledge_outgoing(*handle, m.message_id)?;
                }
            }
        }
        Ok(())
    }

    /// Decides what happens to one fetched envelope. An error return aborts
    /// the round; everything not yet deleted stays on the relay.
    fn process(&self, env: Envelope, report: &mut SyncReport) -> Result<Fate, CoreError> {
        let sender = env.sender();
        let card = {
            let store = self.core.store.lock().map_err(|_| CoreError::Storage {
                msg: "mutex poisoned".into(),
            })?;
            pinned(&store, &sender)?
        };
        if card.is_none() {
            report.dropped += 1;
            return Ok(Fate::Delete);
        }
        let handle = handle_of(&sender);
        match env {
            Envelope::Handshake { handshake, .. } => {
                // The handshake must be the sender's own: its initiator key is
                // what the session is keyed from.
                if handshake.len() != crate::INITIATOR_HANDSHAKE_V1_LEN
                    || handshake[4..36] != sender
                {
                    report.dropped += 1;
                    return Ok(Fate::Delete);
                }
                let has_session = self.core.has_session(handle)?;
                // A responder session an older build stored on receipt of a
                // handshake, untouched since, does not stop the handshake
                // here: `establish_session_responder` alone decides whether
                // it retires that session (docs/S2-B2-DURABLE-MESSAGING.md,
                // section 4b). Nothing is decided or changed here.
                let legacy = has_session && self.core.is_legacy_unconfirmed(handle)?;
                if has_session && !legacy {
                    // No session is replaced by a handshake. If ours is an
                    // unconfirmed start of our own, the handshake is recorded
                    // beside it and raises nothing: its bytes are public, so
                    // a mailbox writer can make one (tracker R-13). Both
                    // sides having started is recorded only once the
                    // contact's first message under it authenticates (the
                    // `Message` branch). (A handshake only recorded here is
                    // not a session and does not reach this branch: it may
                    // be replaced.)
                    if self.own_unconfirmed(handle)? {
                        return self.record_beside(sender, &handshake, handle, report);
                    }
                    // Beside an established session it may be the
                    // contact's restart (option B): recorded the same way,
                    // and only its first message, authenticating there,
                    // replaces the session (`take_message`).
                    if self.confirmed(handle)? {
                        return self.record_restart(sender, &handshake, handle, report);
                    }
                    report.dropped += 1;
                    return Ok(Fate::Delete);
                }
                // Recorded as provisional only: the session is created when
                // the initiator's first message authenticates under it.
                match self.core.establish_session_responder(handle, handshake.clone()) {
                    Ok(()) => Ok(Fate::Delete),
                    Err(e) if transient(&e) => {
                        report.errors.push(e.to_string());
                        Ok(Fate::Keep)
                    }
                    // Refused, so the older session stays (something is
                    // pending on it, it changed meanwhile into a session that
                    // is never replaced, or this handshake cannot be
                    // answered — such as a retransmission of the handshake
                    // that session came from): dropped, as for any other
                    // session.
                    Err(_) if legacy => {
                        report.dropped += 1;
                        Ok(Fate::Delete)
                    }
                    Err(e) => {
                        chat::set_flag(self, &sender, chat::HANDSHAKE_REFUSED)?;
                        // No session holds this handshake and its prekeys are
                        // gone: tell the initiator, so it can start again.
                        if let Some(reason) = RefusalReason::of(&e) {
                            self.queue_refusal(sender, &handshake, reason)?;
                        }
                        report.dropped += 1;
                        report.errors.push(format!("handshake refused: {e}"));
                        Ok(Fate::Delete)
                    }
                }
            }
            Envelope::Refusal { refusal, .. } => {
                let card = card.expect("checked above");
                self.take_refusal(&sender, &card, &refusal, report)?;
                Ok(Fate::Delete)
            }
            Envelope::Message { wire, .. } => self.take_message(sender, handle, &wire, report),
        }
    }

    /// A message envelope from the pinned contact `sender` (`process`).
    fn take_message(
        &self,
        sender: [u8; 32],
        handle: u64,
        wire: &[u8],
        report: &mut SyncReport,
    ) -> Result<Fate, CoreError> {
        // Without a session, the message is either the first one of a
        // recorded handshake — which creates the session if it
        // authenticates — or waits for its handshake (`NoSession`).
        let first = !self.core.has_session(handle)?;
        let received = self.core.receive_committed(handle, wire);
        // Not a message of our established session: it may be the contact's
        // first message under a handshake recorded beside it, that is, the
        // contact restarted the session (option B). That it authenticates
        // there needs the contact's identity secret (or this device's
        // signed-prekey secret, while that is still held: NET-MESSAGING
        // section 8), and the handshake must
        // name this device's current one-time prekey, which a replay of a
        // handshake older than our session does not (`ArciumCore::new`
        // replaces it when an own session is confirmed). Checked before a far
        // skip, which would otherwise take the message. A failed check is
        // reported and must not abort the round.
        if !first && matches!(received, Err(CoreError::Crypto { .. })) && self.confirmed(handle)? {
            match self.core.beside_authenticates(handle, &sender, wire) {
                Ok(true) => {
                    self.accept_restart(&sender, handle)?;
                    crash_point("restart_after_retire");
                    // No session now: the message is read as the first one
                    // of the recorded handshake, which creates the new one.
                    return self.take_message(sender, handle, wire, report);
                }
                Ok(false) => {}
                Err(e) => report
                    .errors
                    .push(format!("checking a restart beside our session: {e}")),
            }
        }
        if !first
            && matches!(received, Err(CoreError::Crypto { .. }))
            && self.far_candidate(handle, wire, report)
        {
            // Tried once the message pass is over (`far_pass`).
            return Ok(Fate::Delete);
        }
        match received {
            Ok(Received::Accepted(message)) => {
                self.far_progress(handle);
                report.accepted += 1;
                if first {
                    report.sessions_accepted += 1;
                }
                crash_point("after_accept");
                self.settle(handle, &message.message_id, &message.plaintext, report)?;
                crash_point("after_settle");
                Ok(Fate::Delete)
            }
            Ok(Received::Duplicate { message_id, .. }) => {
                report.duplicates += 1;
                self.receipt_again(handle, &sender, &message_id)?;
                Ok(Fate::Delete)
            }
            Err(CoreError::NoSession { .. }) => Ok(Fate::Keep),
            Err(CoreError::Crypto { .. }) => {
                // Not a message of our session. If ours is an
                // unconfirmed start of our own, this may be the
                // contact's first message under a handshake
                // recorded beside it. If it authenticates there —
                // which needs the contact's identity secret (or a
                // signed-prekey secret we still hold, NET-MESSAGING
                // section 8) — both
                // devices started a session with each other: the
                // conflict is recorded so the application can show
                // it (section 10). Nothing else is stored.
                //
                // The message is deleted, like any message that
                // does not decrypt here. That loses nothing: the
                // contact keeps it in its outbox and retransmits it,
                // with its handshake, until our receipt (which no
                // session here can give) or until it gives up that
                // session itself. It can only be accepted after
                // `resolve_session_conflict` removed our session, and
                // until then the contact's session stays unconfirmed,
                // so the retransmission is still running then.
                //
                // A beside record that cannot be read or decoded
                // counts as none, as `record_handshake_beside` and
                // `remove_session` treat it: the check is reported
                // and the message is deleted. It must not abort the
                // round, or anyone who stores a message "from" the
                // contact would stall every round here.
                if !first && self.own_unconfirmed(handle)? {
                    match self.core.beside_authenticates(handle, &sender, wire) {
                        Ok(true) => {
                            chat::set_flag(self, &sender, chat::CONFLICT)?;
                            crash_point("conflict_after_flag");
                        }
                        Ok(false) => {}
                        Err(e) => report
                            .errors
                            .push(format!("checking a first message beside our session: {e}")),
                    }
                }
                // A message of our session whose key is gone (it
                // arrived after the key was evicted) can never be
                // read: name it to the contact, who then stops
                // sending it (R-21). Only the contact can read the
                // GONE message, and it changes nothing for an id the
                // contact has not pending, so a forged message that
                // only looks late gains nothing, and draws at most
                // one GONE per session per round. A failed check is
                // reported and must not abort the round.
                if !first {
                    match self.core.beyond_recall(handle, wire) {
                        Ok(true) => self
                            .gone
                            .lock()
                            .expect("gone")
                            .entry(handle)
                            .or_default()
                            .push(message_id(wire)),
                        Ok(false) => {}
                        Err(e) => report
                            .errors
                            .push(format!("checking whether a message is beyond recall: {e}")),
                    }
                }
                report.dropped += 1;
                Ok(Fate::Delete)
            }
            // The recorded handshake can no longer be answered: the
            // prekeys it names rotated or were consumed since.
            Err(
                e @ (CoreError::StaleSignedPrekey
                | CoreError::OneTimePrekeyUnavailable { .. }
                | CoreError::OneTimePrekeyRequired),
            ) => {
                chat::set_flag(self, &sender, chat::HANDSHAKE_REFUSED)?;
                report.dropped += 1;
                report.errors.push(format!("handshake refused: {e}"));
                Ok(Fate::Delete)
            }
            Err(CoreError::SessionUnresolved { .. }) => {
                self.core.recover_session(handle)?;
                Ok(Fate::Keep)
            }
            Err(e) => {
                report.errors.push(e.to_string());
                Ok(Fate::Keep)
            }
        }
    }

    /// Whether our session under `handle` is an unconfirmed start of our
    /// own: this device initiated it and no message from the peer has
    /// authenticated under it yet.
    fn own_unconfirmed(&self, handle: u64) -> Result<bool, CoreError> {
        Ok(self.core.initiator_handshake(handle)?.is_some() && !self.confirmed(handle)?)
    }

    /// Records `handshake` from the pinned contact `peer` beside our own
    /// unconfirmed session with it (docs/S2-B2-DURABLE-MESSAGING.md,
    /// section 4c). Nothing else changes and no flag is set: the record has
    /// no authority, and a later handshake replaces it.
    ///
    /// A handshake this device can never answer (the prekeys it names were
    /// consumed or rotated) is refused as a responder refuses one (section
    /// 6): the refusal is sent, so a genuine initiator gives that session up
    /// and starts again from the current bundle. Without it, a simultaneous
    /// start in which the contact's handshake cannot be answered here would
    /// never show a conflict on this device, and with this device's key the
    /// greater nobody could resolve it. A refusal changes nothing at a peer
    /// whose current handshake it does not name, so one elicited by a forged
    /// handshake is dropped there. The `HANDSHAKE_REFUSED` flag is not set:
    /// `sync_conversations` clears it whenever a session exists.
    fn record_beside(
        &self,
        peer: [u8; 32],
        handshake: &[u8],
        handle: u64,
        report: &mut SyncReport,
    ) -> Result<Fate, CoreError> {
        match self.core.record_handshake_beside(handle, handshake) {
            Ok(()) => {
                crash_point("beside_after_record");
                Ok(Fate::Delete)
            }
            Err(e) if transient(&e) => {
                report.errors.push(e.to_string());
                Ok(Fate::Keep)
            }
            Err(e) => {
                if let Some(reason) = RefusalReason::of(&e) {
                    self.queue_refusal(peer, handshake, reason)?;
                }
                report.dropped += 1;
                report.errors.push(format!("handshake refused: {e}"));
                Ok(Fate::Delete)
            }
        }
    }

    /// Records `handshake` from the pinned contact `peer` beside our
    /// established session with it, as a possible restart of the session by
    /// the contact (option B; `docs/S2-B2-DURABLE-MESSAGING.md` section 4c).
    /// Nothing else changes: the record has no authority, and a later
    /// handshake replaces it.
    ///
    /// A handshake this device cannot answer is refused as beside our own
    /// session (`record_beside`), so a contact whose restart names a
    /// one-time prekey that changed since (another contact's first message
    /// consumed it, or a confirmation of our own session replaced it) gives
    /// that restart up and makes it again from the current bundle. Without
    /// the refusal it would wait for good. Never refused: a late
    /// retransmission of the handshake our responder session came from
    /// (`ArciumCore::is_accepted_handshake`, which also knows it in another
    /// encoding a relay put in its place), whose one-time prekey we consumed
    /// when we accepted it. The contact retransmits it until our receipt
    /// arrives, and a refusal naming it would end the session the contact
    /// has just made. A responder session stored by an older build has no
    /// such record: then the handshake is refused, which ends the contact's
    /// session only if our receipt has not reached it yet. No error is
    /// reported: nothing here needs this user.
    fn record_restart(
        &self,
        peer: [u8; 32],
        handshake: &[u8],
        handle: u64,
        report: &mut SyncReport,
    ) -> Result<Fate, CoreError> {
        match self.core.record_handshake_beside(handle, handshake) {
            Ok(()) => {
                crash_point("restart_after_record");
                Ok(Fate::Delete)
            }
            Err(e) if transient(&e) => {
                report.errors.push(e.to_string());
                Ok(Fate::Keep)
            }
            Err(e) => {
                if !self.core.is_accepted_handshake(&peer, handshake)? {
                    if let Some(reason) = RefusalReason::of(&e) {
                        self.queue_refusal(peer, handshake, reason)?;
                    }
                }
                report.dropped += 1;
                Ok(Fate::Delete)
            }
        }
    }

    /// Test aid: the minute [`Self::this_minute`] reads (`None`: the clock).
    #[cfg(test)]
    pub(crate) fn set_minute(&self, minute: Option<u64>) {
        *self.minute.lock().expect("minute") = minute;
    }

    /// Test aid: the second [`Self::this_second`] reads (`None`: the clock).
    #[cfg(test)]
    pub(crate) fn set_now(&self, now: Option<u64>) {
        *self.now.lock().expect("now") = now;
    }

    /// Test aid: how many far skips this instance tried (R-14).
    #[cfg(test)]
    pub(crate) fn far_tries(&self) -> u32 {
        self.far_tries.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Test aid: how many messages found beyond recall wait to be named.
    #[cfg(test)]
    pub(crate) fn gone_len(&self) -> usize {
        self.gone.lock().expect("gone").values().map(Vec::len).sum()
    }

    /// Test aid: the keys `last_sent` holds.
    #[cfg(test)]
    pub(crate) fn sent_keys(&self) -> Vec<[u8; 32]> {
        self.last_sent.lock().expect("last_sent").keys().copied().collect()
    }

    /// Test aid: the least time between two refusals to one contact
    /// ([`REFUSAL_INTERVAL`] otherwise).
    #[cfg(test)]
    pub(crate) fn set_refusal_interval(&self, interval: Duration) {
        self.refusals.lock().expect("refusals").interval = interval;
    }

    /// Makes a refusal of `handshake` for `peer` and queues it, unless one
    /// is queued for this handshake or peer already, or one was sent to this
    /// peer less than [`REFUSAL_INTERVAL`] ago. A retransmitted handshake
    /// refused before is refused again once the interval has passed.
    fn queue_refusal(
        &self,
        peer: [u8; 32],
        handshake: &[u8],
        reason: RefusalReason,
    ) -> Result<(), CoreError> {
        let hash = handshake_hash(handshake);
        {
            let r = self.refusals.lock().expect("refusals");
            let recent = r
                .last_to
                .get(&peer)
                .is_some_and(|t| t.elapsed() < r.interval);
            if recent || r.queued.iter().any(|(to, _, h)| *to == peer || *h == hash) {
                return Ok(());
            }
        }
        let Some(body) = self.core.make_handshake_refusal(peer, handshake, reason)? else {
            return Ok(());
        };
        self.refusals
            .lock()
            .expect("refusals")
            .queued
            .push((peer, body, hash));
        Ok(())
    }

    /// Sends the queued refusals. A refusal stays queued, for the next round,
    /// when the relay refuses to store it (the initiator's mailbox is full),
    /// while the initiator waits after such a refusal (`held`), and when the
    /// connection fails, and once the round's budget is spent; it leaves the
    /// queue only once the relay stored it. A relay refusal does not end the
    /// round (as in `publish_pending`); a failed connection does, as every
    /// network error does, with nothing lost.
    fn send_refusals(
        &self,
        conn: &mut Connection,
        budget: &Budget,
        relay_refusals: &mut RelayRefusals,
        report: &mut SyncReport,
    ) -> Result<(), CoreError> {
        if self.refusals.lock().expect("refusals").queued.is_empty() {
            return Ok(());
        }
        // Read before the queue is taken: a failure here leaves it in place.
        let our = self.core.our_identity_pk()?;
        let queued = std::mem::take(&mut self.refusals.lock().expect("refusals").queued);
        let mut queued = queued.into_iter();
        let mut keep = Vec::new();
        let mut failed = None;
        for (peer, refusal, hash) in queued.by_ref() {
            if !budget.left() {
                // Out of time: the rest goes out next round.
                keep.push((peer, refusal, hash));
                break;
            }
            if relay_refusals.recipients.contains(&peer) || self.held(&peer) {
                keep.push((peer, refusal, hash));
                continue;
            }
            let env = Envelope::Refusal {
                sender: our,
                refusal: refusal.clone(),
            };
            match self.send_to(conn, peer, env.encode(), relay_refusals) {
                Ok(true) => {
                    let mut r = self.refusals.lock().expect("refusals");
                    r.last_to.insert(peer, Instant::now());
                    report.published += 1;
                }
                Ok(false) => keep.push((peer, refusal, hash)),
                Err(e) => {
                    keep.push((peer, refusal, hash));
                    failed = Some(e);
                    break;
                }
            }
        }
        keep.extend(queued);
        // Ahead of anything queued meanwhile, in their order.
        let mut r = self.refusals.lock().expect("refusals");
        keep.append(&mut r.queued);
        r.queued = keep;
        drop(r);
        failed.map_or(Ok(()), Err)
    }

    /// Acts on a refusal from the pinned contact `peer`. It counts only if
    /// its tag checks for the contact's pinned identity key and ours, it
    /// names those two keys, and it names the handshake of our own session with the
    /// contact, which nothing confirmed yet. Then that session can never
    /// be accepted: it is given up and a new one started. Anything else is
    /// dropped and changes nothing.
    fn take_refusal(
        &self,
        peer: &[u8; 32],
        card: &Card,
        refusal: &[u8],
        report: &mut SyncReport,
    ) -> Result<(), CoreError> {
        let handle = handle_of(peer);
        let opened = if card.dh_pk == *peer {
            self.core.open_handshake_refusal(refusal, peer)?
        } else {
            None
        };
        let valid = match opened {
            Some(r) => {
                self.core.has_session(handle)?
                    && !self.confirmed(handle)?
                    && self
                        .core
                        .initiator_handshake(handle)?
                        .is_some_and(|hs| handshake_hash(&hs) == r.handshake_hash)
            }
            _ => false,
        };
        if !valid {
            report.dropped += 1;
            return Ok(());
        }
        chat::restart_after_refusal(self, peer, report)
    }

    /// Applies every accepted message still in the inbox that the network
    /// layer, not the application, consumes.
    fn settle_inbox(&self, handle: u64, report: &mut SyncReport) -> Result<(), CoreError> {
        for m in self.core.pending_committed(handle)? {
            self.settle(handle, &m.message_id, &m.plaintext, report)?;
        }
        Ok(())
    }

    /// Texts from `peer` accepted and not yet marked read, in order, each in
    /// a wiping owner. What [`received_texts`](Self::received_texts) returns
    /// to the application, before the copy that leaves Rust ownership.
    pub(crate) fn pending_texts(&self, peer: &[u8; 32]) -> Result<Vec<PendingText>, CoreError> {
        let mut texts = Vec::new();
        for m in self.core.pending_committed(handle_of(peer))? {
            if let Some(Payload::Text(text)) = Payload::decode(&m.plaintext) {
                texts.push((m.message_id, text));
            }
        }
        Ok(texts)
    }

    /// Acts on one accepted message. Idempotent: it runs again for anything
    /// still in the inbox after a crash.
    fn settle(
        &self,
        handle: u64,
        id: &[u8],
        plaintext: &[u8],
        report: &mut SyncReport,
    ) -> Result<(), CoreError> {
        let id32: [u8; 32] = id.try_into().expect("32-byte id");
        match Payload::decode(plaintext) {
            // Stays in the inbox for the application; the receipt is
            // committed now, so it survives a crash before it is sent.
            Some(Payload::Text(_)) => self.receipt(handle, &id32, 0).map(|_| ()),
            Some(Payload::Open) => {
                self.receipt(handle, &id32, 0)?;
                self.core
                    .acknowledge_incoming(handle, id.to_vec())
                    .map(|_| ())
            }
            Some(Payload::Receipt(ids)) => {
                for acked in ids {
                    if self.core.acknowledge_outgoing(handle, acked.to_vec())? {
                        report.delivered += 1;
                    }
                }
                self.core
                    .acknowledge_incoming(handle, id.to_vec())
                    .map(|_| ())
            }
            // The contact cannot read these: a text of ours still pending
            // among them is abandoned, so it is not sent again and shows
            // NotDelivered (R-21). Any other id is ignored.
            Some(Payload::Gone(ids)) => {
                let texts: Vec<Vec<u8>> = self
                    .core
                    .pending_outgoing(handle)?
                    .into_iter()
                    .filter(|m| m.client_message_id.first() == Some(&client_id::TEXT))
                    .map(|m| m.message_id)
                    .collect();
                for gone in ids {
                    if texts.iter().any(|t| t[..] == gone[..]) {
                        self.core.abandon_outgoing(handle, gone.to_vec())?;
                    }
                }
                self.core
                    .acknowledge_incoming(handle, id.to_vec())
                    .map(|_| ())
            }
            None => {
                report.dropped += 1;
                report.errors.push("unknown payload type discarded".into());
                self.core
                    .acknowledge_incoming(handle, id.to_vec())
                    .map(|_| ())
            }
        }
    }

    /// Whether `wire`, which did not decrypt under the session `handle`, is
    /// kept for a far skip at the end of the message pass (`far_pass`;
    /// tracker R-14). It must need one: lie more than `MAX_SKIP` positions
    /// ahead in its chain, so more than a thousand of the contact's messages
    /// in a row are missing. A far skip drops the keys of all but the last
    /// thousand positions it skips, so their texts can no longer be read; it
    /// is kept for a gap nothing fills. So the session must have seen far
    /// messages for [`FAR_SKIP_WAIT`] without accepting a message: by then
    /// the sender has sent again whatever it still holds. A far skip may
    /// also derive up to `MAX_FAR_SKIP` keys per chain before the message
    /// authenticates, so a session keeps one and a round at most
    /// [`FAR_TRIES_PER_ROUND`]. A message not kept is deleted like any
    /// message that does not decrypt, so whoever writes forged far messages
    /// to the mailbox learns nothing from what stays there (R-9). A text is
    /// sent again, and a receipt or GONE message when the text it answers
    /// is. A failed check is reported.
    fn far_candidate(&self, handle: u64, wire: &[u8], report: &mut SyncReport) -> bool {
        match self.core.needs_far_skip(handle, wire) {
            Ok(true) => {}
            Ok(false) => return false,
            Err(e) => {
                report
                    .errors
                    .push(format!("checking how far ahead a message lies: {e}"));
                return false;
            }
        }
        let Some(chain) = wire.get(..32).and_then(|b| <[u8; 32]>::try_from(b).ok()) else {
            return false;
        };
        let mut round = self.far_round.lock().expect("far_round");
        if round.judged.contains(&handle) || round.candidates.iter().any(|(h, _)| *h == handle) {
            return false;
        }
        let now = self.this_millis();
        let since = {
            let mut seen = self.far_seen.lock().expect("far_seen");
            if !seen.contains_key(&handle) {
                // A wait that cannot be read tries no far skip this round.
                let Some(stored) = self.stored_far_waits(handle, report) else {
                    round.judged.insert(handle);
                    return false;
                };
                seen.insert(handle, stored);
            }
            let waits = seen.get_mut(&handle).expect("inserted above");
            let (since, changed) = note_far_sighting(waits, chain, now);
            if changed && self.store_far_waits(handle, waits, report) {
                for w in waits.iter_mut() {
                    w.stored_last = w.last;
                }
            }
            since
        };
        let wait = u64::try_from(self.limits().far_skip_wait.as_millis()).unwrap_or(u64::MAX);
        if now.saturating_sub(since) < wait || round.candidates.len() >= FAR_TRIES_PER_ROUND {
            round.judged.insert(handle);
            return false;
        }
        round.candidates.push((handle, wire.to_vec()));
        true
    }

    /// Forgets the far-skip waits of the session `handle` (R-14): it
    /// accepted a message, or it is gone and a new session with the contact
    /// will have the same handle. The stored record is deleted unless this
    /// process knows it holds no wait, so an accepted message costs no
    /// write once that is known. A failed delete is not reported: the
    /// session is then read from the store again, and the next accepted
    /// message tries the delete again; until then a far message of a chain
    /// the record names may be tried without the full wait
    /// (docs/NET-MESSAGING.md section 3).
    pub(crate) fn forget_far_waits(&self, handle: u64) {
        let mut seen = self.far_seen.lock().expect("far_seen");
        if seen.get(&handle).is_some_and(Vec::is_empty) {
            return;
        }
        let deleted = match self.core.store.lock() {
            Ok(store) => matches!(store.delete(&far_wait_key(handle)), Ok(()) | Err(StorageError::NotFound)),
            Err(_) => false,
        };
        if deleted {
            seen.insert(handle, Vec::new());
        } else {
            seen.remove(&handle);
        }
    }

    /// The far-skip waits of the session `handle` kept in the store: none if
    /// there is no record or a damaged one (it is replaced at the next
    /// write). `None` if the store could not be read, which is reported:
    /// the record may hold a wait, and a later write would replace it.
    fn stored_far_waits(&self, handle: u64, report: &mut SyncReport) -> Option<FarWaits> {
        let stored = match self.core.store.lock() {
            Ok(store) => store.get(&far_wait_key(handle)),
            Err(_) => return None,
        };
        match stored {
            Ok(bytes) => Some(unpack_far_waits(&bytes).unwrap_or_default()),
            Err(StorageError::NotFound | StorageError::Decryption) => Some(Vec::new()),
            Err(e) => {
                report.errors.push(format!("reading the wait before a far skip: {e}"));
                None
            }
        }
    }

    /// The far-skip record of the session `handle` was deleted with its
    /// contact (`delete_contact`), in the same transaction: no chain of it
    /// waits.
    pub(crate) fn far_waits_deleted(&self, handle: u64) {
        self.far_seen.lock().expect("far_seen").insert(handle, Vec::new());
    }

    /// Stores the far-skip waits of the session `handle`; whether it did.
    /// A failure is reported: the wait then goes on in memory, and starts
    /// again after a restart.
    fn store_far_waits(&self, handle: u64, waits: &[FarWait], report: &mut SyncReport) -> bool {
        let result = match self.core.store.lock() {
            Ok(store) => store.put(&far_wait_key(handle), &pack_far_waits(waits)),
            Err(_) => return false,
        };
        match result {
            Ok(()) => true,
            Err(e) => {
                report.errors.push(format!("storing the wait before a far skip: {e}"));
                false
            }
        }
    }

    /// Test aid: how many chains of the session `handle` wait for a far skip.
    #[cfg(test)]
    pub(crate) fn far_waits(&self, handle: u64) -> usize {
        self.far_seen
            .lock()
            .expect("far_seen")
            .get(&handle)
            .map_or(0, Vec::len)
    }

    /// The session `handle` accepted a message: the wait before a far skip
    /// starts again, and it tries none this round (R-14).
    fn far_progress(&self, handle: u64) {
        self.forget_far_waits(handle);
        self.far_round
            .lock()
            .expect("far_round")
            .progressed
            .insert(handle);
    }

    /// Tries the far skips the message pass kept (R-14), each for a session
    /// that accepted no message in the pass: one that did may be filling
    /// its gap, and the message comes again. The messages were deleted from
    /// the relay in the pass, so one not read here (a session that moved
    /// on, a failure) is counted dropped and is read only when it comes
    /// again; so is one lost to a crash or to a round that failed before
    /// this, though uncounted. A failure to settle one that was read is
    /// reported; the next round settles it from the inbox.
    fn far_pass(&self, report: &mut SyncReport) {
        let (candidates, progressed) = {
            let mut round = self.far_round.lock().expect("far_round");
            (std::mem::take(&mut round.candidates), round.progressed.clone())
        };
        for (handle, wire) in candidates {
            if progressed.contains(&handle) {
                report.dropped += 1;
                continue;
            }
            #[cfg(test)]
            self.far_tries
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            #[cfg(test)]
            far_hook::run(far_hook::Stage::BeforeTry, handle);
            match self.core.receive_committed_far(handle, &wire) {
                Ok(Received::Accepted(message)) => {
                    report.accepted += 1;
                    self.far_progress(handle);
                    crash_point("after_accept");
                    #[cfg(test)]
                    far_hook::run(far_hook::Stage::BeforeSettle, handle);
                    if let Err(e) = self.settle(handle, &message.message_id, &message.plaintext, report) {
                        report
                            .errors
                            .push(format!("settling a message read with a far skip: {e}"));
                    }
                    crash_point("after_settle");
                }
                // Not reached: a duplicate is found before any decryption.
                Ok(Received::Duplicate { .. }) => report.duplicates += 1,
                Err(CoreError::Crypto { .. }) => report.dropped += 1,
                Err(e) => {
                    report.dropped += 1;
                    report
                        .errors
                        .push(format!("reading a message far ahead in its chain: {e}"));
                }
            }
        }
    }

    /// Commits at most one GONE message per session for the messages this
    /// round found beyond recall (R-21), naming the first
    /// [`wire::MAX_RECEIPT_IDS`] of them in id order. The others are found
    /// again when the contact sends them again; and forged messages that only
    /// look late draw no more than one GONE per session per round. A GONE
    /// leaves the outbox once the relay accepted it, so the contact sending
    /// a named message again may never have got it: as for a receipt
    /// ([`Self::receipt_again`]), a later GONE for the same ids is committed,
    /// at most one per minute. A failure is reported and leaves the round
    /// going: the contact sends those messages again, and they are found
    /// again.
    fn commit_gone(&self, report: &mut SyncReport) {
        let found = std::mem::take(&mut *self.gone.lock().expect("gone"));
        for (handle, mut ids) in found {
            ids.sort_unstable();
            ids.dedup();
            ids.truncate(wire::MAX_RECEIPT_IDS);
            if let Err(e) = self.name_gone(handle, &ids) {
                report.errors.push(format!("naming messages beyond recall: {e}"));
            }
        }
    }

    fn name_gone(&self, handle: u64, ids: &[[u8; 32]]) -> Result<(), CoreError> {
        let payload = Payload::Gone(ids.to_vec()).encode();
        if let SendResult::AlreadyAcknowledged { .. } =
            self.core.send_committed(handle, &client_id::gone(ids, 0), &payload)?
        {
            self.core
                .send_committed(handle, &client_id::gone(ids, self.this_minute() + 1), &payload)?;
        }
        Ok(())
    }

    fn receipt(&self, handle: u64, id: &[u8; 32], round: u64) -> Result<SendResult, CoreError> {
        self.core.send_committed(
            handle,
            &client_id::receipt(id, round),
            &Payload::Receipt(vec![*id]).encode(),
        )
    }

    /// The peer sent `id` again, so it may not have our receipt. If the
    /// original receipt already left the outbox, commit a new one, at most one
    /// per minute per message.
    ///
    /// Only a message that was answered when it was accepted is answered
    /// again: a text or an OPEN, whose receipt `settle` committed under
    /// `client_id::receipt(id, 0)`. A receipt, or a payload this build does
    /// not know, was never answered, so its duplicate is not either: a
    /// replayed receipt changes nothing (docs/NET-MESSAGING.md, section 5).
    /// Send-id records are never deleted, so the check holds for messages
    /// accepted long ago.
    fn receipt_again(&self, handle: u64, peer: &[u8; 32], id: &[u8]) -> Result<(), CoreError> {
        let id32: [u8; 32] = id.try_into().expect("32-byte id");
        if self.core.prior_send(peer, &client_id::receipt(&id32, 0))?.is_none() {
            return Ok(());
        }
        if let SendResult::AlreadyAcknowledged { .. } = self.receipt(handle, &id32, 0)? {
            self.receipt(handle, &id32, self.this_minute() + 1)?;
        }
        Ok(())
    }

    /// Minutes since the Unix epoch: the round of a receipt or GONE sent
    /// again, so each is sent again at most once a minute.
    fn this_minute(&self) -> u64 {
        #[cfg(test)]
        if let Some(minute) = *self.minute.lock().expect("minute") {
            return minute;
        }
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() / 60)
            .unwrap_or(0)
    }

    /// Milliseconds since the Unix epoch, 0 before it: the far-skip waits
    /// (tracker R-14), which go on across a restart. Not monotonic: a clock
    /// set forward shortens a wait, one set back before a chain's first
    /// sighting starts it again (docs/NET-MESSAGING.md section 8).
    fn this_millis(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }

    /// Seconds since the Unix epoch, 0 before it: the age of the signed
    /// prekey (`ArciumCore::maintain_prekeys`). Not monotonic: a rotation
    /// is due when this clock reads a period or more from the key's
    /// publication, in either direction (docs/NET-MESSAGING.md section 8,
    /// "Clocks").
    fn this_second(&self) -> u64 {
        #[cfg(test)]
        if let Some(now) = *self.now.lock().expect("now") {
            return now;
        }
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Test aid: aborts the process (no unwinding, no destructors) when
/// `ARCIUM_NET_CRASH_AT` names `point`. Compiled into tests only.
fn crash_point(_point: &str) {
    #[cfg(test)]
    if std::env::var("ARCIUM_NET_CRASH_AT").as_deref() == Ok(_point) {
        std::process::abort();
    }
}

/// Errors after which the same input may succeed later.
fn transient(e: &CoreError) -> bool {
    matches!(
        e,
        CoreError::Storage { .. }
            | CoreError::SessionConflict { .. }
            | CoreError::CommitOutcomeUnknown { .. }
            | CoreError::RepeatableOutcomeUnknown { .. }
            | CoreError::SessionUnresolved { .. }
    )
}

/// Lets a test act on the relay between the pages of a scan: after each
/// FETCH_AFTER, before its envelopes are processed.
#[cfg(test)]
pub(crate) mod scan_hook {
    use super::Pass;
    use std::cell::RefCell;

    type Hook = Box<dyn FnMut(Pass, usize)>;

    thread_local! {
        static HOOK: RefCell<Option<Hook>> = RefCell::new(None);
    }

    pub(crate) fn set(f: impl FnMut(Pass, usize) + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    pub(crate) fn clear() {
        HOOK.with(|h| *h.borrow_mut() = None);
    }

    pub(super) fn run(pass: Pass, page: usize) {
        HOOK.with(|h| {
            if let Some(f) = h.borrow_mut().as_mut() {
                f(pass, page);
            }
        });
    }
}

/// Lets a test act in the far pass (R-14): before each far try, and after a
/// message read with one was accepted, before it is settled.
#[cfg(test)]
pub(crate) mod far_hook {
    use std::cell::RefCell;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Stage {
        BeforeTry,
        BeforeSettle,
    }

    type Hook = Box<dyn FnMut(Stage, u64)>;

    thread_local! {
        static HOOK: RefCell<Option<Hook>> = RefCell::new(None);
    }

    pub(crate) fn set(f: impl FnMut(Stage, u64) + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    pub(crate) fn clear() {
        HOOK.with(|h| *h.borrow_mut() = None);
    }

    pub(super) fn run(stage: Stage, handle: u64) {
        HOOK.with(|h| {
            if let Some(f) = h.borrow_mut().as_mut() {
                f(stage, handle);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wait(k: u8, first: u64, last: u64) -> FarWait {
        FarWait {
            chain: [k; 32],
            first,
            last,
            stored_last: last,
        }
    }

    /// What the caller does once `waits` is stored.
    fn stored(waits: &mut FarWaits) {
        for w in waits.iter_mut() {
            w.stored_last = w.last;
        }
    }

    #[test]
    fn a_far_wait_record_reads_back_what_was_written() {
        for n in 0..=FAR_CHAINS_PER_SESSION {
            let waits: FarWaits = (0..n)
                .map(|i| {
                    let i = u8::try_from(i).unwrap();
                    wait(i + 1, 1_000 * u64::from(i), u64::MAX - u64::from(i))
                })
                .collect();
            let bytes = pack_far_waits(&waits);
            assert_eq!(bytes.len(), 2 + FAR_WAIT_ENTRY_LEN * n);
            assert_eq!(&bytes[..2], &[1, u8::try_from(n).unwrap()]);
            assert_eq!(unpack_far_waits(&bytes), Some(waits), "{n} chains");
        }
        // Big-endian, chain first.
        let bytes = pack_far_waits(&[wait(7, 0x0102, 0x0304)]);
        assert_eq!(&bytes[2..34], &[7; 32]);
        assert_eq!(&bytes[34..42], &0x0102u64.to_be_bytes());
        assert_eq!(&bytes[42..50], &0x0304u64.to_be_bytes());
    }

    #[test]
    fn a_damaged_far_wait_record_is_read_as_no_wait() {
        let good = pack_far_waits(&[wait(1, 5, 6), wait(2, 7, 8)]);
        assert!(unpack_far_waits(&good).is_some());
        let mut other_version = good.clone();
        other_version[0] = 2;
        let mut more_than_held = pack_far_waits(&vec![wait(1, 1, 1); FAR_CHAINS_PER_SESSION + 1]);
        // Distinct chains, so only the count is wrong.
        for (i, e) in more_than_held[2..].chunks_exact_mut(FAR_WAIT_ENTRY_LEN).enumerate() {
            e[0] = u8::try_from(i).unwrap();
        }
        let mut count_too_high = good.clone();
        count_too_high[1] = 3;
        let repeated = pack_far_waits(&[wait(1, 5, 6), wait(1, 7, 8)]);
        for bad in [
            Vec::new(),
            vec![1],
            other_version,
            more_than_held,
            count_too_high,
            good[..good.len() - 1].to_vec(),
            [&good[..], &[0]].concat(),
            repeated,
        ] {
            assert_eq!(unpack_far_waits(&bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_new_chain_starts_waiting_and_is_stored() {
        let mut waits = FarWaits::new();
        assert_eq!(note_far_sighting(&mut waits, [1; 32], 1_000), (1_000, true));
        assert_eq!(waits, vec![wait(1, 1_000, 1_000)]);
    }

    #[test]
    fn a_chain_seen_again_keeps_its_first_sighting_and_stores_its_last_once_a_minute() {
        let mut waits = vec![wait(1, 1_000, 1_000)];
        let step = FAR_WAIT_LAST_STEP_MS;
        assert_eq!(note_far_sighting(&mut waits, [1; 32], 1_000 + step - 1), (1_000, false));
        assert_eq!(waits[0].last, 1_000 + step - 1, "exact in memory");
        assert_eq!(note_far_sighting(&mut waits, [1; 32], 1_000 + step), (1_000, true));
        stored(&mut waits);
        assert_eq!(note_far_sighting(&mut waits, [1; 32], 1_000 + 2 * step - 1), (1_000, false));
        assert_eq!(note_far_sighting(&mut waits, [1; 32], 1_000 + 2 * step), (1_000, true));
        // An earlier reading after the first sighting moves nothing back.
        stored(&mut waits);
        assert_eq!(note_far_sighting(&mut waits, [1; 32], 2_000), (1_000, false));
        assert_eq!(waits, vec![wait(1, 1_000, 1_000 + 2 * step)]);
    }

    #[test]
    fn a_clock_set_back_before_the_first_sighting_starts_the_wait_again() {
        let mut waits = vec![wait(1, 50_000, 90_000), wait(2, 10_000, 20_000)];
        assert_eq!(note_far_sighting(&mut waits, [1; 32], 40_000), (40_000, true));
        assert_eq!((waits[0].first, waits[0].last), (40_000, 40_000));
        assert_eq!(waits[1], wait(2, 10_000, 20_000), "other chains untouched");
    }

    #[test]
    fn a_new_chain_drops_the_one_seen_least_recently() {
        let mut waits: FarWaits = (1..=4u8).map(|k| wait(k, 0, 100 * u64::from(k))).collect();
        waits[0].last = 900; // chain 1 seen most recently, chain 2 least
        assert_eq!(note_far_sighting(&mut waits, [9; 32], 1_000), (1_000, true));
        let chains: Vec<u8> = waits.iter().map(|w| w.chain[0]).collect();
        assert_eq!(chains, vec![1, 3, 4, 9]);
    }

    /// The order of dropping follows the exact last sighting, not the one
    /// stored a minute ago.
    #[test]
    fn dropping_follows_the_last_sighting_in_memory() {
        let mut waits: FarWaits = (1..=4u8).map(|k| wait(k, 0, 10 + u64::from(k))).collect();
        // Chain 1 is seen again within the minute: not stored, but later
        // than the others.
        assert_eq!(note_far_sighting(&mut waits, [1; 32], 100), (0, false));
        note_far_sighting(&mut waits, [9; 32], 200);
        let chains: Vec<u8> = waits.iter().map(|w| w.chain[0]).collect();
        assert_eq!(chains, vec![1, 3, 4, 9]);
    }
}
