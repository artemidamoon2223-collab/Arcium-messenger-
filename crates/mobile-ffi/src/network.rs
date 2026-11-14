//! End-to-end encrypted messaging over an untrusted relay.
//! Specification: `docs/NET-MESSAGING.md`.
//!
//! [`NetworkMessenger`] moves what the durable layer (S2-B2) already committed:
//! it publishes stored bytes and feeds received bytes to it, and never
//! encrypts or decrypts on its own. So a retry, a crash or a lost connection
//! can repeat a transmission but never produce a second ciphertext for a
//! logical message or a second acceptance of one.
//!
//! Delivery is decided end to end. A text leaves the outbox only when the
//! recipient's receipt arrives inside the ratchet, naming its exact message id;
//! the relay accepting it proves nothing. Receipts themselves are not
//! acknowledged: they leave the outbox once the relay has accepted them, and
//! if one is lost the sender retransmits the text, which is received as a
//! duplicate and answered with a new receipt.

pub(crate) mod chat;
pub(crate) mod wire;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use core_storage::StorageError;
use relay::client::{ClientError, Connection};
use relay::protocol::{ErrorCode, DEFAULT_MAX_MAILBOX, MAX_FETCH, MIN_PAGE};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::contacts::{pinned, Card};
use core_protocol::messaging::{MessageId, Received};

use crate::{
    handshake_hash, unpack_prekey_bundle, ArciumCore, CoreError, PlaintextBytes,
    RefusalReason, SendResult, PREKEYS_KEY,
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

#[derive(uniffi::Object)]
pub struct NetworkMessenger {
    core: Arc<ArciumCore>,
    relay: String,
    timeout: Duration,
    retransmit_after: Duration,
    /// When each message or handshake was last accepted by the relay, and
    /// how often it was. In memory only: after a restart everything pending
    /// is sent once more, and the backoff starts again.
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
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            request_deadline: relay::client::REQUEST_DEADLINE,
            round_budget: ROUND_BUDGET,
            retransmit_cap: RETRANSMIT_CAP,
        }
    }
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
    /// `relay_address` is `host:port`. A pending message or handshake is sent
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
            relay: relay_address,
            timeout: Duration::from_millis(timeout_ms),
            retransmit_after: Duration::from_millis(retransmit_after_ms),
            last_sent: Mutex::new(HashMap::new()),
            refused: Mutex::new(HashMap::new()),
            refusals: Mutex::new(Refusals::default()),
            limits: Mutex::new(Limits::default()),
            resume: Mutex::new(Resume::default()),
        })
    }

    /// Publishes this device's prekey bundle, creating prekeys first if none
    /// exist yet. Existing prekeys are never replaced here.
    pub fn publish_prekeys(&self) -> Result<(), CoreError> {
        let mut conn = self.connect()?;
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

    fn connect(&self) -> Result<Connection, CoreError> {
        let mut conn = Connection::connect(&self.relay, self.timeout).map_err(network)?;
        conn.set_request_deadline(self.limits().request_deadline);
        Ok(conn)
    }

    fn limits(&self) -> Limits {
        *self.limits.lock().expect("limits")
    }

    /// Test aid: the bounds of `docs/NET-MESSAGING.md` section 7, scaled.
    #[cfg(test)]
    pub(crate) fn set_limits(&self, request_deadline: Duration, round_budget: Duration, retransmit_cap: Duration) {
        *self.limits.lock().expect("limits") = Limits {
            request_deadline,
            round_budget,
            retransmit_cap,
        };
    }

    fn require_contact(&self, peer: &[u8; 32]) -> Result<Card, CoreError> {
        let store = self.core.store.lock().map_err(|_| CoreError::Storage {
            msg: "mutex poisoned".into(),
        })?;
        pinned(&store, peer)?.ok_or(CoreError::UnknownContact)
    }

    fn put_bundle(&self, conn: &mut Connection) -> Result<(), CoreError> {
        let exists = {
            let store = self.core.store.lock().map_err(|_| CoreError::Storage {
                msg: "mutex poisoned".into(),
            })?;
            match store.get(PREKEYS_KEY) {
                Ok(_) => true,
                Err(StorageError::NotFound) => false,
                Err(e) => return Err(e.into()),
            }
        };
        if !exists {
            self.core.establish_prekeys()?;
        }
        let bundle = self.core.export_prekey_bundle()?;
        conn.put_bundle(self.core.our_identity_pk()?, bundle)
            .map_err(network)
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
        let mut conn = self.connect()?;
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
        self.send_refusals(&mut conn, &budget, relay_refusals, report)?;
        // Receipts produced above, and the first messages of new sessions.
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

    /// Whether the relay accepted the message `id` in this process's lifetime.
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
    /// refused (a full mailbox). It read the request and answered, so the
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
                if m.client_message_id.first() == Some(&client_id::RECEIPT) {
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
                    // Dropped: no session is ever replaced. If ours is an
                    // unconfirmed start of our own, both sides initiated;
                    // record it so the application can show it (section 8).
                    // (A handshake only recorded here is not a session and
                    // does not reach this branch: it may be replaced.)
                    if self.core.initiator_handshake(handle)?.is_some()
                        && !self.confirmed(handle)?
                    {
                        chat::set_flag(self, &sender, chat::CONFLICT)?;
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
            Envelope::Message { wire, .. } => {
                // Without a session, the message is either the first one of a
                // recorded handshake — which creates the session if it
                // authenticates — or waits for its handshake (`NoSession`).
                let first = !self.core.has_session(handle)?;
                match self.core.receive_committed(handle, &wire) {
                    Ok(Received::Accepted(message)) => {
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
        }
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
            None => {
                report.dropped += 1;
                report.errors.push("unknown payload type discarded".into());
                self.core
                    .acknowledge_incoming(handle, id.to_vec())
                    .map(|_| ())
            }
        }
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
            let minute = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() / 60)
                .unwrap_or(0);
            self.receipt(handle, &id32, minute + 1)?;
        }
        Ok(())
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
