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
mod far_skip;
mod inbox;
mod mailbox;
mod outbox;
mod refusals;

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet, VecDeque};
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
use core_protocol::messaging::{message_id, MessageId, Recall, Received};

use crate::{
    handshake_hash, unpack_prekey_bundle, ArciumCore, CoreError, PlaintextBytes,
    RefusalReason, SendResult,
};
use wire::{client_id, Envelope, Payload};
pub(crate) use far_skip::*;
use mailbox::*;
use refusals::*;

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
    /// Per session, messages of a chain it no longer knows that arrived,
    /// least recently seen first, at most [`FORGOTTEN_SEEN_PER_SESSION`]
    /// (R-21). Such a message is named when it arrives again: a late text
    /// is sent again until it is named, while a GONE is sent until the
    /// relay's acceptance is seen (normally once), so two devices whose
    /// sessions diverged (a rollback, a copied store) do not name each
    /// other's GONE messages round after round; a fault that delivers one
    /// twice draws one GONE more. A message named stays noted, so it is
    /// named again at its next arrival (its GONE lost, or a round that
    /// failed before committing it), at most once a minute
    /// ([`Self::name_gone`]). In memory only: a restart forgets them, and
    /// the texts are found again on their next two arrivals; deleting the
    /// contact or giving the session up clears the session's notes.
    forgotten_seen: Mutex<HashMap<u64, VecDeque<[u8; 32]>>>,
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
    /// Test aid: how many times this instance stored a far-skip wait.
    #[cfg(test)]
    far_writes: std::sync::atomic::AtomicU32,
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

/// How many messages of chains a session no longer knows it notes (R-21,
/// `NetworkMessenger::forgotten_seen`), as a GONE names at most 256 ids. A
/// flood of forged ones pushes a genuine note out, so its text is named
/// only after two more arrivals (docs/NET-MESSAGING.md section 8).
pub(crate) const FORGOTTEN_SEEN_PER_SESSION: usize = 256;

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
            forgotten_seen: Mutex::new(HashMap::new()),
            far_seen: Mutex::new(HashMap::new()),
            far_round: Mutex::new(FarRound::default()),
            #[cfg(test)]
            minute: Mutex::new(None),
            #[cfg(test)]
            now: Mutex::new(None),
            #[cfg(test)]
            far_tries: std::sync::atomic::AtomicU32::new(0),
            #[cfg(test)]
            far_writes: std::sync::atomic::AtomicU32::new(0),
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
mod tests;
