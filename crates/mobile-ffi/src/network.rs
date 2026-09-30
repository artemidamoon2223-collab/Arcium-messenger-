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
use relay::protocol::{DEFAULT_MAX_MAILBOX, MAX_FETCH, MIN_PAGE};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::contacts::{pinned, Card};
use core_protocol::messaging::{MessageId, Received};

use crate::{unpack_prekey_bundle, ArciumCore, CoreError, PlaintextBytes, SendResult, PREKEYS_KEY};
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
    /// When each message or handshake was last accepted by the relay. In
    /// memory only: after a restart everything pending is sent once more.
    last_sent: Mutex<HashMap<[u8; 32], Instant>>,
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
    /// receipt. Every network operation times out after `timeout_ms`.
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
        self.core.establish_session_initiator(handle, bundle)?;
        self.core.send_message(
            handle,
            client_id::OPEN.to_vec(),
            Payload::Open.encode().to_vec(),
        )?;
        Ok(())
    }

    /// Commits the text `text` for `peer` under the application's own id for
    /// it (1 to 63 bytes). Repeating a call with the same id sends nothing new
    /// and reports where the first one stands. `sync` transmits it.
    pub fn send_text(
        &self,
        peer: Vec<u8>,
        client_message_id: Vec<u8>,
        text: Vec<u8>,
    ) -> Result<SentText, CoreError> {
        let text = Zeroizing::new(text);
        let peer = peer_key(&peer)?;
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
    pub fn mark_read(&self, peer: Vec<u8>, message_id: Vec<u8>) -> Result<bool, CoreError> {
        self.core
            .acknowledge_incoming(handle_of(&peer_key(&peer)?), message_id)
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
        if let Err(e) = self.sync_round(&mut report) {
            report.errors.push(e.to_string());
        }
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
        Connection::connect(&self.relay, self.timeout).map_err(network)
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

    fn sync_round(&self, report: &mut SyncReport) -> Result<(), CoreError> {
        let sessions = self.sessions()?;
        // Local recovery first: receipts or OPEN messages committed before a
        // crash, and receipts for texts accepted before one.
        for (_, handle) in &sessions {
            self.settle_inbox(*handle, report)?;
        }
        let mut conn = self.connect()?;
        self.put_bundle(&mut conn)?;
        self.publish_pending(&mut conn, &sessions, report)?;

        let our = self.core.our_identity_pk()?;
        // Handshakes before messages, so a session exists for what follows:
        // first every handshake in the part of the mailbox scanned, then
        // everything else in that same part.
        if let Some(end) = self.scan(&mut conn, our, Pass::Handshakes, u64::MAX, report)? {
            self.scan(&mut conn, our, Pass::Messages, end, report)?;
        }
        // Receipts produced above, and the first messages of new sessions.
        let sessions = self.sessions()?;
        self.publish_pending(&mut conn, &sessions, report)
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
    /// only returns when nothing follows, and on reaching `until`. The cursor
    /// exists only in this call:
    /// sequence numbers are transport positions chosen by the untrusted relay,
    /// never evidence of anything, and a new round starts from the beginning.
    /// A relay that does not return strictly increasing numbers after the
    /// cursor ends the round with an error.
    ///
    /// Returns the last sequence number this pass reached, if any.
    fn scan(
        &self,
        conn: &mut Connection,
        our: [u8; 32],
        pass: Pass,
        until: u64,
        report: &mut SyncReport,
    ) -> Result<Option<u64>, CoreError> {
        let mut after = 0u64;
        let mut seen = 0usize;
        let mut delete = Vec::new();
        'pages: for _page in 0..MAX_SCAN_PAGES {
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
            scan_hook::run(pass, _page);
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
        Ok((after > 0).then_some(after))
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

    fn due(&self, key: &[u8; 32]) -> bool {
        let sent = self.last_sent.lock().expect("last_sent");
        sent.get(key)
            .is_none_or(|t| t.elapsed() >= self.retransmit_after)
    }

    fn mark_sent(&self, key: [u8; 32]) {
        self.last_sent
            .lock()
            .expect("last_sent")
            .insert(key, Instant::now());
    }

    fn publish_pending(
        &self,
        conn: &mut Connection,
        sessions: &[([u8; 32], u64)],
        report: &mut SyncReport,
    ) -> Result<(), CoreError> {
        let our = self.core.our_identity_pk()?;
        for (peer, handle) in sessions {
            if !self.confirmed(*handle)? {
                if let Some(hs) = self.core.initiator_handshake(*handle)? {
                    let key: [u8; 32] = Sha256::digest(&hs).into();
                    if self.due(&key) {
                        let env = Envelope::Handshake {
                            sender: our,
                            handshake: hs,
                        };
                        conn.send(*peer, env.encode()).map_err(network)?;
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
                let env = Envelope::Message {
                    sender: our,
                    wire: m.wire,
                };
                conn.send(*peer, env.encode()).map_err(network)?;
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
                match self.core.establish_session_responder(handle, handshake) {
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
                        report.dropped += 1;
                        report.errors.push(format!("handshake refused: {e}"));
                        Ok(Fate::Delete)
                    }
                }
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
                        self.receipt_again(handle, &message_id)?;
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
        self.core.send_message(
            handle,
            client_id::receipt(id, round),
            Payload::Receipt(vec![*id]).encode().to_vec(),
        )
    }

    /// The peer sent `id` again, so it may not have our receipt. If the
    /// original receipt already left the outbox, commit a new one, at most one
    /// per minute per message.
    fn receipt_again(&self, handle: u64, id: &[u8]) -> Result<(), CoreError> {
        let id32: [u8; 32] = id.try_into().expect("32-byte id");
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
