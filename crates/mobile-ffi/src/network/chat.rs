//! Conversations: what a messaging application shows and keeps.
//! Specification: `docs/NET-MESSAGING.md`, section 10.
//!
//! The durable layer keeps an outgoing text only until the peer's receipt and
//! an incoming text only until the application marks it read, so it holds no
//! history. This module keeps one per contact, in the same encrypted store:
//! one entry per logical message, written by the application's own actions
//! and by `sync_conversations`, never by the ratchet.
//!
//! - An outgoing text is recorded (`Queued`) under the application's id for
//!   it before anything is encrypted, and that id is what `send_text` commits
//!   it under. Every later step repeats with the same id, so a retry, a crash
//!   or a restart finds the committed message and never encrypts it again.
//! - An incoming text is recorded, together with an index on its message id,
//!   before it is marked read. Delivery from the inbox is at least once; the
//!   index makes it appear in the history once.
//! - `Delivered` means the peer's authenticated receipt arrived, and only
//!   that. `Transmitted` means the relay accepted the message, which says
//!   nothing about the peer.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use core_storage::StorageError;
use zeroize::Zeroizing;

use super::{crash_point, handle_of, peer_key, NetworkMessenger, SyncReport, TextState};
use crate::contacts::contact_card_fingerprint;
use crate::CoreError;

/// Longest contact name accepted, in bytes.
pub const MAX_NAME_LEN: usize = 128;
/// Longest text accepted, in bytes. Envelopes are limited to 64 KiB.
pub const MAX_TEXT_LEN: usize = 16 * 1024;

const ENTRY_VERSION: u8 = 1;
const META_VERSION: u8 = 1;

/// Both devices started a session with each other; ours is unconfirmed.
const FLAG_CONFLICT: u8 = 1;
/// The peer's published bundle names keys other than its pinned card.
const FLAG_IDENTITY_MISMATCH: u8 = 2;
/// Do not start a session: wait for the peer's handshake (set when this
/// device resolved a conflict).
const FLAG_ACCEPT_ONLY: u8 = 4;
/// A handshake from the peer was refused.
const FLAG_HANDSHAKE_REFUSED: u8 = 8;

/// Where a history entry stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ChatEntryState {
    /// Recorded, not yet encrypted: no session exists yet, or the commit has
    /// not run. Nothing has left the device.
    Queued,
    /// Encrypted and committed to the outbox; the relay has not accepted it
    /// in this process's lifetime.
    Pending,
    /// The relay accepted it. Nothing is known about the peer.
    Transmitted,
    /// The peer's authenticated receipt arrived: its device accepted and
    /// committed the message. Not a read receipt.
    Delivered,
    /// Given up on by this device without a receipt (after a session
    /// conflict was resolved here). The peer did not and will not accept it.
    NotDelivered,
    /// A text from the peer, accepted by the ratchet.
    Received,
}

impl ChatEntryState {
    fn code(self) -> u8 {
        match self {
            Self::Queued => 0,
            Self::Pending => 1,
            Self::Transmitted => 2,
            Self::Delivered => 3,
            Self::NotDelivered => 4,
            Self::Received => 5,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::Queued,
            1 => Self::Pending,
            2 => Self::Transmitted,
            3 => Self::Delivered,
            4 => Self::NotDelivered,
            5 => Self::Received,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ChatEntry {
    /// Position in this conversation, starting at 1.
    pub seq: u64,
    pub outgoing: bool,
    pub state: ChatEntryState,
    /// Local time the entry was recorded, in ms since the Unix epoch.
    pub timestamp_ms: u64,
    /// The application's id for an outgoing text; empty for incoming ones.
    pub app_id: Vec<u8>,
    /// Invalid UTF-8 from a peer is shown with replacement characters.
    pub text: String,
}

/// The session with a contact, as the application should present it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ChatSessionState {
    /// No session. The first queued text starts one.
    None,
    /// This device started the session; the peer has not answered yet.
    AwaitingPeer,
    /// This device resolved a conflict and waits for the peer's handshake.
    AwaitingPeerSession,
    Established,
    /// Both devices started a session with each other. Nothing is replaced
    /// automatically; `can_resolve` is true on the one device that may
    /// resolve it with `resolve_session_conflict`.
    Conflict {
        can_resolve: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Conversation {
    /// The contact's X25519 identity key.
    pub peer: Vec<u8>,
    pub name: String,
    /// Fingerprint of the pinned card (`contact_card_fingerprint`).
    pub fingerprint: String,
    pub session: ChatSessionState,
    /// The relay served a bundle for this contact that does not match the
    /// pinned card. Queued texts are not sent.
    pub identity_mismatch: bool,
    /// A handshake from this contact could not be accepted.
    pub handshake_refused: bool,
    /// Why queued texts are waiting, if known; empty otherwise.
    pub note: String,
    pub unread: u32,
    pub last: Option<ChatEntry>,
}

// ── Stored records ──────────────────────────────────────────────────────────
//
// Keys: `chat-meta:v1/<peer hex>`, `chat-e.v1.<peer hex>:<seq, 20 digits>`
// (entries; one store namespace per contact, so they can be listed),
// `chat-o:v1/<peer hex>/<app id hex>` and `chat-i:v1/<peer hex>/<message id
// hex>` (index → seq). Values are encrypted by the store; integers are
// big-endian.

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn meta_key(peer: &[u8; 32]) -> String {
    format!("chat-meta:v1/{}", hex(peer))
}

/// The store namespace of `peer`'s entries.
fn entry_namespace(peer: &[u8; 32]) -> String {
    format!("chat-e.v1.{}:", hex(peer))
}

fn entry_key(peer: &[u8; 32], seq: u64) -> String {
    format!("{}{seq:020}", entry_namespace(peer))
}

fn out_key(peer: &[u8; 32], app_id: &[u8]) -> String {
    format!("chat-o:v1/{}/{}", hex(peer), hex(app_id))
}

fn in_key(peer: &[u8; 32], message_id: &[u8]) -> String {
    format!("chat-i:v1/{}/{}", hex(peer), hex(message_id))
}

fn corrupt(what: &str) -> CoreError {
    CoreError::Storage {
        msg: format!("corrupt chat {what} record"),
    }
}

fn invalid(msg: &str) -> CoreError {
    CoreError::InvalidArgument { msg: msg.into() }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Clone)]
struct Entry {
    seq: u64,
    outgoing: bool,
    state: ChatEntryState,
    at_ms: u64,
    app_id: Vec<u8>,
    message_id: Vec<u8>,
    text: Zeroizing<Vec<u8>>,
}

impl Entry {
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(13 + self.text.len() + 96));
        out.push(ENTRY_VERSION);
        out.push(self.outgoing as u8);
        out.push(self.state.code());
        out.extend_from_slice(&self.at_ms.to_be_bytes());
        out.push(self.app_id.len() as u8);
        out.extend_from_slice(&self.app_id);
        out.push(self.message_id.len() as u8);
        out.extend_from_slice(&self.message_id);
        out.extend_from_slice(&self.text);
        out
    }

    fn decode(seq: u64, bytes: &[u8]) -> Result<Self, CoreError> {
        let bad = || corrupt("entry");
        if bytes.len() < 13 || bytes[0] != ENTRY_VERSION || bytes[1] > 1 {
            return Err(bad());
        }
        let state = ChatEntryState::from_code(bytes[2]).ok_or_else(bad)?;
        let at_ms = u64::from_be_bytes(bytes[3..11].try_into().expect("8 bytes"));
        let mut rest = &bytes[11..];
        let mut field = || -> Result<Vec<u8>, CoreError> {
            let (&len, tail) = rest.split_first().ok_or_else(bad)?;
            if tail.len() < len as usize {
                return Err(bad());
            }
            let (value, tail) = tail.split_at(len as usize);
            rest = tail;
            Ok(value.to_vec())
        };
        let app_id = field()?;
        let message_id = field()?;
        Ok(Self {
            seq,
            outgoing: bytes[1] == 1,
            state,
            at_ms,
            app_id,
            message_id,
            text: Zeroizing::new(rest.to_vec()),
        })
    }

    fn public(&self) -> ChatEntry {
        ChatEntry {
            seq: self.seq,
            outgoing: self.outgoing,
            state: self.state,
            timestamp_ms: self.at_ms,
            app_id: self.app_id.clone(),
            text: String::from_utf8_lossy(&self.text).into_owned(),
        }
    }
}

#[derive(Default)]
struct Meta {
    /// Highest seq in use.
    last_seq: u64,
    /// Highest seq the user has seen.
    seen_seq: u64,
    flags: u8,
    name: String,
    note: String,
}

impl Meta {
    fn encode(&self) -> Vec<u8> {
        let mut out = vec![META_VERSION];
        out.extend_from_slice(&self.last_seq.to_be_bytes());
        out.extend_from_slice(&self.seen_seq.to_be_bytes());
        out.push(self.flags);
        for s in [&self.name, &self.note] {
            out.extend_from_slice(&(s.len() as u16).to_be_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, CoreError> {
        let bad = || corrupt("meta");
        if bytes.len() < 18 || bytes[0] != META_VERSION {
            return Err(bad());
        }
        let mut rest = &bytes[18..];
        let mut string = || -> Result<String, CoreError> {
            if rest.len() < 2 {
                return Err(bad());
            }
            let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            if rest.len() < 2 + len {
                return Err(bad());
            }
            let s = String::from_utf8(rest[2..2 + len].to_vec()).map_err(|_| bad())?;
            rest = &rest[2 + len..];
            Ok(s)
        };
        let name = string()?;
        let note = string()?;
        if !rest.is_empty() {
            return Err(bad());
        }
        Ok(Self {
            last_seq: u64::from_be_bytes(bytes[1..9].try_into().expect("8 bytes")),
            seen_seq: u64::from_be_bytes(bytes[9..17].try_into().expect("8 bytes")),
            flags: bytes[17],
            name,
            note,
        })
    }
}

/// Where a store read of an optional key lands.
fn get_opt(result: Result<Vec<u8>, StorageError>) -> Result<Option<Vec<u8>>, CoreError> {
    match result {
        Ok(v) => Ok(Some(v)),
        Err(StorageError::NotFound) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// What one local refresh of a conversation did.
#[derive(Default)]
struct Refresh {
    /// Queued texts committed to the outbox now.
    committed: u32,
    /// Queued texts that cannot be committed because there is no session.
    waiting: u32,
}

/// Sets `flag` for `peer`. Used by the network layer when it drops a
/// handshake that signals a conflict or that it could not accept.
pub(super) fn set_flag(
    messenger: &NetworkMessenger,
    peer: &[u8; 32],
    flag: u8,
) -> Result<(), CoreError> {
    messenger.update_meta(peer, |m| m.flags |= flag)
}

pub(super) const CONFLICT: u8 = FLAG_CONFLICT;
pub(super) const HANDSHAKE_REFUSED: u8 = FLAG_HANDSHAKE_REFUSED;

#[uniffi::export]
impl NetworkMessenger {
    /// Pins `card` (as `ArciumCore::add_contact`, with the same refusal of a
    /// changed identity) and names the contact. Adding the same card again
    /// renames it. Returns the contact's X25519 identity key.
    pub fn add_named_contact(&self, card: Vec<u8>, name: String) -> Result<Vec<u8>, CoreError> {
        let name = checked_name(name)?;
        let peer = self.core.add_contact(card)?;
        let key = peer_key(&peer)?;
        self.update_meta(&key, |m| m.name = name)?;
        Ok(peer)
    }

    pub fn rename_contact(&self, peer: Vec<u8>, name: String) -> Result<(), CoreError> {
        let name = checked_name(name)?;
        let peer = peer_key(&peer)?;
        self.require_contact(&peer)?;
        self.update_meta(&peer, |m| m.name = name)
    }

    /// Every contact with its conversation state, most recent first. Local
    /// only: nothing is sent or fetched.
    pub fn conversations(&self) -> Result<Vec<Conversation>, CoreError> {
        let mut out = Vec::new();
        for peer in self.core.contacts()? {
            out.push(self.conversation(peer)?);
        }
        out.sort_by(|a, b| {
            let at = |c: &Conversation| c.last.as_ref().map_or(0, |e| e.timestamp_ms);
            at(b).cmp(&at(a)).then_with(|| a.name.cmp(&b.name))
        });
        Ok(out)
    }

    pub fn conversation(&self, peer: Vec<u8>) -> Result<Conversation, CoreError> {
        let key = peer_key(&peer)?;
        let card = self.require_contact(&key)?;
        let meta = self.meta(&key)?;
        let entries = self.entries(&key)?;
        let unread = entries
            .iter()
            .filter(|e| !e.outgoing && e.seq > meta.seen_seq)
            .count() as u32;
        Ok(Conversation {
            peer,
            name: meta.name.clone(),
            fingerprint: contact_card_fingerprint(card.encode())?,
            session: self.session_state(&key, &meta)?,
            identity_mismatch: meta.flags & FLAG_IDENTITY_MISMATCH != 0,
            handshake_refused: meta.flags & FLAG_HANDSHAKE_REFUSED != 0,
            note: meta.note.clone(),
            unread,
            last: entries.last().map(Entry::public),
        })
    }

    /// The conversation with `peer`, oldest first. Brings the history up to
    /// date with the local stores first (received texts, receipts, queued
    /// texts a session now exists for); nothing is sent or fetched.
    pub fn chat_entries(&self, peer: Vec<u8>) -> Result<Vec<ChatEntry>, CoreError> {
        let key = peer_key(&peer)?;
        self.require_contact(&key)?;
        self.refresh(&key)?;
        Ok(self.entries(&key)?.iter().map(Entry::public).collect())
    }

    /// Records the text `text` for `peer` under the application's id for it
    /// (1 to 63 bytes, unique per logical message) and, if a session exists,
    /// commits it to the outbox. Calling again with the same id returns the
    /// entry as it stands and never records or encrypts it a second time, so
    /// after an error the caller repeats the call with the same id.
    /// `sync_conversations` starts a session if none exists, and transmits.
    pub fn chat_send(
        &self,
        peer: Vec<u8>,
        app_id: Vec<u8>,
        text: String,
    ) -> Result<ChatEntry, CoreError> {
        let key = peer_key(&peer)?;
        self.require_contact(&key)?;
        if app_id.is_empty() || app_id.len() > 63 {
            return Err(invalid("app id must be 1 to 63 bytes"));
        }
        let text = Zeroizing::new(text.into_bytes());
        if text.is_empty() || text.len() > MAX_TEXT_LEN {
            return Err(invalid("text must be 1 to 16384 bytes"));
        }
        let seq = {
            let mut store = self.core.store.lock().map_err(|_| poisoned())?;
            let tx = store.transaction()?;
            match get_opt(tx.get(&out_key(&key, &app_id)))? {
                Some(seq) => decode_seq(&seq)?,
                None => {
                    let mut meta = match get_opt(tx.get(&meta_key(&key)))? {
                        Some(m) => Meta::decode(&m)?,
                        None => Meta::default(),
                    };
                    meta.last_seq += 1;
                    let seq = meta.last_seq;
                    let entry = Entry {
                        seq,
                        outgoing: true,
                        state: ChatEntryState::Queued,
                        at_ms: now_ms(),
                        app_id: app_id.clone(),
                        message_id: Vec::new(),
                        text,
                    };
                    tx.put(&entry_key(&key, seq), &entry.encode())?;
                    tx.put(&out_key(&key, &app_id), &seq.to_be_bytes())?;
                    tx.put(&meta_key(&key), &meta.encode())?;
                    tx.commit()?;
                    crash_point("chat_after_queue");
                    seq
                }
            }
        };
        self.refresh(&key)?;
        Ok(self.entry(&key, seq)?.public())
    }

    /// Records that the user has seen everything in the conversation so far.
    pub fn mark_seen(&self, peer: Vec<u8>) -> Result<(), CoreError> {
        let key = peer_key(&peer)?;
        self.require_contact(&key)?;
        self.update_meta(&key, |m| m.seen_seq = m.last_seq)
    }

    /// Resolves a session conflict (both devices started a session with each
    /// other) on the one device allowed to: the one whose identity key is
    /// the greater. It marks the texts it committed to its own session
    /// `NotDelivered` (the peer dropped that session's messages and never
    /// accepts it), abandons them, removes that session, and waits for the
    /// peer's, which the peer keeps retransmitting. Texts not yet committed
    /// stay queued and go out in the peer's session. Every step repeats
    /// safely after a crash; calling it again completes it.
    pub fn resolve_session_conflict(&self, peer: Vec<u8>) -> Result<(), CoreError> {
        let key = peer_key(&peer)?;
        self.require_contact(&key)?;
        let meta = self.meta(&key)?;
        if meta.flags & FLAG_CONFLICT == 0 {
            return Err(invalid("no session conflict with this contact"));
        }
        if self.core.our_identity_pk()? <= key {
            return Err(invalid("the contact's device resolves this conflict"));
        }
        let handle = handle_of(&key);
        if self.core.has_session(handle)? {
            if self.confirmed(handle)? {
                // The peer accepted this session after all: nothing to do.
                return self.update_meta(&key, |m| m.flags &= !FLAG_CONFLICT);
            }
            // Before anything leaves the outbox, so the history never reads a
            // missing outbox record as a receipt.
            self.update_meta(&key, |m| m.flags |= FLAG_ACCEPT_ONLY)?;
            for e in self.entries(&key)? {
                if e.outgoing
                    && matches!(
                        e.state,
                        ChatEntryState::Pending | ChatEntryState::Transmitted
                    )
                {
                    self.advance(&key, e.seq, ChatEntryState::NotDelivered, None)?;
                }
            }
            for m in self.core.pending_outgoing(handle)? {
                self.core.abandon_outgoing(handle, m.message_id)?;
            }
            self.core.remove_session(handle)?;
        }
        self.update_meta(&key, |m| {
            m.flags = (m.flags | FLAG_ACCEPT_ONLY) & !FLAG_CONFLICT;
            m.note.clear();
        })
    }

    /// One round for every conversation: records what the local stores hold,
    /// runs `sync`, starts a session for each contact with queued texts and
    /// none yet (after the fetch, so a waiting handshake from the contact is
    /// accepted instead), commits queued texts and sends them. Failures are
    /// listed in the report; nothing local is lost.
    pub fn sync_conversations(&self) -> SyncReport {
        let mut report = SyncReport::default();
        if let Err(e) = self.sync_conversations_round(&mut report) {
            report.errors.push(e.to_string());
        }
        report
    }
}

fn poisoned() -> CoreError {
    CoreError::Storage {
        msg: "mutex poisoned".into(),
    }
}

fn checked_name(name: String) -> Result<String, CoreError> {
    let name = name.trim().to_string();
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(invalid("contact name must be 1 to 128 bytes"));
    }
    Ok(name)
}

fn decode_seq(bytes: &[u8]) -> Result<u64, CoreError> {
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| corrupt("index"))?,
    ))
}

fn merge(into: &mut SyncReport, r: SyncReport) {
    into.published += r.published;
    into.fetched += r.fetched;
    into.accepted += r.accepted;
    into.duplicates += r.duplicates;
    into.sessions_accepted += r.sessions_accepted;
    into.delivered += r.delivered;
    into.dropped += r.dropped;
    into.deferred += r.deferred;
    into.errors.extend(r.errors);
}

impl NetworkMessenger {
    fn sync_conversations_round(&self, report: &mut SyncReport) -> Result<(), CoreError> {
        let peers: Vec<[u8; 32]> = self
            .core
            .contacts()?
            .iter()
            .map(|p| peer_key(p))
            .collect::<Result<_, _>>()?;
        for peer in &peers {
            self.refresh(peer)?;
        }
        merge(report, self.sync());

        let mut started = false;
        for peer in &peers {
            let refresh = self.refresh(peer)?;
            let handle = handle_of(peer);
            if self.core.has_session(handle)? {
                // The peer's session (accepted here, or confirmed by the peer)
                // ends a conflict and the wait for it. Our own unconfirmed
                // one does not: `resolve_session_conflict` may be removing it.
                let peers_session =
                    self.confirmed(handle)? || self.core.initiator_handshake(handle)?.is_none();
                self.update_meta(peer, |m| {
                    m.flags &= !(FLAG_IDENTITY_MISMATCH | FLAG_HANDSHAKE_REFUSED);
                    if peers_session {
                        m.flags &= !(FLAG_CONFLICT | FLAG_ACCEPT_ONLY);
                    }
                    m.note.clear();
                })?;
                continue;
            }
            if refresh.waiting == 0 || self.meta(peer)?.flags & FLAG_ACCEPT_ONLY != 0 {
                continue;
            }
            match self.start_session(peer.to_vec()) {
                Ok(()) => {
                    started = true;
                    self.update_meta(peer, |m| {
                        m.flags &= !FLAG_IDENTITY_MISMATCH;
                        m.note.clear();
                    })?;
                }
                Err(CoreError::PeerBundleUnavailable) => self.update_meta(peer, |m| {
                    m.note = "the contact's keys are not on the relay yet: \
                              they have to open the app while connected"
                        .into();
                })?,
                Err(CoreError::PeerIdentityMismatch) => {
                    self.update_meta(peer, |m| m.flags |= FLAG_IDENTITY_MISMATCH)?
                }
                // Raced with an accepted handshake: the session exists.
                Err(CoreError::SessionAlreadyExists { .. }) => {}
                Err(e) => report.errors.push(e.to_string()),
            }
        }

        let mut committed = 0;
        for peer in &peers {
            committed += self.refresh(peer)?.committed;
        }
        if started || committed > 0 {
            merge(report, self.sync());
            for peer in &peers {
                self.refresh(peer)?;
            }
        }
        Ok(())
    }

    fn meta(&self, peer: &[u8; 32]) -> Result<Meta, CoreError> {
        let store = self.core.store.lock().map_err(|_| poisoned())?;
        match get_opt(store.get(&meta_key(peer)))? {
            Some(m) => Meta::decode(&m),
            None => Ok(Meta::default()),
        }
    }

    fn update_meta(&self, peer: &[u8; 32], f: impl FnOnce(&mut Meta)) -> Result<(), CoreError> {
        let mut store = self.core.store.lock().map_err(|_| poisoned())?;
        let tx = store.transaction()?;
        let mut meta = match get_opt(tx.get(&meta_key(peer)))? {
            Some(m) => Meta::decode(&m)?,
            None => Meta::default(),
        };
        let before = meta.encode();
        f(&mut meta);
        let after = meta.encode();
        if after != before {
            tx.put(&meta_key(peer), &after)?;
            tx.commit()?;
        }
        Ok(())
    }

    fn entry(&self, peer: &[u8; 32], seq: u64) -> Result<Entry, CoreError> {
        let store = self.core.store.lock().map_err(|_| poisoned())?;
        Entry::decode(seq, &Zeroizing::new(store.get(&entry_key(peer, seq))?))
    }

    fn entries(&self, peer: &[u8; 32]) -> Result<Vec<Entry>, CoreError> {
        let store = self.core.store.lock().map_err(|_| poisoned())?;
        let namespace = entry_namespace(peer);
        let mut out = Vec::new();
        for key in store.list_keys_with_prefix(&namespace)? {
            let seq = key
                .strip_prefix(&namespace)
                .and_then(|seq| seq.parse::<u64>().ok())
                .ok_or_else(|| corrupt("entry key"))?;
            out.push(Entry::decode(seq, &Zeroizing::new(store.get(&key)?))?);
        }
        out.sort_by_key(|e| e.seq);
        Ok(out)
    }

    /// Moves entry `seq` forward to `state` (never back: a stale caller
    /// cannot undo a receipt) and records its message id if it has none.
    fn advance(
        &self,
        peer: &[u8; 32],
        seq: u64,
        state: ChatEntryState,
        message_id: Option<&[u8]>,
    ) -> Result<(), CoreError> {
        use ChatEntryState::*;
        let mut store = self.core.store.lock().map_err(|_| poisoned())?;
        let tx = store.transaction()?;
        let key = entry_key(peer, seq);
        let mut entry = Entry::decode(seq, &Zeroizing::new(tx.get(&key)?))?;
        let forward = matches!(
            (entry.state, state),
            (Queued, Pending | Transmitted | Delivered | NotDelivered)
                | (Pending, Transmitted | Delivered | NotDelivered)
                | (Transmitted, Delivered | NotDelivered)
        );
        let new_id = match message_id {
            Some(id) if entry.message_id.is_empty() => Some(id.to_vec()),
            _ => None,
        };
        if !forward && new_id.is_none() {
            return Ok(());
        }
        if forward {
            entry.state = state;
        }
        if let Some(id) = new_id {
            entry.message_id = id;
        }
        tx.put(&key, &entry.encode())?;
        tx.commit()?;
        Ok(())
    }

    /// Records a received text once: the entry and its message-id index are
    /// written together, so a text listed again after a crash is skipped.
    fn record_incoming(
        &self,
        peer: &[u8; 32],
        message_id: &[u8],
        text: Zeroizing<Vec<u8>>,
    ) -> Result<(), CoreError> {
        let mut store = self.core.store.lock().map_err(|_| poisoned())?;
        let tx = store.transaction()?;
        let index = in_key(peer, message_id);
        if get_opt(tx.get(&index))?.is_some() {
            return Ok(());
        }
        let mut meta = match get_opt(tx.get(&meta_key(peer)))? {
            Some(m) => Meta::decode(&m)?,
            None => Meta::default(),
        };
        meta.last_seq += 1;
        let entry = Entry {
            seq: meta.last_seq,
            outgoing: false,
            state: ChatEntryState::Received,
            at_ms: now_ms(),
            app_id: Vec::new(),
            message_id: message_id.to_vec(),
            text,
        };
        tx.put(&entry_key(peer, entry.seq), &entry.encode())?;
        tx.put(&index, &entry.seq.to_be_bytes())?;
        tx.put(&meta_key(peer), &meta.encode())?;
        tx.commit()?;
        Ok(())
    }

    /// Brings the history of `peer` up to date with the local stores. No
    /// network I/O.
    fn refresh(&self, peer: &[u8; 32]) -> Result<Refresh, CoreError> {
        let mut result = Refresh::default();
        let handle = handle_of(peer);
        let has_session = self.core.has_session(handle)?;
        if has_session {
            // Received texts: into the history, then marked read.
            for text in self.received_texts(peer.to_vec())? {
                self.record_incoming(peer, &text.message_id, Zeroizing::new(text.text))?;
                crash_point("chat_after_record");
                self.mark_read(peer.to_vec(), text.message_id)?;
            }
        }
        let pending: HashSet<Vec<u8>> = if has_session {
            self.core
                .pending_outgoing(handle)?
                .into_iter()
                .map(|m| m.message_id)
                .collect()
        } else {
            HashSet::new()
        };
        for e in self.entries(peer)? {
            if !e.outgoing {
                continue;
            }
            match e.state {
                ChatEntryState::Queued if has_session => {
                    // Same id as recorded: returns the committed message if
                    // an earlier attempt got this far.
                    let sent = self.send_text(peer.to_vec(), e.app_id.clone(), e.text.to_vec())?;
                    crash_point("chat_after_outbox");
                    let state = match sent.state {
                        TextState::Pending => ChatEntryState::Pending,
                        TextState::Delivered => ChatEntryState::Delivered,
                        TextState::Abandoned => ChatEntryState::NotDelivered,
                    };
                    self.advance(peer, e.seq, state, Some(&sent.message_id))?;
                    result.committed += 1;
                }
                ChatEntryState::Queued => result.waiting += 1,
                // A committed text leaves the outbox only on the peer's
                // receipt (or when abandoned, which marks it NotDelivered
                // first), so while the session exists, absence is a receipt.
                ChatEntryState::Pending | ChatEntryState::Transmitted if has_session => {
                    if !pending.contains(&e.message_id) {
                        self.advance(peer, e.seq, ChatEntryState::Delivered, None)?;
                    } else if e.state == ChatEntryState::Pending && self.was_sent(&e.message_id) {
                        self.advance(peer, e.seq, ChatEntryState::Transmitted, None)?;
                    }
                }
                _ => {}
            }
        }
        Ok(result)
    }

    fn session_state(&self, peer: &[u8; 32], meta: &Meta) -> Result<ChatSessionState, CoreError> {
        let handle = handle_of(peer);
        if !self.core.has_session(handle)? {
            return Ok(if meta.flags & FLAG_ACCEPT_ONLY != 0 {
                ChatSessionState::AwaitingPeerSession
            } else {
                ChatSessionState::None
            });
        }
        if self.confirmed(handle)? || self.core.initiator_handshake(handle)?.is_none() {
            return Ok(ChatSessionState::Established);
        }
        if meta.flags & FLAG_CONFLICT != 0 {
            return Ok(ChatSessionState::Conflict {
                can_resolve: self.core.our_identity_pk()? > *peer,
            });
        }
        Ok(ChatSessionState::AwaitingPeer)
    }
}
