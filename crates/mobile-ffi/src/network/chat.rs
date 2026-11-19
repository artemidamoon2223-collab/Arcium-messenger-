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

use core_storage::{StorageError, StoreTransaction};
use zeroize::Zeroizing;

use super::wire::client_id;
use super::{crash_point, handle_of, peer_key, NetworkMessenger, SyncReport, TextState};
use crate::messaging_api::SendResult;
use core_protocol::durable::SideWrite;
use crate::contacts::{contact_card_fingerprint, contact_key};
use crate::accepted_handshake_key;
use crate::{CoreError, PlaintextText};

/// Longest contact name accepted, in bytes.
pub const MAX_NAME_LEN: usize = 128;
/// Longest text accepted, in bytes. Envelopes are limited to 64 KiB.
pub const MAX_TEXT_LEN: usize = 16 * 1024;
/// Most entries one `chat_entries_page` returns.
pub const MAX_PAGE: u32 = 200;

const ENTRY_VERSION: u8 = 1;
const META_VERSION: u8 = 1;

/// Both devices started a session with each other; ours is unconfirmed.
/// Set only when the contact's first message under its handshake, recorded
/// beside our session, authenticated here (tracker R-13, option A): a
/// handshake alone never sets it.
const FLAG_CONFLICT: u8 = 16;
/// The conflict flag of builds before option A, which set it on a handshake
/// alone, which anyone can forge. Never set now and ignored when read
/// (`Meta::decode`), so a false conflict such a build recorded is not shown
/// or resolved. A genuine one is recorded again under `FLAG_CONFLICT`: the
/// contact retransmits its handshake and first message while its session is
/// unconfirmed.
const FLAG_CONFLICT_BEFORE_OPTION_A: u8 = 1;
/// The peer's published bundle names keys other than its pinned card.
const FLAG_IDENTITY_MISMATCH: u8 = 2;
/// Do not start a session: wait for the peer's handshake (set when this
/// device resolved a conflict).
const FLAG_ACCEPT_ONLY: u8 = 4;
/// A handshake from the peer was refused.
const FLAG_HANDSHAKE_REFUSED: u8 = 8;
/// The contact restarted the session (option B): its first message under a
/// new handshake replaced the session this device held, and the texts
/// committed to that session were marked `NotDelivered`. Shown to the user
/// until they send the contact a text or reset the session themselves.
const FLAG_PEER_RESET: u8 = 32;
/// Start a session with the contact at the next round even with no text
/// queued: the user reset the session (`reset_session`). Cleared once a
/// session exists.
const FLAG_RESTART: u8 = 64;

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
    /// Given up on by this device without a receipt: after a session
    /// conflict was resolved here, after the session it was committed to
    /// was given up (a refusal, `reset_session`, or the contact's restart),
    /// or because the peer named it in a GONE message (it arrived after its
    /// key was gone, R-21). It is not sent again and never becomes
    /// `Delivered`. Usually the peer did not accept it; when the session was
    /// given up, a copy sent before may have reached the peer, whose receipt
    /// can then no longer be read here.
    NotDelivered,
    /// A text from the peer, accepted by the ratchet.
    Received,
    /// Given up on by the user (`cancel_text`) before a receipt arrived: it
    /// is no longer sent. Says nothing about the peer: a copy the relay
    /// already accepted may still reach it, and its device would then accept
    /// it. Moves to `Delivered` only if the peer's receipt is found after
    /// all.
    Cancelled,
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
            Self::Cancelled => 6,
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
            6 => Self::Cancelled,
            _ => return None,
        })
    }
}

#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct ChatEntry {
    /// Position in this conversation, starting at 1.
    pub seq: u64,
    pub outgoing: bool,
    pub state: ChatEntryState,
    /// Local time the entry was recorded, in ms since the Unix epoch.
    pub timestamp_ms: u64,
    /// The application's id for an outgoing text; empty for incoming ones.
    pub app_id: Vec<u8>,
    /// Invalid UTF-8 from a peer is shown with replacement characters. The
    /// application's copy of the text.
    pub text: PlaintextText,
}

/// Shows the metadata and hides the text: accidental formatting and logging
/// only. `Conversation::last` holds a `ChatEntry`, so it is covered too.
impl std::fmt::Debug for ChatEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatEntry")
            .field("seq", &self.seq)
            .field("outgoing", &self.outgoing)
            .field("state", &self.state)
            .field("timestamp_ms", &self.timestamp_ms)
            .field("app_id", &self.app_id)
            .field("text", &"<redacted>")
            .finish()
    }
}

/// The session with a contact, as the application should present it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ChatSessionState {
    /// No session. The first queued text starts one. A handshake from the
    /// contact that no message has authenticated yet is not a session.
    None,
    /// A session exists here, but no message from the peer has authenticated
    /// under it yet: this device started it and the peer has not answered.
    AwaitingPeer,
    /// This device resolved a conflict and waits for the peer's handshake.
    AwaitingPeerSession,
    /// A message from the peer authenticated under this session and was
    /// committed here — the only thing that establishes a session.
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
    /// The contact restarted the secure session (option B): texts this
    /// device had committed to the old one read `NotDelivered`. Cleared when
    /// the user sends the contact a text or resets the session.
    pub peer_reset: bool,
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
// hex>` (index → seq), `chat-r:v1/<peer hex>/<app id hex>` (the app id is
// taken by `send_text`; empty value), and `chat-open:v1/<peer hex>` (the seqs
// of outgoing entries not yet final, see `OpenSeqs`). Values are encrypted by
// the store; integers are big-endian.
//
// Entry seqs are contiguous: each entry takes `last_seq + 1` in the
// transaction that writes it and the meta, and no entry is ever deleted. So
// an entry, a page or the last entry is read by key, without listing.

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

fn open_key(peer: &[u8; 32]) -> String {
    format!("chat-open:v1/{}", hex(peer))
}

const OPEN_VERSION: u8 = 1;

/// The seqs of `peer`'s outgoing entries that are not final yet (`Queued`,
/// `Pending`, `Transmitted`), ascending: what `refresh` and the giving up of
/// a session walk instead of the whole history. Written in the transaction of
/// every entry change that adds or removes one. A history written before this
/// record existed has none; [`NetworkMessenger::open_seqs`] then builds it
/// once, in one transaction, from the entries themselves.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct OpenSeqs(Vec<u64>);

impl OpenSeqs {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 8 * self.0.len());
        out.push(OPEN_VERSION);
        for seq in &self.0 {
            out.extend_from_slice(&seq.to_be_bytes());
        }
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, CoreError> {
        let bad = || corrupt("open-entry");
        let (&version, rest) = bytes.split_first().ok_or_else(bad)?;
        if version != OPEN_VERSION || rest.len() % 8 != 0 {
            return Err(bad());
        }
        let seqs: Vec<u64> = rest
            .chunks(8)
            .map(|c| u64::from_be_bytes(c.try_into().expect("8 bytes")))
            .collect();
        if seqs.windows(2).any(|w| w[0] >= w[1]) {
            return Err(bad());
        }
        Ok(Self(seqs))
    }

    fn insert(&mut self, seq: u64) {
        if let Err(at) = self.0.binary_search(&seq) {
            self.0.insert(at, seq);
        }
    }

    fn remove(&mut self, seq: u64) {
        if let Ok(at) = self.0.binary_search(&seq) {
            self.0.remove(at);
        }
    }
}

/// Whether an entry in `state` can still change: an outgoing one not yet
/// `Delivered`, `NotDelivered` or `Cancelled`. (A `Cancelled` entry becomes
/// `Delivered` only in `cancel_text`, or when a stale `refresh` holds a
/// receipt for it; nothing walks it otherwise.)
fn is_open(outgoing: bool, state: ChatEntryState) -> bool {
    outgoing
        && matches!(
            state,
            ChatEntryState::Queued | ChatEntryState::Pending | ChatEntryState::Transmitted
        )
}

fn out_key(peer: &[u8; 32], app_id: &[u8]) -> String {
    format!("chat-o:v1/{}/{}", hex(peer), hex(app_id))
}

/// `send_text` and the chat history share one client id per app id
/// (`client_id::text`). Whichever takes an app id first keeps it: `send_text`
/// records this claim, `chat_send` an entry, each in an IMMEDIATE store
/// transaction that first checks for the other's record, so the two never
/// commit under each other's id, also from separate connections.
fn raw_claim_key(peer: &[u8; 32], app_id: &[u8]) -> String {
    format!("chat-r:v1/{}/{}", hex(peer), hex(app_id))
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
            text: PlaintextText(String::from_utf8_lossy(&self.text).into_owned()),
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
            flags: bytes[17] & !FLAG_CONFLICT_BEFORE_OPTION_A,
            name,
            note,
        })
    }
}

/// The meta change of `reset_session`: the next round starts a session,
/// also with no text queued; a dead end or an earlier notice no longer
/// applies.
fn restart_requested(m: &mut Meta) {
    m.flags = (m.flags | FLAG_RESTART) & !(FLAG_ACCEPT_ONLY | FLAG_PEER_RESET | FLAG_HANDSHAKE_REFUSED);
    m.note.clear();
}

/// Which session `retire_session_texts` may remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Retire {
    /// Only our own unconfirmed one (a refusal, a conflict resolution).
    Unconfirmed,
    /// Any, on a restart (option B): the user's or the contact's.
    Any,
}

/// Where a store read of an optional key lands.
fn get_opt(result: Result<Vec<u8>, StorageError>) -> Result<Option<Vec<u8>>, CoreError> {
    match result {
        Ok(v) => Ok(Some(v)),
        Err(StorageError::NotFound) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Whether `peer` is still a contact, read inside the transaction that is
/// about to write one of its chat records. `delete_contact` deletes the card
/// with every chat record in one IMMEDIATE transaction, so a writer that
/// checked the contact before that and writes after it finds the card gone
/// here, and writes nothing: a later re-add inherits no record.
fn pinned_in(tx: &StoreTransaction<'_>, peer: &[u8; 32]) -> Result<bool, CoreError> {
    Ok(get_opt(tx.get(&contact_key(peer)))?.is_some())
}

/// The body of [`NetworkMessenger::advance`], inside `tx`: moves entry `seq`
/// forward to `state` and records `message_id` if it has none. Returns
/// whether it wrote anything; the caller commits.
fn advance_in(
    tx: &StoreTransaction<'_>,
    peer: &[u8; 32],
    seq: u64,
    state: ChatEntryState,
    message_id: Option<&[u8]>,
) -> Result<bool, CoreError> {
    use ChatEntryState::*;
    let key = entry_key(peer, seq);
    let mut entry = Entry::decode(seq, &Zeroizing::new(tx.get(&key)?))?;
    let forward = matches!(
        (entry.state, state),
        (Queued, Pending | Transmitted | Delivered | NotDelivered | Cancelled)
            | (Pending, Transmitted | Delivered | NotDelivered | Cancelled)
            | (Transmitted, Delivered | NotDelivered | Cancelled)
            | (Cancelled, Delivered)
    );
    let new_id = match message_id {
        Some(id) if entry.message_id.is_empty() => Some(id.to_vec()),
        _ => None,
    };
    if !forward && new_id.is_none() {
        return Ok(false);
    }
    if forward {
        entry.state = state;
    }
    if let Some(id) = new_id {
        entry.message_id = id;
    }
    tx.put(&key, &entry.encode())?;
    if !is_open(entry.outgoing, entry.state) {
        if let Some(open) = get_opt(tx.get(&open_key(peer)))? {
            let mut open = OpenSeqs::decode(&open)?;
            open.remove(seq);
            tx.put(&open_key(peer), &open.encode())?;
        }
    }
    Ok(true)
}

/// What one local refresh of a conversation did.
#[derive(Default)]
struct Refresh {
    /// Queued texts committed to the outbox now.
    committed: u32,
    /// Queued texts that cannot be committed because there is no session
    /// that can send them.
    waiting: u32,
}

/// Sets `flag` for `peer`. Used by the network layer when the contact's
/// first message shows a conflict, and when it could not accept a
/// handshake.
pub(super) fn set_flag(
    messenger: &NetworkMessenger,
    peer: &[u8; 32],
    flag: u8,
) -> Result<(), CoreError> {
    messenger.update_meta(peer, |m| m.flags |= flag)
}

/// The contact refused our handshake with a valid refusal
/// (`NetworkMessenger::take_refusal`): our unconfirmed session with it can
/// never be accepted. Gives it up as `resolve_session_conflict` does, clears
/// a conflict flag (the contact refused this session; if it also started one
/// of its own, that conflict is raised again under the new session once the
/// contact's first message authenticates beside it), and starts a new
/// session from the contact's current bundle.
/// Texts not yet committed go out in the new session. If the new session
/// cannot be started now, the next queued text starts it.
pub(super) fn restart_after_refusal(
    messenger: &NetworkMessenger,
    peer: &[u8; 32],
    report: &mut SyncReport,
) -> Result<(), CoreError> {
    messenger.retire_unconfirmed_session(peer, "refusal")?;
    crash_point("refusal_after_remove");
    messenger.update_meta(peer, |m| m.flags &= !FLAG_CONFLICT)?;
    let started = messenger.start_session(peer.to_vec());
    crash_point("refusal_after_restart");
    match started {
        Ok(()) | Err(CoreError::SessionAlreadyExists { .. }) => Ok(()),
        Err(e) if matches!(e, CoreError::Storage { .. }) => Err(e),
        Err(e) => {
            report.errors.push(format!("restarting the session: {e}"));
            Ok(())
        }
    }
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
        self.update_known_meta(&peer, |m| m.name = name)
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
        // Only the entries after the last one seen: the cost follows what is
        // unread, not the length of the history.
        let after_seen = self.entries_in(&key, meta.seen_seq + 1, meta.last_seq)?;
        let unread = after_seen.iter().filter(|e| !e.outgoing).count() as u32;
        let last = match after_seen.last() {
            Some(e) => Some(e.public()),
            None => self.newest_before(&key, meta.last_seq, 1)?.pop().map(|e| e.public()),
        };
        Ok(Conversation {
            peer,
            name: meta.name.clone(),
            fingerprint: contact_card_fingerprint(card.encode())?,
            session: self.session_state(&key, &meta)?,
            identity_mismatch: meta.flags & FLAG_IDENTITY_MISMATCH != 0,
            handshake_refused: meta.flags & FLAG_HANDSHAKE_REFUSED != 0,
            peer_reset: meta.flags & FLAG_PEER_RESET != 0,
            note: meta.note.clone(),
            unread,
            last,
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

    /// A page of the conversation with `peer`, oldest first: the `limit`
    /// (1 to 200) entries just before `before_seq`, or the newest `limit`
    /// entries when `before_seq` is `None`. Pass the first returned entry's
    /// `seq` as `before_seq` for the page before it; an empty page means the
    /// beginning was reached. Brings the history up to date first, as
    /// [`chat_entries`](Self::chat_entries) does. Reads only the page (and,
    /// in a damaged store, the missing numbers it steps over).
    pub fn chat_entries_page(
        &self,
        peer: Vec<u8>,
        before_seq: Option<u64>,
        limit: u32,
    ) -> Result<Vec<ChatEntry>, CoreError> {
        let key = peer_key(&peer)?;
        self.require_contact(&key)?;
        if !(1..=MAX_PAGE).contains(&limit) {
            return Err(invalid("page limit must be 1 to 200"));
        }
        self.refresh(&key)?;
        let last = self.meta(&key)?.last_seq;
        let end = match before_seq {
            Some(before) => before.saturating_sub(1).min(last),
            None => last,
        };
        Ok(self
            .newest_before(&key, end, limit as usize)?
            .iter()
            .map(Entry::public)
            .collect())
    }

    /// Records the text `text` for `peer` under the application's id for it
    /// (1 to 63 bytes, unique per logical message) and, if a session exists,
    /// commits it to the outbox. Calling again with the same id returns the
    /// entry as it stands and never records or encrypts it a second time, so
    /// after an error the caller repeats the call with the same id.
    /// `sync_conversations` starts a session if none exists, and transmits.
    /// An id `send_text` used for this peer is refused (see `send_text`).
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
        // A text committed under this app id without a chat entry came from
        // `send_text` (one from before the claim record existed has no claim);
        // any later one is preceded by its claim, checked below.
        let sent_raw = self
            .core
            .prior_send(&key, &client_id::text(&app_id))?
            .is_some();
        #[cfg(test)]
        test_hooks::chat_send_before_record();
        let seq = {
            let mut store = self.core.store.lock().map_err(|_| poisoned())?;
            let tx = store.transaction()?;
            if !pinned_in(&tx, &key)? {
                return Err(CoreError::UnknownContact);
            }
            match get_opt(tx.get(&out_key(&key, &app_id)))? {
                Some(seq) => decode_seq(&seq)?,
                None if sent_raw || get_opt(tx.get(&raw_claim_key(&key, &app_id)))?.is_some() => {
                    return Err(invalid("app id already used by send_text"));
                }
                None => {
                    let mut meta = match get_opt(tx.get(&meta_key(&key)))? {
                        Some(m) => Meta::decode(&m)?,
                        None => Meta::default(),
                    };
                    meta.last_seq += 1;
                    // The user writes again: the notice of a restart by the
                    // contact has been seen.
                    meta.flags &= !FLAG_PEER_RESET;
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
                    // Not built yet: the build reads this entry with the rest.
                    if let Some(open) = get_opt(tx.get(&open_key(&key)))? {
                        let mut open = OpenSeqs::decode(&open)?;
                        open.insert(seq);
                        tx.put(&open_key(&key), &open.encode())?;
                    }
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

    /// Gives up on the outgoing text `app_id` before the peer's receipt
    /// arrived (R-15): it is never sent again, and the entry reads
    /// `Cancelled`. Nothing is claimed about the peer: a copy the relay
    /// already accepted may still reach it and be accepted there. If the
    /// peer's receipt is already here, the entry reads `Delivered` instead.
    /// A text already `Delivered`, `NotDelivered` or `Cancelled` is returned
    /// as it stands (a `Cancelled` one is upgraded if its receipt is found);
    /// repeating the call is harmless.
    ///
    /// The entry is marked first, in its own transaction, and the committed
    /// message (if any) is abandoned after that, so a `refresh` never reads
    /// the abandonment as `NotDelivered`. From the mark on, `publish_pending`
    /// never sends the text: it abandons it instead (`cancelled_text`), which
    /// also covers a crash before this call abandons it, and a text another
    /// thread commits after the mark. A round already past that check may
    /// still send it once; the Android app runs this on its sync thread,
    /// between rounds. An error after the mark leaves the entry `Cancelled`
    /// and the text unsent; calling again completes the rest.
    ///
    /// `UnknownContact` if the contact is not (or no longer) pinned; an
    /// `InvalidArgument` if the history has no outgoing text with this id.
    pub fn cancel_text(&self, peer: Vec<u8>, app_id: Vec<u8>) -> Result<ChatEntry, CoreError> {
        let key = peer_key(&peer)?;
        self.require_contact(&key)?;
        let client = client_id::text(&app_id);
        // A receipt already here makes it Delivered, not Cancelled. (One
        // that lands after this read is caught after the mark, below.)
        let before = self.core.prior_send(&key, &client)?;
        let seq = {
            let mut store = self.core.store.lock().map_err(|_| poisoned())?;
            let tx = store.transaction()?;
            if !pinned_in(&tx, &key)? {
                return Err(CoreError::UnknownContact);
            }
            let Some(seq) = get_opt(tx.get(&out_key(&key, &app_id)))? else {
                return Err(invalid("no outgoing text with this app id"));
            };
            let seq = decode_seq(&seq)?;
            let state = match before {
                Some(SendResult::AlreadyAcknowledged { .. }) => ChatEntryState::Delivered,
                _ => ChatEntryState::Cancelled,
            };
            let id = match &before {
                Some(SendResult::AlreadyAcknowledged { message_id }) => Some(message_id.as_slice()),
                _ => None,
            };
            if advance_in(&tx, &key, seq, state, id)? {
                tx.commit()?;
                crash_point("cancel_after_mark");
            }
            seq
        };
        if self.entry(&key, seq)?.state != ChatEntryState::Cancelled {
            return Ok(self.entry(&key, seq)?.public());
        }
        let mut now = self.core.prior_send(&key, &client)?;
        if let Some(SendResult::AlreadyPending { message }) = now {
            self.core.abandon_outgoing(handle_of(&key), message.message_id)?;
            crash_point("cancel_after_abandon");
            now = self.core.prior_send(&key, &client)?;
        }
        // A receipt that won the race with the mark: the record says
        // acknowledged for this entry's message (or, for a text a crash left
        // `Queued` after committing it, for the message its id committed).
        if let Some(SendResult::AlreadyAcknowledged { message_id }) = now {
            let entry = self.entry(&key, seq)?;
            if entry.message_id.is_empty() || entry.message_id == message_id {
                self.advance(&key, seq, ChatEntryState::Delivered, Some(&message_id))?;
            }
        }
        Ok(self.entry(&key, seq)?.public())
    }

    /// Resolves a session conflict (both devices started a session with each
    /// other) on the one device allowed to: the one whose identity key is
    /// the greater. The conflict was recorded when the peer's first message
    /// under its own handshake authenticated here: the peer started a
    /// session of its own (or that message was replayed from one it has
    /// since given up, docs/NET-MESSAGING.md section 8). It marks the texts
    /// it committed to its own session
    /// `NotDelivered` (the peer dropped that session's messages and never
    /// accepts it), abandons them, removes that session, and waits for the
    /// peer's, which the peer keeps retransmitting. Texts not yet committed
    /// when the session is removed stay queued and go out in the peer's
    /// session; a text the history commits to our session before that (also
    /// one sent while this runs) is abandoned with it and ends `NotDelivered`.
    /// Every step repeats safely after a crash; calling it again completes it.
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
                return self.update_known_meta(&key, |m| m.flags &= !FLAG_CONFLICT);
            }
            self.update_known_meta(&key, |m| m.flags |= FLAG_ACCEPT_ONLY)?;
            self.retire_unconfirmed_session(&key, "resolve")?;
        }
        self.update_known_meta(&key, |m| {
            m.flags = (m.flags | FLAG_ACCEPT_ONLY) & !FLAG_CONFLICT;
            m.note.clear();
        })
    }

    /// Starts the secure session with `peer` again, on the user's request
    /// (option B; `docs/NET-MESSAGING.md` section 10, "Reset"). The session
    /// this device holds with the contact, in any state but a conflict
    /// (`resolve_session_conflict` is for that), is given up: texts committed
    /// to it are marked `NotDelivered` and abandoned, and it is removed; a
    /// handshake the contact sent beside it is kept. The next round
    /// (`sync_conversations`) starts a new session from the contact's current
    /// bundle, also with no text queued. The contact replaces its own copy of
    /// the old session once this device's first message under the new one
    /// authenticates there. Until then texts sent here go out on the new
    /// session and wait for it, and what the contact sends under the old
    /// session cannot be read here: the contact's texts read `NotDelivered`
    /// there once it replaces the session. Texts marked `NotDelivered` are
    /// not sent again (the user can send them again). A commit on the
    /// session whose outcome is unknown is settled first, as a round does,
    /// and a text `chat_send` commits on another thread while the session
    /// is given up is given up with it. A session whose record cannot be
    /// read is refused (`InvalidSession`), with nothing changed: delete the
    /// contact instead. The contact's device must run a build with option
    /// B; until it does, the restart waits, and once it does the restart is
    /// refused once and made again, so texts written meanwhile read
    /// `NotDelivered` (`docs/NET-MESSAGING.md` section 10, "Reset"). Every step repeats safely after a crash, but a
    /// process death part way is not completed by itself: calling it again
    /// completes it. Works without a connection.
    pub fn reset_session(&self, peer: Vec<u8>) -> Result<(), CoreError> {
        let key = peer_key(&peer)?;
        self.require_contact(&key)?;
        if self.meta(&key)?.flags & FLAG_CONFLICT != 0 {
            return Err(invalid("resolve the session conflict instead"));
        }
        let handle = handle_of(&key);
        // The removal is refused while a commit has an unknown outcome.
        self.core.recover_if_unresolved(handle)?;
        if self.core.has_session(handle)? {
            // A session record that cannot be read is refused by the
            // removal; refuse it here, before any text is given up.
            self.confirmed(handle)?;
            // The request to start again is written with the removal, so
            // a crash cannot leave the session gone and nothing started. A
            // text committed after the abandon pass makes the removal fail;
            // one more pass gives it up too.
            match self.retire_session_texts(&key, "reset", Retire::Any, Some(&restart_requested)) {
                Err(CoreError::PendingOutgoing { .. }) => {
                    self.retire_session_texts(&key, "reset", Retire::Any, Some(&restart_requested))?
                }
                other => other?,
            }
        }
        crash_point("reset_after_retire");
        // With no session there was nothing to remove: only the request.
        self.update_known_meta(&key, restart_requested)
    }

    /// Deletes the contact `peer` and everything this device keeps for it,
    /// in one store transaction: the pinned card, its name and flags, the
    /// whole conversation history, the session in whatever state it is
    /// (established, unconfirmed, in conflict, unreadable or absent), both
    /// handshakes, the pending outgoing texts (marked abandoned, so never
    /// shown or counted as delivered) and the incoming messages not yet
    /// taken into the history. The records that detect repeats (`seen:`,
    /// `sendid:`) stay: nothing already received becomes new, and no logical
    /// id is encrypted twice (`Messenger::forget_peer`).
    ///
    /// Texts not yet delivered are lost. The peer is told nothing and keeps
    /// its session; if the contact is added again and a text is sent, the
    /// new session replaces the peer's as after a reset (option B). To start
    /// a new session with a contact who stays, use `reset_session`.
    ///
    /// The contact need not be pinned: deleting again removes whatever is
    /// left. Refused if the contact's session handle is registered to
    /// another identity (`SessionIdCollision`).
    ///
    /// A chat record is written only in a transaction that finds the card
    /// still pinned, so no call that read the contact before the delete
    /// writes its history, flags or indexes after it. A `sync_conversations`
    /// round in flight can still act on the durable layer for the contact
    /// (for example start a session) after it; so do not run the two
    /// concurrently. The Android app runs both on its one sync thread.
    pub fn delete_contact(&self, peer: Vec<u8>) -> Result<(), CoreError> {
        let key = peer_key(&peer)?;
        let handle = handle_of(&key);
        // Forgetting is refused while a commit on the handle has an unknown
        // outcome; establish what the store holds first, as a round does.
        self.core.recover_if_unresolved(handle)?;
        {
            let (mut store, mut messenger) = self.core.lock()?;
            let mut also = vec![
                contact_key(&key),
                meta_key(&key),
                open_key(&key),
                accepted_handshake_key(&key),
                crate::network::far_wait_key(handle),
            ];
            also.extend(store.list_keys_with_prefix(&entry_namespace(&key))?);
            // Each index key with an empty last part is this contact's prefix
            // in a namespace shared by all contacts.
            for prefix in [out_key(&key, &[]), raw_claim_key(&key, &[]), in_key(&key, &[])] {
                let namespace = &prefix[..=prefix.find(':').expect("a namespaced key")];
                also.extend(
                    store
                        .list_keys_with_prefix(namespace)?
                        .into_iter()
                        .filter(|k| k.starts_with(&prefix)),
                );
            }
            messenger
                .forget_peer(&mut store, handle, &key, &also)
                .map_err(|e| CoreError::messaging(handle, e))?;
        }
        // In-memory state kept per contact. `last_sent` is keyed by message
        // id: its entries for this contact are never consulted again, and
        // the next round drops them (`prune_sent`).
        self.refused.lock().expect("refused").remove(&key);
        // A new session with this contact has the same handle; its stored
        // waits went with the rest.
        self.far_waits_deleted(handle);
        let mut refusals = self.refusals.lock().expect("refusals");
        refusals.queued.retain(|(to, _, _)| *to != key);
        refusals.last_to.remove(&key);
        Ok(())
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
                // A session the peer has authenticated a message on (the
                // peer's, accepted here, or ours, confirmed by the peer) ends a
                // conflict and the wait for it. Our own unconfirmed one does
                // not: `resolve_session_conflict` may be removing it.
                let peers_session = self.confirmed(handle)?;
                self.update_meta(peer, |m| {
                    m.flags &= !(FLAG_IDENTITY_MISMATCH | FLAG_HANDSHAKE_REFUSED | FLAG_RESTART);
                    if peers_session {
                        m.flags &= !(FLAG_CONFLICT | FLAG_ACCEPT_ONLY);
                    }
                    m.note.clear();
                })?;
                continue;
            }
            let flags = self.meta(peer)?.flags;
            if (refresh.waiting == 0 && flags & FLAG_RESTART == 0) || flags & FLAG_ACCEPT_ONLY != 0 {
                continue;
            }
            match self.start_session(peer.to_vec()) {
                Ok(()) => {
                    started = true;
                    self.update_meta(peer, |m| {
                        m.flags &= !(FLAG_IDENTITY_MISMATCH | FLAG_RESTART);
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

    /// Gives up our own unconfirmed session with `peer`: marks the texts
    /// committed to it `NotDelivered`, abandons them and removes the
    /// session (S2-B2 section 6a: nothing was received on it). Marked before
    /// anything leaves the outbox: a text committed after the marking pass
    /// is abandoned unmarked, and `refresh` then reads the abandonment from
    /// its send record, never a receipt. Every step repeats safely after a
    /// crash. `stage` names its crash points (`{stage}_after_mark`,
    /// `{stage}_after_abandon`).
    fn retire_unconfirmed_session(&self, peer: &[u8; 32], stage: &str) -> Result<(), CoreError> {
        self.retire_session_texts(peer, stage, Retire::Unconfirmed, None)
    }

    /// The contact restarted the session (option B): its first message under
    /// the handshake recorded beside our established session authenticated
    /// there (`NetworkMessenger::take_message`). Gives our session up as
    /// `reset_session` does: texts committed to it `NotDelivered`, abandoned,
    /// the session removed, the recorded handshake kept; and records for the
    /// user that the contact restarted it, in the transaction that removes
    /// the session. The caller then reads the message again, as the first
    /// one of that handshake, which creates the new session. Every step
    /// repeats safely after a crash: the message stays on the relay until it
    /// is accepted, and the contact retransmits it until our receipt.
    pub(super) fn accept_restart(&self, peer: &[u8; 32], handle: u64) -> Result<(), CoreError> {
        debug_assert_eq!(handle, handle_of(peer));
        let note = |m: &mut Meta| m.flags = (m.flags | FLAG_PEER_RESET) & !FLAG_RESTART;
        self.retire_session_texts(peer, "restart", Retire::Any, Some(&note))
    }

    /// Gives up our session with `peer` (`retire_unconfirmed_session`,
    /// `reset_session`, `accept_restart`): marks the texts committed to it
    /// `NotDelivered`, abandons them and removes the session, only an
    /// unconfirmed one with [`Retire::Unconfirmed`] (S2-B2 section 6a), any
    /// with [`Retire::Any`], which keeps a handshake recorded beside it.
    /// With `Retire::Any`, `note` changes the contact's meta in the
    /// transaction that removes the session, so the change and the removal
    /// happen together or not at all.
    fn retire_session_texts(
        &self,
        peer: &[u8; 32],
        stage: &str,
        retire: Retire,
        note: Option<&dyn Fn(&mut Meta)>,
    ) -> Result<(), CoreError> {
        let handle = handle_of(peer);
        // A text whose receipt was committed earlier in this round, before
        // `refresh` read it, is Delivered, not given up: the receipt left
        // only its send record (`refresh` reads it the same way).
        let pending: HashSet<Vec<u8>> = self
            .core
            .pending_outgoing(handle)?
            .into_iter()
            .map(|m| m.message_id)
            .collect();
        for e in self.open_entries(peer)? {
            if e.outgoing
                && matches!(
                    e.state,
                    ChatEntryState::Pending | ChatEntryState::Transmitted
                )
            {
                let acknowledged = !pending.contains(&e.message_id)
                    && matches!(
                        self.core.prior_send(peer, &client_id::text(&e.app_id))?,
                        Some(SendResult::AlreadyAcknowledged { message_id }) if message_id == e.message_id
                    );
                let state = if acknowledged {
                    ChatEntryState::Delivered
                } else {
                    ChatEntryState::NotDelivered
                };
                self.advance(peer, e.seq, state, None)?;
            }
        }
        #[cfg(test)]
        test_hooks::between_resolve_passes();
        crash_point(&format!("{stage}_after_mark"));
        for m in self.core.pending_outgoing(handle)? {
            self.core.abandon_outgoing(handle, m.message_id)?;
        }
        crash_point(&format!("{stage}_after_abandon"));
        #[cfg(test)]
        test_hooks::before_retire();
        match retire {
            Retire::Unconfirmed => self.core.remove_session(handle)?,
            Retire::Any => {
                // Any write to the meta between reading it and the removal
                // (a new entry, a text marked seen, a rename on another
                // thread) fails the removal's precondition with nothing
                // written; the meta is then read again.
                let mut tries = 0;
                loop {
                    let extra = match note {
                        Some(f) => vec![self.meta_write(peer, f)?],
                        None => Vec::new(),
                    };
                    #[cfg(test)]
                    test_hooks::between_meta_and_retire();
                    if self.core.retire_session(handle, &extra)? {
                        break;
                    }
                    tries += 1;
                    if tries == 3 {
                        return Err(CoreError::Storage {
                            msg: "the contact's record kept changing while the session was given up; \
                                  try again"
                                .into(),
                        });
                    }
                }
            }
        }
        // The next session with this contact has the same handle.
        self.forget_far_waits(handle);
        Ok(())
    }

    /// `peer`'s meta changed by `f`, as a write that commits only if the
    /// meta is still what was read here (for `retire_session_texts`).
    fn meta_write(&self, peer: &[u8; 32], f: &dyn Fn(&mut Meta)) -> Result<SideWrite, CoreError> {
        let store = self.core.store.lock().map_err(|_| poisoned())?;
        let key = meta_key(peer);
        let old = get_opt(store.get(&key))?;
        let mut meta = match &old {
            Some(bytes) => Meta::decode(bytes)?,
            None => Meta::default(),
        };
        f(&mut meta);
        let new = Zeroizing::new(meta.encode());
        let write = match old {
            Some(bytes) => SideWrite::replace(key, Zeroizing::new(bytes), new),
            None => SideWrite::insert(key, new),
        };
        write.map_err(|_| CoreError::Storage {
            msg: "chat meta key is reserved".into(),
        })
    }

    fn meta(&self, peer: &[u8; 32]) -> Result<Meta, CoreError> {
        let store = self.core.store.lock().map_err(|_| poisoned())?;
        match get_opt(store.get(&meta_key(peer)))? {
            Some(m) => Meta::decode(&m),
            None => Ok(Meta::default()),
        }
    }

    /// Changes `peer`'s meta in one transaction. Writes nothing once `peer` is
    /// no longer a contact (deleted meanwhile), and reports that as success:
    /// for background writers. User actions use [`Self::update_known_meta`].
    fn update_meta(&self, peer: &[u8; 32], f: impl FnOnce(&mut Meta)) -> Result<(), CoreError> {
        self.write_meta(peer, f).map(|_| ())
    }

    /// As [`Self::update_meta`], but a contact deleted meanwhile is
    /// `UnknownContact`, with nothing written.
    fn update_known_meta(&self, peer: &[u8; 32], f: impl FnOnce(&mut Meta)) -> Result<(), CoreError> {
        match self.write_meta(peer, f)? {
            true => Ok(()),
            false => Err(CoreError::UnknownContact),
        }
    }

    /// Whether `peer` is a contact; its meta changed by `f` if so.
    fn write_meta(&self, peer: &[u8; 32], f: impl FnOnce(&mut Meta)) -> Result<bool, CoreError> {
        let mut store = self.core.store.lock().map_err(|_| poisoned())?;
        let tx = store.transaction()?;
        if !pinned_in(&tx, peer)? {
            return Ok(false);
        }
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
        Ok(true)
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

    /// The entries of `peer` numbered `first..=last` that exist, by key,
    /// oldest first (none if `first > last`).
    ///
    /// Entries are numbered without gaps and never deleted, so a number is
    /// missing only from a damaged store. A missing number is skipped rather
    /// than failing the read, which would otherwise fail the conversation
    /// list and every round (R-10). An entry that exists but cannot be read
    /// is still an error.
    fn entries_in(&self, peer: &[u8; 32], first: u64, last: u64) -> Result<Vec<Entry>, CoreError> {
        let store = self.core.store.lock().map_err(|_| poisoned())?;
        let mut out = Vec::new();
        for seq in first.max(1)..=last {
            if let Some(bytes) = get_opt(store.get(&entry_key(peer, seq)))? {
                out.push(Entry::decode(seq, &Zeroizing::new(bytes))?);
            }
        }
        Ok(out)
    }

    /// Up to `limit` entries of `peer` that exist, numbered `last` or lower,
    /// oldest first: the newest ones, walking back over missing numbers as
    /// [`entries_in`](Self::entries_in) skips them. Without gaps this is
    /// exactly `last - limit + 1 ..= last` (from 1).
    fn newest_before(&self, peer: &[u8; 32], last: u64, limit: usize) -> Result<Vec<Entry>, CoreError> {
        let store = self.core.store.lock().map_err(|_| poisoned())?;
        let mut out = Vec::new();
        let mut seq = last;
        while seq >= 1 && out.len() < limit {
            if let Some(bytes) = get_opt(store.get(&entry_key(peer, seq)))? {
                out.push(Entry::decode(seq, &Zeroizing::new(bytes))?);
            }
            seq -= 1;
        }
        out.reverse();
        Ok(out)
    }

    /// `peer`'s outgoing entries that are not final yet, oldest first. Builds
    /// the open-entry record first if this history has none (written before
    /// it existed): one transaction reads every entry by seq and writes it,
    /// so no entry change can fall between the two.
    fn open_entries(&self, peer: &[u8; 32]) -> Result<Vec<Entry>, CoreError> {
        let seqs = self.open_seqs(peer)?;
        let store = self.core.store.lock().map_err(|_| poisoned())?;
        let mut out = Vec::with_capacity(seqs.0.len());
        for seq in seqs.0 {
            // A missing entry (damaged store) cannot be advanced: skipped.
            let Some(bytes) = get_opt(store.get(&entry_key(peer, seq)))? else {
                continue;
            };
            let e = Entry::decode(seq, &Zeroizing::new(bytes))?;
            // Defensive: the record and the entry change in one transaction.
            if is_open(e.outgoing, e.state) {
                out.push(e);
            }
        }
        Ok(out)
    }

    fn open_seqs(&self, peer: &[u8; 32]) -> Result<OpenSeqs, CoreError> {
        let mut store = self.core.store.lock().map_err(|_| poisoned())?;
        if let Some(open) = get_opt(store.get(&open_key(peer)))? {
            return OpenSeqs::decode(&open);
        }
        let tx = store.transaction()?;
        if let Some(open) = get_opt(tx.get(&open_key(peer)))? {
            return OpenSeqs::decode(&open);
        }
        // Deleted meanwhile: nothing to build, nothing written.
        if !pinned_in(&tx, peer)? {
            return Ok(OpenSeqs::default());
        }
        let last = match get_opt(tx.get(&meta_key(peer)))? {
            Some(m) => Meta::decode(&m)?.last_seq,
            None => 0,
        };
        let mut open = OpenSeqs::default();
        for seq in 1..=last {
            // A missing number (damaged store) is skipped, as by `entries_in`.
            let Some(bytes) = get_opt(tx.get(&entry_key(peer, seq)))? else {
                continue;
            };
            let e = Entry::decode(seq, &Zeroizing::new(bytes))?;
            if is_open(e.outgoing, e.state) {
                open.0.push(seq);
            }
        }
        tx.put(&open_key(peer), &open.encode())?;
        tx.commit()?;
        crash_point("chat_after_open_build");
        Ok(open)
    }

    /// Moves entry `seq` forward to `state` (never back: a stale caller
    /// cannot undo a receipt) and records its message id if it has none.
    ///
    /// Forward is `Queued → Pending → Transmitted → Delivered`, from any of
    /// the first three to `NotDelivered` or `Cancelled`, and from `Cancelled`
    /// to `Delivered` (the peer's receipt is a fact; a cancel only stops
    /// sending); a step may skip states. Skips
    /// happen when the stored state lags what the durable layer already
    /// holds: a `Queued` entry whose commit ran before a crash comes back from
    /// `send_text` as pending, delivered or abandoned, and a `Pending` one
    /// whose receipt arrived before the relay's acceptance was seen here goes
    /// straight to `Delivered`. `Received` entries never change.
    fn advance(
        &self,
        peer: &[u8; 32],
        seq: u64,
        state: ChatEntryState,
        message_id: Option<&[u8]>,
    ) -> Result<(), CoreError> {
        let mut store = self.core.store.lock().map_err(|_| poisoned())?;
        let tx = store.transaction()?;
        if !pinned_in(&tx, peer)? {
            return Ok(());
        }
        if advance_in(&tx, peer, seq, state, message_id)? {
            tx.commit()?;
        }
        Ok(())
    }

    /// Whether the history entry of the text committed under `app_id` reads
    /// `Cancelled`. `publish_pending` asks before sending each text, and
    /// abandons a cancelled one instead: so a cancelled text is never sent
    /// again, whoever committed it and whenever (a crash between
    /// `cancel_text`'s mark and its abandoning, or a `refresh` on another
    /// thread that read the entry as `Queued` before the mark and committed
    /// it after). A text `send_text` committed has no entry; a missing entry
    /// (damaged store) reads as not cancelled.
    pub(super) fn cancelled_text(&self, peer: &[u8; 32], app_id: &[u8]) -> Result<bool, CoreError> {
        let store = self.core.store.lock().map_err(|_| poisoned())?;
        let Some(seq) = get_opt(store.get(&out_key(peer, app_id)))? else {
            return Ok(false);
        };
        let seq = decode_seq(&seq)?;
        Ok(match get_opt(store.get(&entry_key(peer, seq)))? {
            Some(bytes) => Entry::decode(seq, &Zeroizing::new(bytes))?.state == ChatEntryState::Cancelled,
            None => false,
        })
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
        if !pinned_in(&tx, peer)? {
            return Ok(());
        }
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

    /// Takes `app_id` for `send_text` (see [`raw_claim_key`]); refused if a
    /// chat entry has it. Repeating it is harmless.
    pub(super) fn claim_for_send_text(&self, peer: &[u8; 32], app_id: &[u8]) -> Result<(), CoreError> {
        let mut store = self.core.store.lock().map_err(|_| poisoned())?;
        let tx = store.transaction()?;
        if !pinned_in(&tx, peer)? {
            return Err(CoreError::UnknownContact);
        }
        if get_opt(tx.get(&out_key(peer, app_id)))?.is_some() {
            return Err(invalid("app id already used by the chat history"));
        }
        if get_opt(tx.get(&raw_claim_key(peer, app_id)))?.is_none() {
            tx.put(&raw_claim_key(peer, app_id), &[])?;
            tx.commit()?;
        }
        Ok(())
    }

    /// Brings the history of `peer` up to date with the local stores. No
    /// network I/O.
    fn refresh(&self, peer: &[u8; 32]) -> Result<Refresh, CoreError> {
        let mut result = Refresh::default();
        let handle = handle_of(peer);
        // Committing a queued text below is a send, refused while the
        // session is unresolved. This runs before `sync` in a round and on
        // every `chat_send` and `chat_entries`, so recovery cannot wait for
        // the next received message.
        self.core.recover_if_unresolved(handle)?;
        let has_session = self.core.has_session(handle)?;
        if has_session {
            // Received texts: into the history, then marked read.
            for (message_id, text) in self.pending_texts(peer)? {
                self.record_incoming(peer, &message_id, text)?;
                crash_point("chat_after_record");
                self.mark_read(peer.to_vec(), message_id.to_vec())?;
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
        // A responder session an older build stored on receipt of a
        // handshake cannot encrypt until the peer's first message arrives,
        // and may yet be retired for a newer handshake
        // (docs/S2-B2-DURABLE-MESSAGING.md, section 4b). Texts wait for a
        // session that can send them, as with no session.
        let can_send = has_session && !self.core.is_legacy_unconfirmed(handle)?;
        for e in self.open_entries(peer)? {
            if !e.outgoing {
                continue;
            }
            match e.state {
                ChatEntryState::Queued if can_send => {
                    // Same id as recorded: returns the committed message if
                    // an earlier attempt got this far. The text moves out of
                    // the entry, still in its wiping owner.
                    let sent = self.send_committed_text(peer, &e.app_id, e.text)?;
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
                // Out of the outbox: the send record says why. Acknowledged
                // (the peer's receipt) is Delivered, abandoned NotDelivered;
                // anything else, including a record for another message,
                // changes nothing. Absence alone is never read as a receipt:
                // a text committed while `resolve_session_conflict` runs is
                // abandoned after that call's NotDelivered pass. The record
                // is the peer's, so this holds with no session too.
                ChatEntryState::Pending | ChatEntryState::Transmitted => {
                    if !pending.contains(&e.message_id) {
                        // The id comparison is defensive: an entry is linked
                        // to the message its own client id committed, so no
                        // test reaches a mismatch (a history adopted from a
                        // `send_text` before claims existed matches, too).
                        let state = match self.core.prior_send(peer, &client_id::text(&e.app_id))? {
                            Some(SendResult::AlreadyAcknowledged { message_id })
                                if message_id == e.message_id =>
                            {
                                Some(ChatEntryState::Delivered)
                            }
                            Some(SendResult::Abandoned { message_id }) if message_id == e.message_id => {
                                Some(ChatEntryState::NotDelivered)
                            }
                            _ => None,
                        };
                        if let Some(state) = state {
                            self.advance(peer, e.seq, state, None)?;
                        }
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
        // Established only by a message from the peer that authenticated
        // and was committed here — never by a received handshake alone.
        if self.confirmed(handle)? {
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

#[cfg(test)]
impl NetworkMessenger {
    /// Test aid: the open-entry record of `peer` (building it if absent) and
    /// what a full scan of the history says it should hold.
    pub(crate) fn open_record_and_scan(&self, peer: &[u8]) -> (Vec<u64>, Vec<u64>) {
        let peer = peer_key(peer).unwrap();
        let record = self.open_seqs(&peer).unwrap().0;
        let scan = self
            .entries(&peer)
            .unwrap()
            .into_iter()
            .filter(|e| is_open(e.outgoing, e.state))
            .map(|e| e.seq)
            .collect();
        (record, scan)
    }

    /// Test aid: removes the open-entry record of `peer`, as in a history a
    /// build before the record wrote.
    pub(crate) fn drop_open_record(&self, peer: &[u8]) {
        let peer = peer_key(peer).unwrap();
        let store = self.core.store.lock().unwrap();
        store.delete(&open_key(&peer)).unwrap();
    }

    /// Test aid: removes entry `seq` of `peer`, as only a damaged store
    /// could (R-10).
    pub(crate) fn drop_entry(&self, peer: &[u8], seq: u64) {
        let peer = peer_key(peer).unwrap();
        let store = self.core.store.lock().unwrap();
        store.delete(&entry_key(&peer, seq)).unwrap();
    }

    pub(crate) fn has_open_record(&self, peer: &[u8]) -> bool {
        let peer = peer_key(peer).unwrap();
        let store = self.core.store.lock().unwrap();
        get_opt(store.get(&open_key(&peer))).unwrap().is_some()
    }
}

#[cfg(test)]
pub(crate) mod test_hooks {
    use std::cell::RefCell;

    thread_local! {
        static BETWEEN: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
        static BEFORE_RECORD: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
        static BEFORE_RETIRE: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
        static META_RETIRE: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    }

    /// Runs `f` once, on this thread, in the next `chat_send` on this thread
    /// after its check for a text `send_text` committed and before the
    /// transaction that records the entry.
    pub(crate) fn set_chat_send_before_record(f: impl FnOnce() + 'static) {
        BEFORE_RECORD.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    pub(super) fn chat_send_before_record() {
        if let Some(f) = BEFORE_RECORD.with(|h| h.borrow_mut().take()) {
            f();
        }
    }

    /// Runs `f` once, on this thread, in the next session given up on this
    /// thread with a meta change, after the meta was read and before the
    /// removal that writes it.
    pub(crate) fn set_between_meta_and_retire(f: impl FnOnce() + 'static) {
        META_RETIRE.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    pub(super) fn between_meta_and_retire() {
        if let Some(f) = META_RETIRE.with(|h| h.borrow_mut().take()) {
            f();
        }
    }

    /// Runs `f` once, on this thread, after the abandon pass of the next
    /// session given up on this thread (`reset_session`, a resolution, a
    /// refusal or a restart) and before the session is removed.
    pub(crate) fn set_before_retire(f: impl FnOnce() + 'static) {
        BEFORE_RETIRE.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    pub(super) fn before_retire() {
        if let Some(f) = BEFORE_RETIRE.with(|h| h.borrow_mut().take()) {
            f();
        }
    }

    /// Runs `f` once, on this thread, between the NotDelivered pass and the
    /// abandon pass of the next `resolve_session_conflict` on this thread:
    /// a deterministic stand-in for another thread's call landing there.
    pub(crate) fn set_between_resolve_passes(f: impl FnOnce() + 'static) {
        BETWEEN.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    pub(super) fn between_resolve_passes() {
        if let Some(f) = BETWEEN.with(|h| h.borrow_mut().take()) {
            f();
        }
    }
}
