//! Staged ratchet transitions with an explicit, conditional commit boundary.
//!
//! The live message path reaches this module through
//! [`crate::messaging::Messenger`], which commits each transition together
//! with its outbox or inbox record ([`DurableSession::commit_with`]).
//!
//! A transition (one encrypt or one decrypt) runs on an independent copy of
//! the ratchet. The copy's new state is encoded, and only once the store
//! reports that record as committed is the copy installed and the operation's
//! output (ciphertext or plaintext) handed out. Until then the installed state
//! is untouched and the output is withheld, so no output is released before
//! the store has reported the state that produced it as committed.
//!
//! # Conditional writes
//!
//! Every write is a compare-and-update performed by the store inside one S1
//! transaction (`BEGIN IMMEDIATE` … `COMMIT`): creating a session requires
//! that no record exists, and a transition requires that the stored record is
//! the predecessor this instance holds — same binding, same role, same
//! generation. Because the check runs inside the write transaction, another
//! connection cannot write between the check and the replacement. A failed
//! check is a [`Conflict`]: nothing is written, the staged state and its output
//! are discarded, and the instance refuses further transitions. There is no
//! automatic reload or retry.
//!
//! The store interface is sealed: [`S1CheckpointStore`] is its only
//! implementation outside this crate's tests, so callers cannot substitute a
//! store that skips the check. Sealing constrains implementations, not
//! calls: code outside this crate that holds a `T: CheckpointStore` can call
//! its `read` (which returns the same bytes `EncryptedStore::get` would), but
//! not its conditional write, whose precondition type cannot be named or
//! built there.
//!
//! The conditional write protects only writes made through this module. The
//! S1 [`EncryptedStore`] a caller passes in keeps its own public `get`, `put`
//! and `delete`: a caller can read a raw session record (and rebuild an
//! independent ratchet from it), or overwrite the record unconditionally,
//! including with an older one. A live instance detects such an overwrite as
//! a [`Conflict`] on its next commit; a session loaded afterwards starts from
//! whatever was written.
//!
//! When the store cannot say whether a write took effect, the instance
//! becomes *unresolved* and refuses every further transition. There is no
//! resolution rule here. In particular, reading back an older record does not
//! show that the attempted write never happened.
//!
//! # What this does not provide
//!
//! - Power-loss durability: a reported commit is as durable as the store's
//!   configuration makes it.
//! - Rollback protection: an older copy of the database file is accepted, and
//!   a session loaded from it continues from the older generation.
//! - Persistence of the unresolved or conflicted state: both live only in the
//!   instance. A new instance loaded from the store starts from whatever the
//!   store holds.
//! - A global guarantee against competing ciphertexts. [`DurableSession`] never
//!   exposes its ratchet, so its own operations cannot fork state. But
//!   `DoubleRatchet` and its checkpoint and copy functions are public in
//!   `core-crypto`, and Rust visibility cannot limit them to this crate: a
//!   `DoubleRatchet` owned elsewhere, or one rebuilt from a record by code
//!   holding the store key, can still produce ciphertexts outside this
//!   mechanism.

use std::sync::atomic::{AtomicU64, Ordering};

use core_crypto::ratchet::{DoubleRatchet, Header, RatchetError};
use core_storage::{EncryptedStore, StorageError};
use zeroize::Zeroizing;

use crate::checkpoint::{
    decode_session_checkpoint, encode_parts, encode_session_checkpoint, session_storage_key,
    SessionBinding, SessionCheckpointError, SessionRole,
};
use crate::Session;

use sealed::{Current, Expect, Store, Write, WriteFailure};

mod sealed {
    use super::*;

    /// What a conditional write requires of the stored record.
    pub enum Expect<'a> {
        /// No record may exist.
        Absent,
        /// The stored record must be this session's record at `generation`.
        Predecessor {
            generation: u64,
            role: SessionRole,
            binding: &'a SessionBinding,
        },
        /// The stored record must be exactly these bytes.
        Exactly(&'a [u8]),
    }

    /// One write in a conditional batch: `value` replaces the record at
    /// `key` only if `expect` holds for it.
    pub struct Write<'a> {
        pub key: &'a str,
        pub expect: Expect<'a>,
        pub value: &'a [u8],
    }

    /// The stored record as seen inside the write transaction.
    pub enum Current<'a> {
        Missing,
        /// A row exists but the store could not authenticate it.
        Unreadable,
        Present(&'a [u8]),
    }

    pub enum WriteFailure {
        /// The precondition of `writes[index]` did not hold; nothing was
        /// written.
        Conflict { index: usize, conflict: Conflict },
        /// No record was stored.
        NotCommitted(StorageError),
        /// The records may or may not have been stored.
        OutcomeUnknown(StorageError),
    }

    /// The operations behind [`CheckpointStore`](super::CheckpointStore).
    /// Unnameable outside this crate, so it cannot be implemented there.
    pub trait Store {
        /// `Ok(None)` only when no record exists under `key`.
        fn read(&mut self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError>;

        /// Checks every write's precondition against the stored records and,
        /// only if all hold, applies every write — atomically: all or none.
        fn write_conditional(&mut self, writes: &[Write<'_>]) -> Result<(), WriteFailure>;
    }
}

/// A store for session checkpoints. Sealed: implemented only by
/// [`S1CheckpointStore`].
///
/// ```compile_fail,E0277
/// struct Unchecked;
/// impl core_protocol::durable::CheckpointStore for Unchecked {}
/// ```
pub trait CheckpointStore: Store {}

/// The production store: session checkpoints in an S1 [`EncryptedStore`],
/// whose AEAD (with the key name as associated data) provides their
/// confidentiality and integrity.
///
/// Each write is one `BEGIN IMMEDIATE` transaction that reads the current
/// record, checks the precondition and only then puts the new one. A failure
/// before `commit` rolls the transaction back as it is dropped, so nothing is
/// written. Any error from `commit` is reported as an unknown outcome,
/// because S1 documents that it can arrive after the commit point.
pub struct S1CheckpointStore<'a> {
    store: &'a mut EncryptedStore,
}

impl<'a> S1CheckpointStore<'a> {
    pub fn new(store: &'a mut EncryptedStore) -> Self {
        Self { store }
    }
}

impl Store for S1CheckpointStore<'_> {
    fn read(&mut self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        match self.store.get(key) {
            Ok(v) => Ok(Some(Zeroizing::new(v))),
            Err(StorageError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn write_conditional(&mut self, writes: &[Write<'_>]) -> Result<(), WriteFailure> {
        let tx = self
            .store
            .transaction()
            .map_err(WriteFailure::NotCommitted)?;
        // Every precondition is checked before anything is written. On a
        // conflict or any error below, `tx` is dropped and rolled back.
        for (index, w) in writes.iter().enumerate() {
            // Err(true): a row exists but fails authentication; Err(false): none.
            let stored = match tx.get(w.key) {
                Ok(v) => Ok(Zeroizing::new(v)),
                Err(StorageError::NotFound) => Err(false),
                Err(StorageError::Decryption) => Err(true),
                Err(e) => return Err(WriteFailure::NotCommitted(e)),
            };
            let current = match &stored {
                Ok(v) => Current::Present(v),
                Err(false) => Current::Missing,
                Err(true) => Current::Unreadable,
            };
            check_precondition(current, &w.expect)
                .map_err(|conflict| WriteFailure::Conflict { index, conflict })?;
        }
        for w in writes {
            tx.put(w.key, w.value).map_err(WriteFailure::NotCommitted)?;
        }
        #[cfg(test)]
        {
            test_hooks::crash_point("before_commit");
            if let Some(fault) = test_hooks::take_fault() {
                return test_hooks::apply(fault, tx);
            }
        }
        let r = tx.commit().map_err(WriteFailure::OutcomeUnknown);
        #[cfg(test)]
        test_hooks::crash_point("after_commit");
        r
    }
}

impl CheckpointStore for S1CheckpointStore<'_> {}

/// Why a conditional write was refused. Nothing was written.
#[derive(Debug)]
pub enum Conflict {
    /// Creating a session, but a record (valid or not) already exists.
    RecordExists,
    /// Replacing a session record, but none is stored.
    RecordMissing,
    /// A row exists but the store could not authenticate it.
    StoredRecordUnreadable,
    /// The stored record is malformed or unsupported.
    StoredRecordInvalid(SessionCheckpointError),
    /// The stored record is bound to other identities.
    BindingMismatch(SessionCheckpointError),
    /// The stored record is for the other X3DH role.
    RoleMismatch,
    /// The stored record is at another generation: another instance has
    /// written since this one loaded, or the store was rolled back.
    GenerationMismatch { expected: u64, found: u64 },
    /// A record required to be byte-identical to what the caller read has
    /// changed since.
    RecordChanged,
}

/// Decides whether `current` satisfies `expect`. Runs inside the store's
/// write transaction.
fn check_precondition(current: Current<'_>, expect: &Expect<'_>) -> Result<(), Conflict> {
    match (expect, current) {
        (Expect::Absent, Current::Missing) => Ok(()),
        (Expect::Absent, _) => Err(Conflict::RecordExists),
        (Expect::Exactly(_), Current::Missing) => Err(Conflict::RecordMissing),
        (Expect::Exactly(_), Current::Unreadable) => Err(Conflict::StoredRecordUnreadable),
        (Expect::Exactly(want), Current::Present(have)) => {
            if have == *want {
                Ok(())
            } else {
                Err(Conflict::RecordChanged)
            }
        }
        (Expect::Predecessor { .. }, Current::Missing) => Err(Conflict::RecordMissing),
        (Expect::Predecessor { .. }, Current::Unreadable) => Err(Conflict::StoredRecordUnreadable),
        (
            Expect::Predecessor {
                generation,
                role,
                binding,
            },
            Current::Present(bytes),
        ) => {
            let found = decode_session_checkpoint(bytes, binding).map_err(|e| match e {
                SessionCheckpointError::OurIdentityMismatch
                | SessionCheckpointError::PeerIdentityMismatch => Conflict::BindingMismatch(e),
                e => Conflict::StoredRecordInvalid(e),
            })?;
            if found.role != *role {
                return Err(Conflict::RoleMismatch);
            }
            if found.generation != *generation {
                return Err(Conflict::GenerationMismatch {
                    expected: *generation,
                    found: found.generation,
                });
            }
            Ok(())
        }
    }
}

/// Why creating or loading a durable session failed.
#[derive(Debug)]
pub enum OpenError {
    /// Reading the store failed.
    Store(StorageError),
    /// `create` found a record (valid or not) already stored for this peer
    /// and left it in place.
    AlreadyExists,
    /// The precondition of `side[index]` did not hold; nothing was written.
    SideConflict { index: usize, conflict: Conflict },
    /// A stored record exists but is invalid or bound to other identities,
    /// or the session given to `create` is inconsistent.
    Invalid(SessionCheckpointError),
    /// The initial record was definitely not stored.
    NotCommitted(StorageError),
    /// The initial record may or may not have been stored.
    OutcomeUnknown(StorageError),
    /// The side writes were not usable; nothing was written.
    SideWrite(SideWriteError),
}

/// Why a transition could not be staged. The installed state is unchanged.
#[derive(Debug)]
pub enum StageError {
    /// An earlier commit's outcome is unknown; see [`DurableSession`].
    Unresolved {
        attempted_generation: u64,
    },
    /// An earlier commit found the store no longer holding this instance's
    /// state; see [`CommitError::Conflict`].
    Conflicted,
    GenerationExhausted,
    Ratchet(RatchetError),
    Checkpoint(SessionCheckpointError),
}

/// Why a staged transition was not installed. In every case its output was
/// discarded.
#[derive(Debug)]
pub enum CommitError {
    /// An earlier commit's outcome is unknown; nothing was written.
    Unresolved { attempted_generation: u64 },
    /// An earlier commit conflicted; nothing was written.
    Conflicted,
    /// The transition was staged from another instance or an older state
    /// of this one; nothing was written.
    StaleTransition,
    /// The stored record is not this instance's predecessor; nothing was
    /// written. The installed state is unchanged and the instance now refuses
    /// further transitions. It is not reloaded or retried automatically.
    Conflict(Conflict),
    /// The session record was this instance's predecessor, but the
    /// precondition of `side[index]` did not hold; nothing was written. The
    /// installed state is unchanged and the instance stays usable.
    SideConflict { index: usize, conflict: Conflict },
    /// The store definitely did not keep the record. The installed state is
    /// unchanged.
    NotCommitted(StorageError),
    /// The store may or may not have kept the record. The instance is now
    /// unresolved.
    OutcomeUnknown(StorageError),
    /// The side writes were not usable; nothing was written.
    SideWrite(SideWriteError),
}

/// A record written in the same transaction as a session checkpoint, so that
/// the two become durable together or not at all.
///
/// Side writes cannot touch session records: a key in the `session:`
/// namespace is refused when the write is built, so the conditional check on
/// the session record cannot be bypassed through a side write.
pub struct SideWrite {
    key: String,
    expect: SideExpect,
    value: Zeroizing<Vec<u8>>,
}

enum SideExpect {
    Absent,
    Exactly(Zeroizing<Vec<u8>>),
}

/// Why a [`SideWrite`] could not be built, or a batch of them used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SideWriteError {
    /// The key is in the namespace reserved for session records.
    ReservedKey,
    /// Two writes in one batch name the same key.
    DuplicateKey,
}

const SESSION_NAMESPACE: &str = "session:";

impl SideWrite {
    /// Writes `value` at `key`, which must not exist yet.
    pub fn insert(key: String, value: Zeroizing<Vec<u8>>) -> Result<Self, SideWriteError> {
        Self::new(key, SideExpect::Absent, value)
    }

    /// Replaces the record at `key`, which must still be exactly `expected`.
    pub fn replace(
        key: String,
        expected: Zeroizing<Vec<u8>>,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<Self, SideWriteError> {
        Self::new(key, SideExpect::Exactly(expected), value)
    }

    fn new(key: String, expect: SideExpect, value: Zeroizing<Vec<u8>>) -> Result<Self, SideWriteError> {
        if key.starts_with(SESSION_NAMESPACE) {
            return Err(SideWriteError::ReservedKey);
        }
        Ok(Self { key, expect, value })
    }

    pub fn key(&self) -> &str {
        &self.key
    }
}

/// The session write followed by the side writes, refusing a batch that
/// names one key twice.
fn batch<'a>(
    session: Write<'a>,
    side: &'a [SideWrite],
) -> Result<Vec<Write<'a>>, SideWriteError> {
    let mut writes = Vec::with_capacity(1 + side.len());
    writes.push(session);
    for w in side {
        if writes.iter().any(|x| x.key == w.key) {
            return Err(SideWriteError::DuplicateKey);
        }
        writes.push(Write {
            key: &w.key,
            expect: match &w.expect {
                SideExpect::Absent => Expect::Absent,
                SideExpect::Exactly(v) => Expect::Exactly(v),
            },
            value: &w.value,
        });
    }
    Ok(writes)
}

static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(0);

enum Status {
    Active,
    Unresolved { attempted_generation: u64 },
    Conflicted,
}

/// A session whose ratchet only advances through conditionally committed
/// checkpoints.
///
/// The ratchet is never exposed, so the only way to use it is a staged
/// transition. Neither of these compiles:
///
/// ```compile_fail,E0599
/// fn peek(s: &core_protocol::durable::DurableSession) {
///     let _ = s.session();
/// }
/// ```
///
/// ```compile_fail,E0603
/// use core_protocol::checkpoint::decode_session_checkpoint;
/// ```
pub struct DurableSession {
    session: Session,
    role: SessionRole,
    our_identity_pk: [u8; 32],
    key: String,
    generation: u64,
    status: Status,
    instance: u64,
}

/// A prepared transition: the advanced ratchet, the record describing it, and
/// the output that is released only by a successful
/// [`commit`](DurableSession::commit). Dropping it abandons the transition and
/// wipes its key material.
pub struct StagedTransition<T> {
    ratchet: DoubleRatchet,
    record: Zeroizing<Vec<u8>>,
    output: T,
    generation: u64,
    base_generation: u64,
    instance: u64,
}

impl<T> StagedTransition<T> {
    /// The generation this transition would commit.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The withheld output, readable inside this crate so that a record
    /// derived from it (an outbox or inbox entry) can be written in the same
    /// transaction as the checkpoint. Outside this crate the output is
    /// reachable only through a successful commit.
    pub(crate) fn output(&self) -> &T {
        &self.output
    }
}

impl DurableSession {
    fn new(
        session: Session,
        role: SessionRole,
        our_identity_pk: [u8; 32],
        generation: u64,
    ) -> Self {
        let key = session_storage_key(&session.peer_identity_pk);
        Self {
            session,
            role,
            our_identity_pk,
            key,
            generation,
            status: Status::Active,
            instance: NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Stores a newly established session as generation 0, only if no record
    /// (valid or not) exists for this peer. The check and the insert are one
    /// store transaction, so a concurrent creator cannot be overwritten.
    pub fn create<S: CheckpointStore>(
        store: &mut S,
        session: Session,
        role: SessionRole,
        our_identity_pk: [u8; 32],
    ) -> Result<Self, OpenError> {
        Self::create_with(store, session, role, our_identity_pk, &[])
    }

    /// [`create`](Self::create), writing `side` in the same transaction. If
    /// any precondition fails — the session's or a side write's — nothing is
    /// written.
    pub fn create_with<S: CheckpointStore>(
        store: &mut S,
        session: Session,
        role: SessionRole,
        our_identity_pk: [u8; 32],
        side: &[SideWrite],
    ) -> Result<Self, OpenError> {
        let record = encode_session_checkpoint(&session, role, &our_identity_pk, 0)
            .map_err(OpenError::Invalid)?;
        let this = Self::new(session, role, our_identity_pk, 0);
        let writes = batch(
            Write {
                key: &this.key,
                expect: Expect::Absent,
                value: &record,
            },
            side,
        )
        .map_err(OpenError::SideWrite)?;
        match store.write_conditional(&writes) {
            Ok(()) => Ok(this),
            Err(WriteFailure::Conflict { index: 0, .. }) => Err(OpenError::AlreadyExists),
            Err(WriteFailure::Conflict { index, conflict }) => Err(OpenError::SideConflict {
                index: index - 1,
                conflict,
            }),
            Err(WriteFailure::NotCommitted(e)) => Err(OpenError::NotCommitted(e)),
            Err(WriteFailure::OutcomeUnknown(e)) => Err(OpenError::OutcomeUnknown(e)),
        }
    }

    /// Loads the stored session for `binding`.
    ///
    /// `Ok(None)` means no record exists. A record that exists but is
    /// malformed, unsupported or bound to other identities is an error; it is
    /// never treated as missing.
    pub fn load<S: CheckpointStore>(
        store: &mut S,
        binding: &SessionBinding,
    ) -> Result<Option<Self>, OpenError> {
        let key = session_storage_key(&binding.peer_identity_pk);
        let Some(record) = store.read(&key).map_err(OpenError::Store)? else {
            return Ok(None);
        };
        let restored = decode_session_checkpoint(&record, binding).map_err(OpenError::Invalid)?;
        Ok(Some(Self::new(
            restored.session,
            restored.role,
            binding.our_identity_pk,
            restored.generation,
        )))
    }

    pub fn role(&self) -> SessionRole {
        self.role
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn our_identity_pk(&self) -> [u8; 32] {
        self.our_identity_pk
    }

    pub fn peer_identity_pk(&self) -> [u8; 32] {
        self.session.peer_identity_pk
    }

    /// `Some(generation)` of the write whose outcome is unknown.
    pub fn unresolved_generation(&self) -> Option<u64> {
        match self.status {
            Status::Unresolved {
                attempted_generation,
            } => Some(attempted_generation),
            _ => None,
        }
    }

    /// Whether a commit found the store no longer holding this instance's
    /// state.
    pub fn is_conflicted(&self) -> bool {
        matches!(self.status, Status::Conflicted)
    }

    /// Stages encrypting `plaintext`. Returns `(header, ciphertext)` on commit.
    pub fn stage_encrypt(
        &self,
        plaintext: &[u8],
    ) -> Result<StagedTransition<(Header, Vec<u8>)>, StageError> {
        self.stage(|r, ad| r.encrypt(plaintext, ad))
    }

    /// Stages decrypting a message. Returns the plaintext on commit.
    pub fn stage_decrypt(
        &self,
        header: &Header,
        ciphertext: &[u8],
    ) -> Result<StagedTransition<Vec<u8>>, StageError> {
        self.stage(|r, ad| r.decrypt(header, ciphertext, ad))
    }

    fn stage<T>(
        &self,
        op: impl FnOnce(&mut DoubleRatchet, &[u8]) -> Result<T, RatchetError>,
    ) -> Result<StagedTransition<T>, StageError> {
        match self.status {
            Status::Active => {}
            Status::Unresolved {
                attempted_generation,
            } => {
                return Err(StageError::Unresolved {
                    attempted_generation,
                })
            }
            Status::Conflicted => return Err(StageError::Conflicted),
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(StageError::GenerationExhausted)?;
        let mut ratchet = self.session.ratchet.staged_copy();
        let output = op(&mut ratchet, &self.session.ad).map_err(StageError::Ratchet)?;
        let record = encode_parts(
            &ratchet,
            &self.session.ad,
            &self.session.peer_identity_pk,
            self.role,
            &self.our_identity_pk,
            generation,
        )
        .map_err(StageError::Checkpoint)?;
        Ok(StagedTransition {
            ratchet,
            record,
            output,
            generation,
            base_generation: self.generation,
            instance: self.instance,
        })
    }

    /// Writes the staged record if the store still holds this instance's
    /// current record and, only if the store reports the write committed,
    /// installs the staged ratchet and returns the output.
    ///
    /// Nothing is retried. After [`CommitError::Conflict`] or
    /// [`CommitError::OutcomeUnknown`] the instance refuses further
    /// transitions; deciding what to do next is left to the caller, and must
    /// not rest on rereading an older record alone.
    pub fn commit<S: CheckpointStore, T>(
        &mut self,
        store: &mut S,
        staged: StagedTransition<T>,
    ) -> Result<T, CommitError> {
        self.commit_with(store, staged, &[])
    }

    /// [`commit`](Self::commit), writing `side` in the same transaction as the
    /// checkpoint. The output is released only if every write committed.
    pub fn commit_with<S: CheckpointStore, T>(
        &mut self,
        store: &mut S,
        staged: StagedTransition<T>,
        side: &[SideWrite],
    ) -> Result<T, CommitError> {
        match self.status {
            Status::Active => {}
            Status::Unresolved {
                attempted_generation,
            } => {
                return Err(CommitError::Unresolved {
                    attempted_generation,
                })
            }
            Status::Conflicted => return Err(CommitError::Conflicted),
        }
        if staged.instance != self.instance || staged.base_generation != self.generation {
            return Err(CommitError::StaleTransition);
        }
        let binding = SessionBinding {
            our_identity_pk: self.our_identity_pk,
            peer_identity_pk: self.session.peer_identity_pk,
        };
        let writes = batch(
            Write {
                key: &self.key,
                expect: Expect::Predecessor {
                    generation: self.generation,
                    role: self.role,
                    binding: &binding,
                },
                value: &staged.record,
            },
            side,
        )
        .map_err(CommitError::SideWrite)?;
        let result = store.write_conditional(&writes);
        drop(writes);
        match result {
            Ok(()) => {
                let StagedTransition {
                    ratchet,
                    output,
                    generation,
                    ..
                } = staged;
                self.session.ratchet = ratchet;
                self.generation = generation;
                Ok(output)
            }
            Err(WriteFailure::Conflict { index: 0, conflict }) => {
                self.status = Status::Conflicted;
                Err(CommitError::Conflict(conflict))
            }
            Err(WriteFailure::Conflict { index, conflict }) => Err(CommitError::SideConflict {
                index: index - 1,
                conflict,
            }),
            Err(WriteFailure::NotCommitted(e)) => Err(CommitError::NotCommitted(e)),
            Err(WriteFailure::OutcomeUnknown(e)) => {
                self.status = Status::Unresolved {
                    attempted_generation: staged.generation,
                };
                Err(CommitError::OutcomeUnknown(e))
            }
        }
    }
}

/// Failure injection for this crate's tests. Compiled into tests only.
#[cfg(test)]
pub(crate) mod test_hooks {
    use super::*;
    use std::cell::Cell;

    /// Environment variable naming the point at which a child test process
    /// aborts inside `S1CheckpointStore::write_conditional`.
    pub(crate) const CRASH_AT_ENV: &str = "ARCIUM_DURABLE_CRASH_AT";

    /// Aborts the process — no unwinding, no destructors, no rollback by
    /// `Drop` — when `CRASH_AT_ENV` names `point`.
    pub(crate) fn crash_point(point: &str) {
        if std::env::var(CRASH_AT_ENV).as_deref() == Ok(point) {
            std::process::abort();
        }
    }

    /// A scripted outcome for the next S1 commit on this thread. Simulated:
    /// the real transaction is committed or rolled back, and the reported
    /// result is chosen by the test, not by an I/O fault.
    #[derive(Clone, Copy, Debug)]
    pub(crate) enum CommitFault {
        /// Roll back and report `NotCommitted`.
        NotCommitted,
        /// Commit, then report an unknown outcome.
        UnknownStored,
        /// Roll back, then report an unknown outcome.
        UnknownLost,
    }

    thread_local! {
        static NEXT: Cell<Option<CommitFault>> = const { Cell::new(None) };
    }

    pub(crate) fn inject(fault: CommitFault) {
        NEXT.with(|n| n.set(Some(fault)));
    }

    pub(super) fn take_fault() -> Option<CommitFault> {
        NEXT.with(|n| n.take())
    }

    pub(super) fn apply(
        fault: CommitFault,
        tx: core_storage::StoreTransaction<'_>,
    ) -> Result<(), WriteFailure> {
        let simulated = || StorageError::TransactionStateInvalid("simulated");
        match fault {
            CommitFault::NotCommitted => {
                drop(tx);
                Err(WriteFailure::NotCommitted(simulated()))
            }
            CommitFault::UnknownStored => {
                tx.commit().expect("simulated fault needs a real commit");
                Err(WriteFailure::OutcomeUnknown(simulated()))
            }
            CommitFault::UnknownLost => {
                drop(tx);
                Err(WriteFailure::OutcomeUnknown(simulated()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::{Arc, Barrier};
    use x25519_dalek::{PublicKey, StaticSecret};

    const MASTER_KEY: [u8; 32] = [0x42; 32];

    // ── Stores ────────────────────────────────────────────────────────────────

    fn memdb() -> EncryptedStore {
        EncryptedStore::open_in_memory(MASTER_KEY).unwrap()
    }

    fn filedb(path: &Path) -> EncryptedStore {
        EncryptedStore::open(path, MASTER_KEY).unwrap()
    }

    fn s1(db: &mut EncryptedStore) -> S1CheckpointStore<'_> {
        S1CheckpointStore::new(db)
    }

    /// Simulated failures. These model what a store may report; they do not
    /// reproduce real I/O faults.
    #[derive(Clone, Copy)]
    enum Fault {
        NotCommitted,
        /// Reports an unknown outcome although the record was stored.
        UnknownStored,
        /// Reports an unknown outcome and the record was not stored.
        UnknownLost,
    }

    /// In-memory store applying the same precondition check as the S1 store,
    /// with scripted failures.
    #[derive(Default)]
    struct FakeStore {
        records: HashMap<String, Vec<u8>>,
        next_write: Option<Fault>,
    }

    fn simulated() -> StorageError {
        StorageError::TransactionStateInvalid("simulated")
    }

    impl Store for FakeStore {
        fn read(&mut self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
            Ok(self.records.get(key).map(|v| Zeroizing::new(v.clone())))
        }

        fn write_conditional(&mut self, writes: &[Write<'_>]) -> Result<(), WriteFailure> {
            for (index, w) in writes.iter().enumerate() {
                let current = match self.records.get(w.key) {
                    Some(v) => Current::Present(v),
                    None => Current::Missing,
                };
                check_precondition(current, &w.expect)
                    .map_err(|conflict| WriteFailure::Conflict { index, conflict })?;
            }
            let apply = |records: &mut HashMap<String, Vec<u8>>| {
                for w in writes {
                    records.insert(w.key.to_string(), w.value.to_vec());
                }
            };
            match self.next_write.take() {
                None => {
                    apply(&mut self.records);
                    Ok(())
                }
                Some(Fault::NotCommitted) => Err(WriteFailure::NotCommitted(simulated())),
                Some(Fault::UnknownStored) => {
                    apply(&mut self.records);
                    Err(WriteFailure::OutcomeUnknown(simulated()))
                }
                Some(Fault::UnknownLost) => Err(WriteFailure::OutcomeUnknown(simulated())),
            }
        }
    }

    impl CheckpointStore for FakeStore {}

    // ── Sessions ──────────────────────────────────────────────────────────────

    struct Pair {
        alice: Session,
        bob: Session,
        alice_pk: [u8; 32],
        bob_pk: [u8; 32],
    }

    /// Two matching sessions with the AD layout X3DH produces. The root key
    /// is fixed because these tests exercise persistence, not X3DH.
    fn pair() -> Pair {
        let alice_pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes();
        let bob_pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes();
        let mut ad = alice_pk.to_vec();
        ad.extend_from_slice(&bob_pk);
        let spk = StaticSecret::random_from_rng(OsRng);
        let root = [5u8; 32];
        Pair {
            alice: Session {
                ratchet: DoubleRatchet::init_alice(root, PublicKey::from(&spk)),
                ad: ad.clone(),
                peer_identity_pk: bob_pk,
            },
            bob: Session {
                ratchet: DoubleRatchet::init_bob(root, spk),
                ad,
                peer_identity_pk: alice_pk,
            },
            alice_pk,
            bob_pk,
        }
    }

    /// Another initiator session for the same identities as `p.alice`.
    fn rival_initiator(p: &Pair) -> Session {
        let mut ad = p.alice_pk.to_vec();
        ad.extend_from_slice(&p.bob_pk);
        let spk = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        Session {
            ratchet: DoubleRatchet::init_alice([6u8; 32], spk),
            ad,
            peer_identity_pk: p.bob_pk,
        }
    }

    fn binding(our: [u8; 32], peer: [u8; 32]) -> SessionBinding {
        SessionBinding {
            our_identity_pk: our,
            peer_identity_pk: peer,
        }
    }

    fn installed(s: &DurableSession) -> Zeroizing<Vec<u8>> {
        s.session.ratchet.to_checkpoint().unwrap()
    }

    fn stored<S: CheckpointStore>(store: &mut S, s: &DurableSession) -> Zeroizing<Vec<u8>> {
        store.read(&s.key).unwrap().expect("record present")
    }

    fn send<S: CheckpointStore>(
        s: &mut DurableSession,
        store: &mut S,
        m: &[u8],
    ) -> (Header, Vec<u8>) {
        let staged = s.stage_encrypt(m).unwrap();
        s.commit(store, staged).unwrap()
    }

    fn recv<S: CheckpointStore>(
        s: &mut DurableSession,
        store: &mut S,
        m: &(Header, Vec<u8>),
    ) -> Vec<u8> {
        let staged = s.stage_decrypt(&m.0, &m.1).unwrap();
        s.commit(store, staged).unwrap()
    }

    // ── Loading and creation ──────────────────────────────────────────────────

    #[test]
    fn missing_and_invalid_records_are_distinguished() {
        let p = pair();
        let mut db = memdb();
        let b = binding(p.alice_pk, p.bob_pk);
        assert!(
            DurableSession::load(&mut s1(&mut db), &b)
                .unwrap()
                .is_none(),
            "missing is Ok(None)"
        );

        db.put(&session_storage_key(&p.bob_pk), b"garbage").unwrap();
        assert!(matches!(
            DurableSession::load(&mut s1(&mut db), &b),
            Err(OpenError::Invalid(SessionCheckpointError::Truncated { .. }))
        ));
        // An invalid record is not overwritten by a fresh session either.
        assert!(matches!(
            DurableSession::create(
                &mut s1(&mut db),
                p.alice,
                SessionRole::Initiator,
                p.alice_pk
            ),
            Err(OpenError::AlreadyExists)
        ));
        assert_eq!(db.get(&session_storage_key(&p.bob_pk)).unwrap(), b"garbage");
    }

    #[test]
    fn create_refuses_to_replace_an_existing_session() {
        let p = pair();
        let mut db = memdb();
        let rival = rival_initiator(&p);
        let s = DurableSession::create(
            &mut s1(&mut db),
            p.alice,
            SessionRole::Initiator,
            p.alice_pk,
        )
        .unwrap();
        let before = stored(&mut s1(&mut db), &s);
        assert!(matches!(
            DurableSession::create(&mut s1(&mut db), rival, SessionRole::Initiator, p.alice_pk),
            Err(OpenError::AlreadyExists)
        ));
        assert_eq!(*stored(&mut s1(&mut db), &s), *before);
    }

    #[test]
    fn load_checks_the_binding() {
        let p = pair();
        let mut db = memdb();
        DurableSession::create(
            &mut s1(&mut db),
            p.alice,
            SessionRole::Initiator,
            p.alice_pk,
        )
        .unwrap();
        let other = PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes();
        assert!(matches!(
            DurableSession::load(&mut s1(&mut db), &binding(other, p.bob_pk)),
            Err(OpenError::Invalid(
                SessionCheckpointError::OurIdentityMismatch
            ))
        ));
    }

    // ── P4: competing creation ────────────────────────────────────────────────

    /// P4 regression, real SQLite, two connections to one file. The earlier
    /// `create` read the store outside any transaction and then wrote
    /// unconditionally, so a session created by another connection after
    /// that read was silently replaced. The absence check now runs inside
    /// the write transaction, so the later creator sees the record.
    #[test]
    fn p4_creation_on_a_second_connection_does_not_replace_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.db");
        let (mut c1, mut c2) = (filedb(&path), filedb(&path));
        let p = pair();
        let rival = rival_initiator(&p);
        let rival_dh = rival.ratchet.our_dh_public().to_bytes();

        DurableSession::create(&mut s1(&mut c2), rival, SessionRole::Initiator, p.alice_pk)
            .unwrap();
        assert!(matches!(
            DurableSession::create(
                &mut s1(&mut c1),
                p.alice,
                SessionRole::Initiator,
                p.alice_pk
            ),
            Err(OpenError::AlreadyExists)
        ));
        let kept = DurableSession::load(&mut s1(&mut c1), &binding(p.alice_pk, p.bob_pk))
            .unwrap()
            .unwrap();
        assert_eq!(kept.session.ratchet.our_dh_public().to_bytes(), rival_dh);
    }

    /// P4 regression, real SQLite: two threads, each with its own connection,
    /// create the same session at once. Exactly one succeeds and the stored
    /// record is the winner's. Neither thread holds a transaction while
    /// waiting for the other; SQLite's busy handler serialises the two
    /// `BEGIN IMMEDIATE`s.
    #[test]
    fn p4_concurrent_creation_has_exactly_one_winner() {
        for _ in 0..8 {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("sessions.db");
            drop(filedb(&path)); // create the schema before the race
            let p = pair();
            let (alice_pk, bob_pk) = (p.alice_pk, p.bob_pk);
            let rival = rival_initiator(&p);
            let barrier = Arc::new(Barrier::new(2));
            let handles: Vec<_> = [p.alice, rival]
                .into_iter()
                .map(|session| {
                    let (path, barrier) = (path.clone(), barrier.clone());
                    std::thread::spawn(move || {
                        let mut db = filedb(&path);
                        let dh = session.ratchet.our_dh_public().to_bytes();
                        barrier.wait();
                        let r = DurableSession::create(
                            &mut s1(&mut db),
                            session,
                            SessionRole::Initiator,
                            alice_pk,
                        );
                        (dh, r.map(|_| ()))
                    })
                })
                .collect();
            let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            let winners: Vec<_> = results.iter().filter(|(_, r)| r.is_ok()).collect();
            assert_eq!(winners.len(), 1, "exactly one creator succeeds");
            let loser = results.iter().find(|(_, r)| r.is_err()).unwrap();
            assert!(matches!(loser.1, Err(OpenError::AlreadyExists)));

            let mut db = filedb(&path);
            let kept = DurableSession::load(&mut s1(&mut db), &binding(alice_pk, bob_pk))
                .unwrap()
                .unwrap();
            assert_eq!(
                kept.session.ratchet.our_dh_public().to_bytes(),
                winners[0].0
            );
        }
    }

    // ── P1: stale instances ───────────────────────────────────────────────────

    /// P1 regression, real SQLite, two connections to one file. A stale
    /// instance used to overwrite the newer generation written by another
    /// instance and release a ciphertext competing with one already sent.
    #[test]
    fn p1_stale_instance_cannot_overwrite_a_newer_generation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.db");
        let (mut c1, mut c2) = (filedb(&path), filedb(&path));
        let p = pair();
        let b = binding(p.alice_pk, p.bob_pk);
        DurableSession::create(
            &mut s1(&mut c1),
            p.alice,
            SessionRole::Initiator,
            p.alice_pk,
        )
        .unwrap();
        let mut stale = DurableSession::load(&mut s1(&mut c1), &b).unwrap().unwrap();
        let mut fresh = DurableSession::load(&mut s1(&mut c2), &b).unwrap().unwrap();
        for m in [b"a", b"b", b"c"] {
            send(&mut fresh, &mut s1(&mut c2), m);
        }
        let newest = stored(&mut s1(&mut c1), &fresh);
        let before = installed(&stale);

        let staged = stale.stage_encrypt(b"competing").unwrap();
        match stale.commit(&mut s1(&mut c1), staged) {
            Err(CommitError::Conflict(Conflict::GenerationMismatch {
                expected: 0,
                found: 3,
            })) => {}
            other => panic!(
                "expected a generation conflict, got {:?}",
                other.map(|_| ())
            ),
        }
        // Nothing was written, nothing was installed, nothing was released.
        assert_eq!(*stored(&mut s1(&mut c1), &fresh), *newest);
        assert_eq!(*installed(&stale), *before);
        assert_eq!(stale.generation(), 0);
        assert!(stale.is_conflicted());
        assert!(matches!(
            stale.stage_encrypt(b"again"),
            Err(StageError::Conflicted)
        ));
        // The conflict rolled its transaction back: the connection is usable.
        assert_eq!(
            DurableSession::load(&mut s1(&mut c1), &b)
                .unwrap()
                .unwrap()
                .generation(),
            3
        );
        // The newer instance continues normally.
        send(&mut fresh, &mut s1(&mut c2), b"d");
    }

    /// P2 through the ordinary API: of two instances at the same generation,
    /// only the first commit releases a ciphertext.
    #[test]
    fn p2_two_instances_cannot_both_release_a_ciphertext_for_one_generation() {
        let p = pair();
        let mut db = memdb();
        let b = binding(p.alice_pk, p.bob_pk);
        DurableSession::create(
            &mut s1(&mut db),
            p.alice,
            SessionRole::Initiator,
            p.alice_pk,
        )
        .unwrap();
        let mut x = DurableSession::load(&mut s1(&mut db), &b).unwrap().unwrap();
        let mut y = DurableSession::load(&mut s1(&mut db), &b).unwrap().unwrap();
        let tx = x.stage_encrypt(b"x").unwrap();
        let ty = y.stage_encrypt(b"y").unwrap();
        assert!(x.commit(&mut s1(&mut db), tx).is_ok());
        assert!(matches!(
            y.commit(&mut s1(&mut db), ty),
            Err(CommitError::Conflict(Conflict::GenerationMismatch { .. }))
        ));
    }

    #[test]
    fn predecessor_check_covers_missing_invalid_rebound_and_other_role_records() {
        let p = pair();
        let key = session_storage_key(&p.bob_pk);
        let mut db = memdb();
        let mut s = DurableSession::create(
            &mut s1(&mut db),
            p.alice,
            SessionRole::Initiator,
            p.alice_pk,
        )
        .unwrap();

        let commit_against = |db: &mut EncryptedStore, s: &mut DurableSession| {
            let staged = s.stage_encrypt(b"m").unwrap();
            let r = s.commit(&mut s1(db), staged);
            s.status = Status::Active; // re-arm for the next case
            r
        };

        db.delete(&key).unwrap();
        assert!(matches!(
            commit_against(&mut db, &mut s),
            Err(CommitError::Conflict(Conflict::RecordMissing))
        ));

        db.put(&key, b"garbage").unwrap();
        assert!(matches!(
            commit_against(&mut db, &mut s),
            Err(CommitError::Conflict(Conflict::StoredRecordInvalid(_)))
        ));

        let other_us = PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes();
        let mut ad = other_us.to_vec();
        ad.extend_from_slice(&p.bob_pk);
        let foreign = Session {
            ratchet: DoubleRatchet::init_alice(
                [1; 32],
                PublicKey::from(&StaticSecret::random_from_rng(OsRng)),
            ),
            ad,
            peer_identity_pk: p.bob_pk,
        };
        let rec =
            encode_session_checkpoint(&foreign, SessionRole::Initiator, &other_us, 0).unwrap();
        db.put(&key, &rec).unwrap();
        assert!(matches!(
            commit_against(&mut db, &mut s),
            Err(CommitError::Conflict(Conflict::BindingMismatch(_)))
        ));

        let mut ad = p.bob_pk.to_vec();
        ad.extend_from_slice(&p.alice_pk);
        let responder = Session {
            ratchet: DoubleRatchet::init_bob([1; 32], StaticSecret::random_from_rng(OsRng)),
            ad,
            peer_identity_pk: p.bob_pk,
        };
        let rec =
            encode_session_checkpoint(&responder, SessionRole::Responder, &p.alice_pk, 0).unwrap();
        db.put(&key, &rec).unwrap();
        assert!(matches!(
            commit_against(&mut db, &mut s),
            Err(CommitError::Conflict(Conflict::RoleMismatch))
        ));
        assert_eq!(s.generation(), 0);
    }

    /// A row the store cannot authenticate is never a match. (Producing one
    /// through S1 needs raw SQL access, so the decision is tested directly.)
    #[test]
    fn an_unreadable_record_satisfies_no_precondition() {
        let b = binding([1; 32], [2; 32]);
        assert!(matches!(
            check_precondition(Current::Unreadable, &Expect::Absent),
            Err(Conflict::RecordExists)
        ));
        assert!(matches!(
            check_precondition(
                Current::Unreadable,
                &Expect::Predecessor {
                    generation: 0,
                    role: SessionRole::Initiator,
                    binding: &b
                }
            ),
            Err(Conflict::StoredRecordUnreadable)
        ));
    }

    // ── Transitions ───────────────────────────────────────────────────────────

    /// Alice and Bob each keep their session only in their own encrypted
    /// store, and are rebuilt from it before every message.
    #[test]
    fn conversation_survives_reloading_both_sides_from_the_store() {
        let p = pair();
        let (mut da, mut dbb) = (memdb(), memdb());
        let (ba, bb) = (binding(p.alice_pk, p.bob_pk), binding(p.bob_pk, p.alice_pk));
        DurableSession::create(
            &mut s1(&mut da),
            p.alice,
            SessionRole::Initiator,
            p.alice_pk,
        )
        .unwrap();
        DurableSession::create(&mut s1(&mut dbb), p.bob, SessionRole::Responder, p.bob_pk).unwrap();

        for i in 0u8..4 {
            let mut a = DurableSession::load(&mut s1(&mut da), &ba)
                .unwrap()
                .unwrap();
            let msg = send(&mut a, &mut s1(&mut da), &[i]);
            let mut b = DurableSession::load(&mut s1(&mut dbb), &bb)
                .unwrap()
                .unwrap();
            assert_eq!(recv(&mut b, &mut s1(&mut dbb), &msg), [i]);
            drop((a, b));

            let mut b = DurableSession::load(&mut s1(&mut dbb), &bb)
                .unwrap()
                .unwrap();
            assert_eq!(b.role(), SessionRole::Responder);
            let reply = send(&mut b, &mut s1(&mut dbb), &[i, i]);
            let mut a = DurableSession::load(&mut s1(&mut da), &ba)
                .unwrap()
                .unwrap();
            assert_eq!(recv(&mut a, &mut s1(&mut da), &reply), [i, i]);
            assert_eq!(a.generation(), 2 * u64::from(i) + 2);
        }
    }

    #[test]
    fn staging_does_not_touch_installed_or_stored_state() {
        let p = pair();
        let mut db = memdb();
        let s = DurableSession::create(
            &mut s1(&mut db),
            p.alice,
            SessionRole::Initiator,
            p.alice_pk,
        )
        .unwrap();
        let (mem, disk) = (installed(&s), stored(&mut s1(&mut db), &s));
        let staged = s.stage_encrypt(b"x").unwrap();
        assert_eq!(staged.generation(), 1);
        assert_eq!(*installed(&s), *mem);
        assert_eq!(*stored(&mut s1(&mut db), &s), *disk);
        drop(staged);
        assert_eq!(*installed(&s), *mem);
        assert_eq!(s.generation(), 0);
    }

    /// S1 atomicity: a checkpoint written in a transaction that is dropped
    /// without `commit` is not visible, and the previous generation loads.
    #[test]
    fn uncommitted_s1_transaction_leaves_the_previous_generation() {
        let p = pair();
        let mut db = memdb();
        let b = binding(p.alice_pk, p.bob_pk);
        let mut s = DurableSession::create(
            &mut s1(&mut db),
            p.alice,
            SessionRole::Initiator,
            p.alice_pk,
        )
        .unwrap();
        send(&mut s, &mut s1(&mut db), b"one");
        let committed = stored(&mut s1(&mut db), &s);

        let staged = s.stage_encrypt(b"two").unwrap();
        {
            let tx = db.transaction().unwrap();
            tx.put(&s.key, &staged.record).unwrap();
            // dropped without commit
        }
        drop(staged);
        assert_eq!(*stored(&mut s1(&mut db), &s), *committed);
        let reloaded = DurableSession::load(&mut s1(&mut db), &b).unwrap().unwrap();
        assert_eq!(reloaded.generation(), 1);
        assert_eq!(*installed(&reloaded), *installed(&s));
    }

    #[test]
    fn not_committed_keeps_the_installed_state_and_withholds_output() {
        let p = pair();
        let mut store = FakeStore::default();
        let mut s = DurableSession::create(&mut store, p.alice, SessionRole::Initiator, p.alice_pk)
            .unwrap();
        let (mem, disk) = (installed(&s), stored(&mut store, &s));

        store.next_write = Some(Fault::NotCommitted);
        let staged = s.stage_encrypt(b"lost").unwrap();
        assert!(matches!(
            s.commit(&mut store, staged),
            Err(CommitError::NotCommitted(_))
        ));
        assert_eq!(*installed(&s), *mem);
        assert_eq!(*stored(&mut store, &s), *disk);
        assert_eq!(s.generation(), 0);
        assert_eq!(s.unresolved_generation(), None);
        assert!(!s.is_conflicted());

        // The session remains usable; the caller decides whether to try again.
        let mut bob_store = FakeStore::default();
        let mut bob =
            DurableSession::create(&mut bob_store, p.bob, SessionRole::Responder, p.bob_pk)
                .unwrap();
        let msg = send(&mut s, &mut store, b"sent");
        assert_eq!(msg.0.n, 0, "the discarded attempt consumed no counter");
        assert_eq!(recv(&mut bob, &mut bob_store, &msg), b"sent");
    }

    #[test]
    fn unknown_outcome_leaves_the_session_unresolved_whatever_was_stored() {
        for fault in [Fault::UnknownStored, Fault::UnknownLost] {
            let p = pair();
            let mut store = FakeStore::default();
            let mut s =
                DurableSession::create(&mut store, p.alice, SessionRole::Initiator, p.alice_pk)
                    .unwrap();
            let mem = installed(&s);

            store.next_write = Some(fault);
            let staged = s.stage_encrypt(b"maybe").unwrap();
            assert!(matches!(
                s.commit(&mut store, staged),
                Err(CommitError::OutcomeUnknown(_))
            ));
            assert_eq!(s.unresolved_generation(), Some(1));
            assert_eq!(*installed(&s), *mem, "staged state is not installed");
            assert_eq!(s.generation(), 0);

            assert!(matches!(
                s.stage_encrypt(b"next"),
                Err(StageError::Unresolved {
                    attempted_generation: 1
                })
            ));
            assert!(matches!(
                s.stage_decrypt(
                    &Header {
                        dh: [0; 32],
                        pn: 0,
                        n: 0
                    },
                    &[]
                ),
                Err(StageError::Unresolved { .. })
            ));
        }
    }

    #[test]
    fn a_transition_commits_only_onto_the_state_it_was_staged_from() {
        let p = pair();
        let mut store = FakeStore::default();
        let b = binding(p.alice_pk, p.bob_pk);
        let mut s = DurableSession::create(&mut store, p.alice, SessionRole::Initiator, p.alice_pk)
            .unwrap();
        let first = s.stage_encrypt(b"a").unwrap();
        let second = s.stage_encrypt(b"b").unwrap();
        s.commit(&mut store, first).unwrap();
        let after_first = stored(&mut store, &s);
        assert!(matches!(
            s.commit(&mut store, second),
            Err(CommitError::StaleTransition)
        ));
        assert_eq!(*stored(&mut store, &s), *after_first);

        // A transition staged by one instance cannot be committed by another.
        let mut other = DurableSession::load(&mut store, &b).unwrap().unwrap();
        let staged = s.stage_encrypt(b"c").unwrap();
        assert!(matches!(
            other.commit(&mut store, staged),
            Err(CommitError::StaleTransition)
        ));
    }

    #[test]
    fn a_failed_decrypt_stages_nothing() {
        let p = pair();
        let mut store = FakeStore::default();
        let s =
            DurableSession::create(&mut store, p.bob, SessionRole::Responder, p.bob_pk).unwrap();
        let mem = installed(&s);
        let forged = Header {
            dh: [7; 32],
            pn: 0,
            n: 0,
        };
        assert!(matches!(
            s.stage_decrypt(&forged, &[0u8; 40]),
            Err(StageError::Ratchet(RatchetError::Decryption))
        ));
        assert_eq!(*installed(&s), *mem);
    }

    /// F-1 at the session level: a stored record whose `nr` could overflow is
    /// refused when loaded (decode), while a message that would carry a valid
    /// state past the limit is refused when staged (transition) — without
    /// touching the installed or stored state.
    #[test]
    fn receive_counter_limit_is_enforced_on_load_and_on_stage() {
        use core_crypto::ratchet::{CheckpointError, MAX_SKIP};
        const LIMIT: u32 = u32::MAX - MAX_SKIP - 1;

        let p = pair();
        let (mut alice, mut bob_r) = (p.alice.ratchet, p.bob.ratchet);
        let (h, c) = alice.encrypt(b"sync", &p.alice.ad).unwrap();
        bob_r.decrypt(&h, &c, &p.bob.ad).unwrap();
        // Move both counters, leaving the chain keys in step.
        let with_counter = |r: &DoubleRatchet, off: usize, v: u32| {
            let mut rec = r.to_checkpoint().unwrap().to_vec();
            rec[off..off + 4].copy_from_slice(&v.to_be_bytes());
            DoubleRatchet::from_checkpoint(&rec)
        };
        let Ok(mut alice) = with_counter(&alice, 162, LIMIT) else {
            panic!("ns")
        };
        let Ok(bob_r) = with_counter(&bob_r, 166, LIMIT) else {
            panic!("nr")
        };
        assert!(matches!(
            with_counter(&bob_r, 166, LIMIT + 1),
            Err(CheckpointError::CounterExhausted("nr"))
        ));

        let mut db = memdb();
        let bob = Session {
            ratchet: bob_r,
            ad: p.bob.ad.clone(),
            peer_identity_pk: p.alice_pk,
        };
        let s = DurableSession::create(&mut s1(&mut db), bob, SessionRole::Responder, p.bob_pk)
            .unwrap();
        let (mem, disk) = (installed(&s), stored(&mut s1(&mut db), &s));

        // Transition: an authentic message at n = LIMIT decrypts in the
        // staged copy, but the resulting nr = LIMIT + 1 cannot be persisted.
        let (h, c) = alice.encrypt(b"over", &p.alice.ad).unwrap();
        assert_eq!(h.n, LIMIT);
        assert!(matches!(
            s.stage_decrypt(&h, &c),
            Err(StageError::Checkpoint(SessionCheckpointError::Ratchet(
                CheckpointError::CounterExhausted("nr")
            )))
        ));
        // A forged header at n = u32::MAX fails the skip limit, no overflow.
        let forged = Header {
            dh: h.dh,
            pn: 0,
            n: u32::MAX,
        };
        assert!(matches!(
            s.stage_decrypt(&forged, &[0u8; 40]),
            Err(StageError::Ratchet(RatchetError::SkipLimit))
        ));
        assert_eq!(*installed(&s), *mem);
        assert_eq!(*stored(&mut s1(&mut db), &s), *disk);

        // Decode: a stored record past the limit is refused by load.
        let mut rec = disk.to_vec();
        rec[149 + 166..149 + 170].copy_from_slice(&(LIMIT + 1).to_be_bytes());
        db.put(&s.key, &rec).unwrap();
        assert!(matches!(
            DurableSession::load(&mut s1(&mut db), &binding(p.bob_pk, p.alice_pk)),
            Err(OpenError::Invalid(SessionCheckpointError::Ratchet(
                CheckpointError::CounterExhausted("nr")
            )))
        ));
    }

    #[test]
    fn generation_does_not_wrap() {
        let p = pair();
        let mut store = FakeStore::default();
        let mut s = DurableSession::create(&mut store, p.alice, SessionRole::Initiator, p.alice_pk)
            .unwrap();
        s.generation = u64::MAX;
        assert!(matches!(
            s.stage_encrypt(b"x"),
            Err(StageError::GenerationExhausted)
        ));
    }
}
