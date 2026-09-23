//! Staged ratchet transitions with an explicit commit boundary.
//!
//! **Not connected to the live message path.** `mobile-ffi` keeps its
//! in-memory `SessionManager`; nothing here is called from it.
//!
//! A transition (one encrypt or one decrypt) runs on an independent copy of
//! the ratchet. The copy's new state is encoded, and only once the store
//! reports that record as committed is the copy installed and the operation's
//! output (ciphertext or plaintext) handed out. Until then the installed state
//! is untouched and the output is withheld, so no output is released before
//! the store has reported the state that produced it as committed.
//!
//! When the store cannot say whether a write took effect, the session becomes
//! *unresolved*: the staged state and its output are discarded and every
//! further transition is refused. There is no resolution rule here. In
//! particular, reading back an older record does not show that the attempted
//! write never happened, and nothing retries the transition.
//!
//! What this does not provide: power-loss durability (that depends on the
//! store's configuration), protection against an older record being put back,
//! or delivery guarantees for the withheld output.

use std::sync::atomic::{AtomicU64, Ordering};

use core_crypto::ratchet::{DoubleRatchet, Header, RatchetError};
use zeroize::Zeroizing;

use crate::checkpoint::{
    decode_session_checkpoint, encode_parts, encode_session_checkpoint, session_storage_key,
    SessionBinding, SessionCheckpointError, SessionRole,
};
use crate::Session;

/// A byte store for session checkpoints.
///
/// The session layer assumes it is the only writer of its keys; `create`
/// checks for an existing record and then writes, which is not atomic against
/// other writers.
pub trait CheckpointStore {
    type Error;

    /// `Ok(None)` only when no record exists under `key`. A record that exists
    /// but cannot be read must be an error, never `None`.
    fn read(&mut self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error>;

    /// Stores `record` under `key`, replacing any previous record.
    fn write(&mut self, key: &str, record: &[u8]) -> Result<(), WriteFailure<Self::Error>>;
}

/// How a write failed, as far as the store can tell.
#[derive(Debug)]
pub enum WriteFailure<E> {
    /// The record was definitely not stored.
    NotCommitted(E),
    /// The record may or may not have been stored (for example, `COMMIT`
    /// returned an error after its commit point).
    OutcomeUnknown(E),
}

/// Why creating or loading a durable session failed.
#[derive(Debug)]
pub enum OpenError<E> {
    /// Reading the store failed.
    Store(E),
    /// `create` found a record (valid or not) already stored for this peer
    /// and left it in place.
    AlreadyExists,
    /// A stored record exists but is invalid or bound to other identities.
    Invalid(SessionCheckpointError),
    /// The initial record was definitely not stored.
    NotCommitted(E),
    /// The initial record may or may not have been stored.
    OutcomeUnknown(E),
}

/// Why a transition could not be staged. The installed state is unchanged.
#[derive(Debug)]
pub enum StageError {
    /// An earlier commit's outcome is unknown; see [`DurableSession`].
    Unresolved {
        attempted_generation: u64,
    },
    GenerationExhausted,
    Ratchet(RatchetError),
    Checkpoint(SessionCheckpointError),
}

/// Why a staged transition was not installed.
#[derive(Debug)]
pub enum CommitError<E> {
    /// An earlier commit's outcome is unknown; nothing was written.
    Unresolved { attempted_generation: u64 },
    /// The transition was staged from another session or an older state;
    /// nothing was written.
    StaleTransition,
    /// The store definitely did not keep the record. The installed state is
    /// unchanged and the output was discarded.
    NotCommitted(E),
    /// The store may or may not have kept the record. The output was
    /// discarded and the session is now unresolved.
    OutcomeUnknown(E),
}

static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(0);

/// A session whose ratchet only advances through committed checkpoints.
pub struct DurableSession {
    session: Session,
    role: SessionRole,
    our_identity_pk: [u8; 32],
    key: String,
    generation: u64,
    unresolved: Option<u64>,
    instance: u64,
}

/// A prepared transition: the advanced ratchet, the record describing it, and
/// the output that is released only by a successful
/// [`commit`](DurableSession::commit). Dropping it abandons the transition and
/// wipes its secrets.
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
            unresolved: None,
            instance: NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Stores a newly established session as generation 0.
    ///
    /// Refuses if any record is already stored for this peer, whether valid or
    /// not: an existing session is never replaced by a fresh one here.
    pub fn create<S: CheckpointStore>(
        store: &mut S,
        session: Session,
        role: SessionRole,
        our_identity_pk: [u8; 32],
    ) -> Result<Self, OpenError<S::Error>> {
        let record = encode_session_checkpoint(&session, role, &our_identity_pk, 0)
            .map_err(OpenError::Invalid)?;
        let this = Self::new(session, role, our_identity_pk, 0);
        match store.read(&this.key) {
            Err(e) => return Err(OpenError::Store(e)),
            Ok(Some(_)) => return Err(OpenError::AlreadyExists),
            Ok(None) => {}
        }
        match store.write(&this.key, &record) {
            Ok(()) => Ok(this),
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
    ) -> Result<Option<Self>, OpenError<S::Error>> {
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

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn role(&self) -> SessionRole {
        self.role
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// `Some(generation)` of the write whose outcome is unknown.
    pub fn unresolved_generation(&self) -> Option<u64> {
        self.unresolved
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
        if let Some(g) = self.unresolved {
            return Err(StageError::Unresolved {
                attempted_generation: g,
            });
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

    /// Writes the staged record and, only if the store reports it committed,
    /// installs the staged ratchet and returns the output.
    ///
    /// Nothing is retried. After [`CommitError::OutcomeUnknown`] the session
    /// refuses further transitions; deciding what the store holds is left to
    /// the caller, and must not rest on rereading an older record alone.
    pub fn commit<S: CheckpointStore, T>(
        &mut self,
        store: &mut S,
        staged: StagedTransition<T>,
    ) -> Result<T, CommitError<S::Error>> {
        if let Some(g) = self.unresolved {
            return Err(CommitError::Unresolved {
                attempted_generation: g,
            });
        }
        if staged.instance != self.instance || staged.base_generation != self.generation {
            return Err(CommitError::StaleTransition);
        }
        match store.write(&self.key, &staged.record) {
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
            Err(WriteFailure::NotCommitted(e)) => Err(CommitError::NotCommitted(e)),
            Err(WriteFailure::OutcomeUnknown(e)) => {
                self.unresolved = Some(staged.generation);
                Err(CommitError::OutcomeUnknown(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_storage::{EncryptedStore, StorageError};
    use rand_core::OsRng;
    use std::collections::HashMap;
    use x25519_dalek::{PublicKey, StaticSecret};

    // ── Stores ────────────────────────────────────────────────────────────────

    /// Adapter over the S1 transaction API: one `BEGIN IMMEDIATE` … `COMMIT`
    /// per checkpoint. Failures before `commit` are rolled back when the
    /// transaction drops; any `commit` error is treated as unknown, because
    /// S1 documents that it can arrive after the commit point.
    struct SqliteStore(EncryptedStore);

    impl CheckpointStore for SqliteStore {
        type Error = StorageError;

        fn read(&mut self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
            match self.0.get(key) {
                Ok(v) => Ok(Some(Zeroizing::new(v))),
                Err(StorageError::NotFound) => Ok(None),
                Err(e) => Err(e),
            }
        }

        fn write(&mut self, key: &str, record: &[u8]) -> Result<(), WriteFailure<StorageError>> {
            let tx = self.0.transaction().map_err(WriteFailure::NotCommitted)?;
            tx.put(key, record).map_err(WriteFailure::NotCommitted)?;
            tx.commit().map_err(WriteFailure::OutcomeUnknown)
        }
    }

    fn sqlite() -> SqliteStore {
        SqliteStore(EncryptedStore::open_in_memory([0x42; 32]).unwrap())
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

    #[derive(Default)]
    struct FakeStore {
        records: HashMap<String, Vec<u8>>,
        next_write: Option<Fault>,
    }

    impl CheckpointStore for FakeStore {
        type Error = &'static str;

        fn read(&mut self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, &'static str> {
            Ok(self.records.get(key).map(|v| Zeroizing::new(v.clone())))
        }

        fn write(&mut self, key: &str, record: &[u8]) -> Result<(), WriteFailure<&'static str>> {
            match self.next_write.take() {
                None => {
                    self.records.insert(key.to_string(), record.to_vec());
                    Ok(())
                }
                Some(Fault::NotCommitted) => Err(WriteFailure::NotCommitted("simulated")),
                Some(Fault::UnknownStored) => {
                    self.records.insert(key.to_string(), record.to_vec());
                    Err(WriteFailure::OutcomeUnknown("simulated"))
                }
                Some(Fault::UnknownLost) => Err(WriteFailure::OutcomeUnknown("simulated")),
            }
        }
    }

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

    fn binding(our: [u8; 32], peer: [u8; 32]) -> SessionBinding {
        SessionBinding {
            our_identity_pk: our,
            peer_identity_pk: peer,
        }
    }

    fn installed(s: &DurableSession) -> Zeroizing<Vec<u8>> {
        s.session().ratchet.to_checkpoint().unwrap()
    }

    fn stored<S: CheckpointStore>(store: &mut S, s: &DurableSession) -> Zeroizing<Vec<u8>>
    where
        S::Error: std::fmt::Debug,
    {
        store.read(&s.key).unwrap().expect("record present")
    }

    fn send<S: CheckpointStore>(
        s: &mut DurableSession,
        store: &mut S,
        m: &[u8],
    ) -> (Header, Vec<u8>)
    where
        S::Error: std::fmt::Debug,
    {
        let staged = s.stage_encrypt(m).unwrap();
        s.commit(store, staged).unwrap()
    }

    fn recv<S: CheckpointStore>(
        s: &mut DurableSession,
        store: &mut S,
        m: &(Header, Vec<u8>),
    ) -> Vec<u8>
    where
        S::Error: std::fmt::Debug,
    {
        let staged = s.stage_decrypt(&m.0, &m.1).unwrap();
        s.commit(store, staged).unwrap()
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn missing_and_invalid_records_are_distinguished() {
        let p = pair();
        let mut store = sqlite();
        let b = binding(p.alice_pk, p.bob_pk);
        assert!(
            DurableSession::load(&mut store, &b).unwrap().is_none(),
            "missing is Ok(None)"
        );

        store
            .0
            .put(&session_storage_key(&p.bob_pk), b"garbage")
            .unwrap();
        assert!(matches!(
            DurableSession::load(&mut store, &b),
            Err(OpenError::Invalid(SessionCheckpointError::Truncated { .. }))
        ));
        // An invalid record is not overwritten by a fresh session either.
        assert!(matches!(
            DurableSession::create(&mut store, p.alice, SessionRole::Initiator, p.alice_pk),
            Err(OpenError::AlreadyExists)
        ));
        assert_eq!(
            store.0.get(&session_storage_key(&p.bob_pk)).unwrap(),
            b"garbage"
        );
    }

    #[test]
    fn create_refuses_to_replace_an_existing_session() {
        let p = pair();
        let mut store = sqlite();
        let s = DurableSession::create(&mut store, p.alice, SessionRole::Initiator, p.alice_pk)
            .unwrap();
        let before = stored(&mut store, &s);
        let mut ad = p.alice_pk.to_vec();
        ad.extend_from_slice(&p.bob_pk);
        let spk = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let fresh = Session {
            ratchet: DoubleRatchet::init_alice([6u8; 32], spk),
            ad,
            peer_identity_pk: p.bob_pk,
        };
        assert!(matches!(
            DurableSession::create(&mut store, fresh, SessionRole::Initiator, p.alice_pk),
            Err(OpenError::AlreadyExists)
        ));
        assert_eq!(*stored(&mut store, &s), *before);
    }

    #[test]
    fn load_checks_the_binding() {
        let p = pair();
        let mut store = sqlite();
        DurableSession::create(&mut store, p.alice, SessionRole::Initiator, p.alice_pk).unwrap();
        let other = PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes();
        assert!(matches!(
            DurableSession::load(&mut store, &binding(other, p.bob_pk)),
            Err(OpenError::Invalid(
                SessionCheckpointError::OurIdentityMismatch
            ))
        ));
    }

    /// Alice and Bob each keep their session only in their own encrypted
    /// store, and are rebuilt from it before every message.
    #[test]
    fn conversation_survives_reloading_both_sides_from_the_store() {
        let p = pair();
        let (mut sa, mut sb) = (sqlite(), sqlite());
        let (ba, bb) = (binding(p.alice_pk, p.bob_pk), binding(p.bob_pk, p.alice_pk));
        DurableSession::create(&mut sa, p.alice, SessionRole::Initiator, p.alice_pk).unwrap();
        DurableSession::create(&mut sb, p.bob, SessionRole::Responder, p.bob_pk).unwrap();

        for i in 0u8..4 {
            let mut a = DurableSession::load(&mut sa, &ba).unwrap().unwrap();
            let msg = send(&mut a, &mut sa, &[i]);
            let mut b = DurableSession::load(&mut sb, &bb).unwrap().unwrap();
            assert_eq!(recv(&mut b, &mut sb, &msg), [i]);
            drop((a, b));

            let mut b = DurableSession::load(&mut sb, &bb).unwrap().unwrap();
            assert_eq!(b.role(), SessionRole::Responder);
            let reply = send(&mut b, &mut sb, &[i, i]);
            let mut a = DurableSession::load(&mut sa, &ba).unwrap().unwrap();
            assert_eq!(recv(&mut a, &mut sa, &reply), [i, i]);
            assert_eq!(a.generation(), 2 * u64::from(i) + 2);
        }
    }

    #[test]
    fn staging_does_not_touch_installed_or_stored_state() {
        let p = pair();
        let mut store = sqlite();
        let s = DurableSession::create(&mut store, p.alice, SessionRole::Initiator, p.alice_pk)
            .unwrap();
        let (mem, disk) = (installed(&s), stored(&mut store, &s));
        let staged = s.stage_encrypt(b"x").unwrap();
        assert_eq!(staged.generation(), 1);
        assert_eq!(*installed(&s), *mem);
        assert_eq!(*stored(&mut store, &s), *disk);
        drop(staged);
        assert_eq!(*installed(&s), *mem);
        assert_eq!(s.generation(), 0);
    }

    /// S1 atomicity: a checkpoint written in a transaction that is dropped
    /// without `commit` is not visible, and the previous generation loads.
    #[test]
    fn uncommitted_s1_transaction_leaves_the_previous_generation() {
        let p = pair();
        let mut store = sqlite();
        let b = binding(p.alice_pk, p.bob_pk);
        let mut s = DurableSession::create(&mut store, p.alice, SessionRole::Initiator, p.alice_pk)
            .unwrap();
        send(&mut s, &mut store, b"one");
        let committed = stored(&mut store, &s);

        let staged = s.stage_encrypt(b"two").unwrap();
        {
            let tx = store.0.transaction().unwrap();
            tx.put(&s.key, &staged.record).unwrap();
            // dropped without commit
        }
        drop(staged);
        assert_eq!(*stored(&mut store, &s), *committed);
        let reloaded = DurableSession::load(&mut store, &b).unwrap().unwrap();
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

        // Another instance of the same session at the same generation.
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
