//! First contact on the responder side (ARCIUM-SESSION-CONFIRMATION-001):
//! a received handshake is only a provisional record without authority, and
//! [`Messenger::accept_first_message`] creates the session only if the
//! peer's first message authenticates — in one conditional transaction with
//! its handle, its inbox record, the rotated prekey record and the deletion
//! of the provisional record. Specification: `docs/S2-B2-DURABLE-MESSAGING.md`,
//! section 4.
//!
//! The handshake bytes are opaque here; X3DH runs in `mobile-ffi`. These
//! tests use the matching session pair of `pair()` for the cryptography.

use super::*;
use crate::durable::Conflict;

const PREKEYS: &str = "prekeys/v2";

fn provisional(peer: &[u8; 32], bytes: &[u8]) -> ProvisionalHandshake {
    ProvisionalHandshake {
        peer_identity_pk: *peer,
        handshake: bytes.to_vec(),
    }
}

/// Records `p` as `mobile-ffi` does, naming the prekey record as it stands.
fn record_hs(
    m: &Messenger,
    db: &mut EncryptedStore,
    our: [u8; 32],
    handle: u64,
    p: &ProvisionalHandshake,
) -> Result<(), MessagingError> {
    let value = Zeroizing::new(db.get(PREKEYS).unwrap_or_default());
    let validated = ValidatedRecord {
        key: PREKEYS.into(),
        value,
    };
    m.record_provisional_handshake(db, our, handle, p, &validated)
}

fn keys(store: &EncryptedStore, namespace: &str) -> usize {
    store.list_keys_with_prefix(namespace).unwrap().len()
}

/// Alice with a stored initiator session. Bob with a prekey record and
/// Alice's handshake recorded as provisional — no session. The responder
/// session Bob's X3DH derives is kept outside the store, as a checkpoint, so
/// every attempt starts from the same state.
struct Fc {
    a: EncryptedStore,
    b: EncryptedStore,
    am: Messenger,
    bm: Messenger,
    alice_pk: [u8; 32],
    bob_pk: [u8; 32],
    bob_ratchet: Vec<u8>,
    ad: Vec<u8>,
}

fn first_contact(mut a: EncryptedStore, mut b: EncryptedStore) -> Fc {
    let p = pair();
    let mut am = Messenger::new();
    am.create_session(
        &mut a,
        p.alice_pk,
        new_session(ALICE_HANDLE, p.alice, SessionRole::Initiator),
    )
    .unwrap();
    b.put(PREKEYS, b"old").unwrap();
    let bm = Messenger::new();
    record_hs(&bm, &mut b, p.bob_pk, BOB_HANDLE, &provisional(&p.alice_pk, b"hs1"))
        .unwrap();
    Fc {
        a,
        b,
        am,
        bm,
        alice_pk: p.alice_pk,
        bob_pk: p.bob_pk,
        bob_ratchet: p.bob.ratchet.to_checkpoint().unwrap().to_vec(),
        ad: p.bob.ad.clone(),
    }
}

fn memory_first_contact() -> Fc {
    first_contact(
        EncryptedStore::open_in_memory(KEY).unwrap(),
        EncryptedStore::open_in_memory(KEY).unwrap(),
    )
}

impl Fc {
    /// The responder session derived from `hs1`, with the prekey rotation.
    fn first(&self, recorded: &[u8]) -> FirstContact {
        FirstContact {
            handle: BOB_HANDLE,
            session: Session {
                ratchet: DoubleRatchet::from_checkpoint(&self.bob_ratchet).unwrap(),
                ad: self.ad.clone(),
                peer_identity_pk: self.alice_pk,
            },
            provisional: provisional(&self.alice_pk, recorded),
            extra: vec![SideWrite::replace(
                PREKEYS.into(),
                Zeroizing::new(b"old".to_vec()),
                Zeroizing::new(b"rotated".to_vec()),
            )
            .unwrap()],
        }
    }

    fn accept(&mut self, wire: &[u8]) -> Result<Received, MessagingError> {
        let first = self.first(b"hs1");
        self.bm
            .accept_first_message(&mut self.b, self.bob_pk, first, wire)
    }

    fn alice_sends(&mut self, m: &[u8]) -> OutgoingMessage {
        self.am
            .send(&mut self.a, self.alice_pk, ALICE_HANDLE, &cid(), m)
            .map(new_message)
            .unwrap()
    }

    /// Nothing but the provisional record and the untouched prekeys.
    fn assert_provisional_only(&self, recorded: &[u8]) {
        assert_eq!(
            (
                keys(&self.b, "session:"),
                keys(&self.b, "handle:"),
                keys(&self.b, "inbox:"),
                keys(&self.b, "seen:")
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(self.b.get(PREKEYS).unwrap(), b"old");
        assert_eq!(
            self.bm.provisional_handshake(&self.b, BOB_HANDLE).unwrap(),
            Some(provisional(&self.alice_pk, recorded))
        );
    }

    fn session_record(&self) -> Vec<u8> {
        self.b.get(&session_storage_key(&self.alice_pk)).unwrap()
    }
}

#[test]
fn a_recorded_handshake_is_not_a_session() {
    let mut f = memory_first_contact();
    f.assert_provisional_only(b"hs1");
    assert_eq!(f.bm.peer_of(&f.b, BOB_HANDLE).unwrap(), None);
    let m1 = f.alice_sends(b"first");
    assert!(matches!(
        f.bm.receive(&mut f.b, f.bob_pk, BOB_HANDLE, &m1.wire),
        Err(MessagingError::NoSession { .. })
    ));
    assert!(matches!(
        f.bm.remove_session(&mut f.b, f.bob_pk, BOB_HANDLE),
        Err(MessagingError::NoSession { .. })
    ));
    f.assert_provisional_only(b"hs1");
}

#[test]
fn the_first_authenticated_message_creates_the_session_with_everything_it_needs() {
    let mut f = memory_first_contact();
    let m1 = f.alice_sends(b"first");
    let got = accepted(f.accept(&m1.wire).unwrap());
    assert_eq!((got.generation, &**got.plaintext), (1, &b"first"[..]));
    assert_eq!(generation(&mut f.b, f.bob_pk, BOB_HANDLE), 1);
    assert!(f.bm.has_received(&mut f.b, f.bob_pk, BOB_HANDLE).unwrap());
    assert_eq!(f.bm.peer_of(&f.b, BOB_HANDLE).unwrap(), Some(f.alice_pk));
    assert_eq!(f.bm.provisional_handshake(&f.b, BOB_HANDLE).unwrap(), None);
    assert_eq!(f.b.get(PREKEYS).unwrap(), b"rotated");
    assert_eq!(f.bm.pending_incoming(&f.b, BOB_HANDLE).unwrap(), vec![got]);

    // Exactly once: the same message again, by either path, is a duplicate.
    let record = f.session_record();
    assert!(matches!(
        f.accept(&m1.wire).unwrap(),
        Received::Duplicate { .. }
    ));
    assert!(matches!(
        f.bm.receive(&mut f.b, f.bob_pk, BOB_HANDLE, &m1.wire)
            .unwrap(),
        Received::Duplicate { .. }
    ));
    assert_eq!(f.session_record(), record);
    assert_eq!(f.bm.pending_incoming(&f.b, BOB_HANDLE).unwrap().len(), 1);

    let reply =
        f.bm.send(&mut f.b, f.bob_pk, BOB_HANDLE, &cid(), b"reply")
            .map(new_message)
            .unwrap();
    assert_eq!(
        *accepted(
            f.am.receive(&mut f.a, f.alice_pk, ALICE_HANDLE, &reply.wire)
                .unwrap()
        )
        .plaintext,
        b"reply"
    );
}

#[test]
fn a_first_message_that_does_not_authenticate_writes_nothing() {
    let mut f = memory_first_contact();
    let m1 = f.alice_sends(b"first");
    let mut damaged = m1.wire.clone();
    *damaged.last_mut().unwrap() ^= 1;
    assert!(matches!(
        f.accept(&damaged),
        Err(MessagingError::Ratchet(_))
    ));
    assert!(matches!(
        f.accept(&m1.wire[..HEADER_SIZE - 1]),
        Err(MessagingError::MalformedMessage)
    ));
    f.assert_provisional_only(b"hs1");
    assert_eq!(*accepted(f.accept(&m1.wire).unwrap()).plaintext, b"first");
}

#[test]
fn recording_is_refused_once_a_session_exists_and_changes_nothing() {
    let mut f = memory_first_contact();
    let m1 = f.alice_sends(b"first");
    accepted(f.accept(&m1.wire).unwrap());
    let record = f.session_record();
    assert!(matches!(
        record_hs(&f.bm, &mut f.b, f.bob_pk, BOB_HANDLE, &provisional(&f.alice_pk, b"hs2")),
        Err(MessagingError::AlreadyExists { .. })
    ));
    // The peer's session under another handle refuses it too.
    assert!(matches!(
        record_hs(&f.bm, &mut f.b, f.bob_pk, 7, &provisional(&f.alice_pk, b"hs2")),
        Err(MessagingError::AlreadyExists { .. })
    ));
    let carol = pair().alice_pk;
    assert!(matches!(
        record_hs(&f.bm, &mut f.b, f.bob_pk, BOB_HANDLE, &provisional(&carol, b"hs3")),
        Err(MessagingError::HandleCollision { .. })
    ));
    assert_eq!(f.session_record(), record);
    assert_eq!(keys(&f.b, "hsin:"), 0);

    // A session record that cannot be read is never replaced either.
    let mut g = memory_first_contact();
    let dave = pair().alice_pk;
    g.b.put(&session_storage_key(&dave), b"corrupt").unwrap();
    assert!(matches!(
        record_hs(&g.bm, &mut g.b, g.bob_pk, 9, &provisional(&dave, b"hs")),
        Err(MessagingError::AlreadyExists { .. })
    ));
    assert_eq!(keys(&g.b, "hsin:"), 1, "only Alice's");
}

#[test]
fn a_provisional_handshake_is_replaced_by_a_newer_one_and_repeats_change_nothing() {
    let mut f = memory_first_contact();
    record_hs(&f.bm, &mut f.b, f.bob_pk, BOB_HANDLE, &provisional(&f.alice_pk, b"hs1"))
        .unwrap();
    f.assert_provisional_only(b"hs1");
    record_hs(&f.bm, &mut f.b, f.bob_pk, BOB_HANDLE, &provisional(&f.alice_pk, b"hs2"))
        .unwrap();
    f.assert_provisional_only(b"hs2");

    // A session derived from the replaced handshake is not created, even
    // from a message that authenticates under it.
    let m1 = f.alice_sends(b"first");
    assert!(matches!(
        f.accept(&m1.wire),
        Err(MessagingError::Conflict(Conflict::RecordChanged))
    ));
    f.assert_provisional_only(b"hs2");
    let first = f.first(b"hs2");
    accepted(
        f.bm.accept_first_message(&mut f.b, f.bob_pk, first, &m1.wire)
            .unwrap(),
    );
}

#[test]
fn an_acceptance_for_another_peer_s_handshake_is_refused() {
    let mut f = memory_first_contact();
    let m1 = f.alice_sends(b"first");
    let mut first = f.first(b"hs1");
    first.provisional.peer_identity_pk = pair().alice_pk;
    assert!(matches!(
        f.bm.accept_first_message(&mut f.b, f.bob_pk, first, &m1.wire),
        Err(MessagingError::InconsistentStore(_))
    ));
    f.assert_provisional_only(b"hs1");
}

/// 9: an acceptance staged while another connection created the session
/// from a first message commits nothing over it; its own message is then
/// received on that session — once.
#[test]
fn a_stale_acceptance_never_overwrites_the_session_another_instance_created() {
    for other_message_first in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.db");
        let mut f = first_contact(
            EncryptedStore::open_in_memory(KEY).unwrap(),
            EncryptedStore::open(&path, KEY).unwrap(),
        );
        let m1 = f.alice_sends(b"one");
        let m2 = f.alice_sends(b"two");
        let winner_wire = if other_message_first {
            m2.wire.clone()
        } else {
            m1.wire.clone()
        };
        let winners_record = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (first, bob_pk, alice_pk, out) = (
            f.first(b"hs1"),
            f.bob_pk,
            f.alice_pk,
            winners_record.clone(),
        );
        crate::messaging::race_hook::set(move || {
            let mut db = EncryptedStore::open(&path, KEY).unwrap();
            let mut m = Messenger::new();
            accepted(
                m.accept_first_message(&mut db, bob_pk, first, &winner_wire)
                    .unwrap(),
            );
            *out.lock().unwrap() = db.get(&session_storage_key(&alice_pk)).unwrap();
        });
        let result = f.accept(&m1.wire).unwrap();
        let winners = winners_record.lock().unwrap().clone();
        if other_message_first {
            // m1 is new to the winner's session: received there, from its
            // skipped key, as that session's next generation.
            assert_eq!(accepted(result).generation, 2);
            assert_eq!(generation(&mut f.b, f.bob_pk, BOB_HANDLE), 2);
        } else {
            assert!(matches!(result, Received::Duplicate { .. }));
            assert_eq!(f.session_record(), winners, "the winner's record stands");
        }
        assert_eq!(f.b.get(PREKEYS).unwrap(), b"rotated");
        assert_eq!(keys(&f.b, "hsin:"), 0);
        let pending = f.bm.pending_incoming(&f.b, BOB_HANDLE).unwrap();
        assert_eq!(
            pending.len(),
            1 + other_message_first as usize,
            "each accepted once"
        );
    }
}

/// A handshake replaced between staging and commit: the acceptance staged
/// from the old one commits nothing.
#[test]
fn a_handshake_replaced_while_accepting_makes_the_acceptance_write_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("b.db");
    let mut f = first_contact(
        EncryptedStore::open_in_memory(KEY).unwrap(),
        EncryptedStore::open(&path, KEY).unwrap(),
    );
    let (alice_pk, bob_pk) = (f.alice_pk, f.bob_pk);
    crate::messaging::race_hook::set(move || {
        let mut db = EncryptedStore::open(&path, KEY).unwrap();
        let hs2 = provisional(&alice_pk, b"hs2");
        record_hs(&Messenger::new(), &mut db, bob_pk, BOB_HANDLE, &hs2).unwrap();
    });
    let m1 = f.alice_sends(b"first");
    assert!(matches!(
        f.accept(&m1.wire),
        Err(MessagingError::Conflict(Conflict::RecordChanged))
    ));
    f.assert_provisional_only(b"hs2");
}

/// A prekey record that changed after it was validated — another peer's
/// first message consumed the one-time prekey between staging and commit —
/// makes the acceptance write nothing: a one-time prekey contributes to one
/// stored session only.
#[test]
fn a_prekey_record_changed_while_accepting_makes_the_acceptance_write_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("b.db");
    let mut f = first_contact(
        EncryptedStore::open_in_memory(KEY).unwrap(),
        EncryptedStore::open(&path, KEY).unwrap(),
    );
    crate::messaging::race_hook::set(move || {
        EncryptedStore::open(&path, KEY)
            .unwrap()
            .put(PREKEYS, b"rotated by another first contact")
            .unwrap();
    });
    let m1 = f.alice_sends(b"first");
    assert!(matches!(
        f.accept(&m1.wire),
        Err(MessagingError::ExtraConflict {
            index: 0,
            conflict: Conflict::RecordChanged
        })
    ));
    assert_eq!(
        (
            keys(&f.b, "session:"),
            keys(&f.b, "handle:"),
            keys(&f.b, "inbox:")
        ),
        (0, 0, 0)
    );
    assert!(f
        .bm
        .provisional_handshake(&f.b, BOB_HANDLE)
        .unwrap()
        .is_some());
}

/// 8 (simulated): an unknown commit outcome of the acceptance is resolved as
/// an unknown creation; a definite failure writes nothing.
#[test]
fn an_unknown_first_message_outcome_is_recovered_like_a_creation() {
    for fault in [
        CommitFault::UnknownStored,
        CommitFault::UnknownLost,
        CommitFault::NotCommitted,
    ] {
        let mut f = memory_first_contact();
        let m1 = f.alice_sends(b"first");
        test_hooks::inject(fault);
        let r = f.accept(&m1.wire);
        if let CommitFault::NotCommitted = fault {
            assert!(matches!(r, Err(MessagingError::NotCommitted(_))), "{r:?}");
            f.assert_provisional_only(b"hs1");
            accepted(f.accept(&m1.wire).unwrap());
            continue;
        }
        assert!(matches!(
            r,
            Err(MessagingError::OutcomeUnknown {
                attempted_generation: 1,
                ..
            })
        ));
        // Nothing proceeds on the handle until it is recovered.
        assert!(matches!(
            f.accept(&m1.wire),
            Err(MessagingError::Unresolved { .. })
        ));
        assert!(matches!(
            f.bm.receive(&mut f.b, f.bob_pk, BOB_HANDLE, &m1.wire),
            Err(MessagingError::Unresolved { .. })
        ));
        let rec =
            f.bm.recover(&mut f.b, f.bob_pk, BOB_HANDLE)
                .unwrap()
                .unwrap();
        assert_eq!(rec.attempted_generation, 1);
        match fault {
            CommitFault::UnknownStored => {
                assert_eq!((rec.stored_generation, rec.artifact_committed), (1, true));
                assert!(matches!(
                    f.bm.receive(&mut f.b, f.bob_pk, BOB_HANDLE, &m1.wire)
                        .unwrap(),
                    Received::Duplicate { .. }
                ));
            }
            _ => {
                assert_eq!((rec.stored_generation, rec.artifact_committed), (0, false));
                f.assert_provisional_only(b"hs1");
                accepted(f.accept(&m1.wire).unwrap());
            }
        }
    }
}

// ── Process death inside the acceptance's transaction ─────────────────────────

const CHILD_ENV: &str = "ARCIUM_FIRST_CHILD";
const DIR_ENV: &str = "ARCIUM_FIRST_DIR";

/// Reopens the fixture written by `file_fixture`.
fn reopen(dir: &Path) -> Fc {
    let state = std::fs::read(dir.join("state")).unwrap();
    let (alice_pk, rest) = state.split_at(32);
    let (bob_pk, rest) = rest.split_at(32);
    let (ad, bob_ratchet) = rest.split_at(64);
    Fc {
        a: EncryptedStore::open(dir.join("a.db"), KEY).unwrap(),
        b: EncryptedStore::open(dir.join("b.db"), KEY).unwrap(),
        am: Messenger::new(),
        bm: Messenger::new(),
        alice_pk: alice_pk.try_into().unwrap(),
        bob_pk: bob_pk.try_into().unwrap(),
        bob_ratchet: bob_ratchet.to_vec(),
        ad: ad.to_vec(),
    }
}

fn file_fixture(dir: &Path) -> Vec<u8> {
    let mut f = first_contact(
        EncryptedStore::open(dir.join("a.db"), KEY).unwrap(),
        EncryptedStore::open(dir.join("b.db"), KEY).unwrap(),
    );
    let state = [
        &f.alice_pk[..],
        &f.bob_pk[..],
        &f.ad[..],
        &f.bob_ratchet[..],
    ]
    .concat();
    std::fs::write(dir.join("state"), state).unwrap();
    let m1 = f.alice_sends(b"first");
    std::fs::write(dir.join("wire"), &m1.wire).unwrap();
    m1.wire
}

#[test]
fn first_contact_child() {
    let (Ok(_), Ok(dir)) = (std::env::var(CHILD_ENV), std::env::var(DIR_ENV)) else {
        return; // Not a child run.
    };
    let dir = PathBuf::from(dir);
    let mut f = reopen(&dir);
    let wire = std::fs::read(dir.join("wire")).unwrap();
    accepted(f.accept(&wire).unwrap());
    std::process::abort();
}

#[cfg(unix)]
fn run_first_child(dir: &Path, point: &str) {
    use std::os::unix::process::ExitStatusExt;
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "messaging::tests::first_contact::first_contact_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, "accept")
        .env(DIR_ENV, dir)
        .env(CRASH_AT_ENV, point)
        .status()
        .unwrap();
    assert_eq!(
        status.signal(),
        Some(6),
        "child must die by abort(): {status:?}"
    );
}

/// 8: a process that dies inside the acceptance's transaction leaves either
/// nothing — the handshake still provisional, the prekeys untouched — or all
/// of it: session, handle, inbox record, rotated prekeys, no provisional
/// record. Never a part.
#[cfg(unix)]
#[test]
fn a_process_killed_while_accepting_a_first_message_leaves_all_or_nothing() {
    for point in ["before_commit", "after_commit"] {
        let dir = tempfile::tempdir().unwrap();
        let wire = file_fixture(dir.path());
        run_first_child(dir.path(), point);
        let mut f = reopen(dir.path());
        if point == "before_commit" {
            f.assert_provisional_only(b"hs1");
            assert_eq!(*accepted(f.accept(&wire).unwrap()).plaintext, b"first");
        } else {
            assert_eq!(generation(&mut f.b, f.bob_pk, BOB_HANDLE), 1);
            assert_eq!(f.bm.peer_of(&f.b, BOB_HANDLE).unwrap(), Some(f.alice_pk));
            assert_eq!(f.bm.provisional_handshake(&f.b, BOB_HANDLE).unwrap(), None);
            assert_eq!(f.b.get(PREKEYS).unwrap(), b"rotated");
            assert_eq!(f.bm.pending_incoming(&f.b, BOB_HANDLE).unwrap().len(), 1);
            assert!(matches!(
                f.accept(&wire).unwrap(),
                Received::Duplicate { .. }
            ));
        }
    }
}
