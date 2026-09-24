//! Tests for [`super`]: semantics, competing instances, simulated commit
//! failures and real process deaths.

use super::*;
use crate::checkpoint::session_storage_key;
use crate::checkpoint::{SessionCheckpointError, SessionRole};
use crate::durable::test_hooks::{self, CommitFault, CRASH_AT_ENV};
use crate::durable::SideWriteError;
use crate::Session;
use core_crypto::ratchet::DoubleRatchet;
use core_crypto::ratchet::RatchetError;
use rand_core::OsRng;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use x25519_dalek::{PublicKey, StaticSecret};

/// A fresh logical message id for each call.
fn cid() -> Vec<u8> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed).to_be_bytes().to_vec()
}

/// The message of a first send of a logical message.
fn new_message(o: SendOutcome) -> OutgoingMessage {
    match o {
        SendOutcome::Sent(m) => m,
        other => panic!("expected a new message, got {other:?}"),
    }
}

const KEY: [u8; 32] = [0x24; 32];
const ALICE_HANDLE: u64 = 0xA11CE;
const BOB_HANDLE: u64 = 0xB0B;

struct Pair {
    alice: Session,
    bob: Session,
    alice_pk: [u8; 32],
    bob_pk: [u8; 32],
}

/// Matching initiator/responder sessions with the X3DH AD layout. The
/// root key is fixed: these tests exercise persistence, not X3DH.
fn pair() -> Pair {
    let alice_pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes();
    let bob_pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes();
    let mut ad = alice_pk.to_vec();
    ad.extend_from_slice(&bob_pk);
    let spk = StaticSecret::random_from_rng(OsRng);
    let root = [9u8; 32];
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

fn new_session(handle: u64, session: Session, role: SessionRole) -> NewSession {
    NewSession {
        handle,
        session,
        role,
        initial_outbound: None,
        extra: Vec::new(),
    }
}

/// Alice (initiator) and Bob (responder), each in their own store.
struct Peers {
    a: EncryptedStore,
    b: EncryptedStore,
    am: Messenger,
    bm: Messenger,
    alice_pk: [u8; 32],
    bob_pk: [u8; 32],
}

fn setup(a: EncryptedStore, b: EncryptedStore) -> Peers {
    let p = pair();
    let mut peers = Peers {
        a,
        b,
        am: Messenger::new(),
        bm: Messenger::new(),
        alice_pk: p.alice_pk,
        bob_pk: p.bob_pk,
    };
    peers
        .am
        .create_session(
            &mut peers.a,
            p.alice_pk,
            new_session(ALICE_HANDLE, p.alice, SessionRole::Initiator),
        )
        .unwrap();
    peers
        .bm
        .create_session(
            &mut peers.b,
            p.bob_pk,
            new_session(BOB_HANDLE, p.bob, SessionRole::Responder),
        )
        .unwrap();
    peers
}

fn memory_peers() -> Peers {
    setup(
        EncryptedStore::open_in_memory(KEY).unwrap(),
        EncryptedStore::open_in_memory(KEY).unwrap(),
    )
}

impl Peers {
    fn alice_sends(&mut self, m: &[u8]) -> OutgoingMessage {
        self.am
            .send(&mut self.a, self.alice_pk, ALICE_HANDLE, &cid(), m)
            .map(new_message)
            .unwrap()
    }
    fn bob_sends(&mut self, m: &[u8]) -> OutgoingMessage {
        self.bm
            .send(&mut self.b, self.bob_pk, BOB_HANDLE, &cid(), m)
            .map(new_message)
            .unwrap()
    }
    fn bob_receives(&mut self, wire: &[u8]) -> Result<Received, MessagingError> {
        self.bm.receive(&mut self.b, self.bob_pk, BOB_HANDLE, wire)
    }
    fn alice_receives(&mut self, wire: &[u8]) -> Result<Received, MessagingError> {
        self.am
            .receive(&mut self.a, self.alice_pk, ALICE_HANDLE, wire)
    }
}

fn generation(store: &mut EncryptedStore, our: [u8; 32], handle: u64) -> u64 {
    Messenger::new()
        .load(store, our, handle)
        .unwrap()
        .0
        .generation()
}

fn accepted(r: Received) -> IncomingMessage {
    match r {
        Received::Accepted(m) => m,
        other => panic!("expected Accepted, got {other:?}"),
    }
}

// ── Outbox and inbox ──────────────────────────────────────────────────────

#[test]
fn a_send_is_committed_with_its_outbox_record_and_returned_unchanged() {
    let mut p = memory_peers();
    let sent = p.alice_sends(b"hello");
    assert_eq!(sent.message_id, message_id(&sent.wire));
    assert_eq!(sent.generation, 1);
    assert_eq!(generation(&mut p.a, p.alice_pk, ALICE_HANDLE), 1);

    let pending = p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap();
    assert_eq!(pending, vec![sent.clone()]);
    // Reading again returns the same bytes and advances nothing.
    assert_eq!(p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap(), pending);
    assert_eq!(generation(&mut p.a, p.alice_pk, ALICE_HANDLE), 1);

    let got = accepted(p.bob_receives(&sent.wire).unwrap());
    assert_eq!(*got.plaintext, b"hello");
    assert_eq!(got.message_id, sent.message_id, "both sides derive one id");

    assert!(p
        .am
        .acknowledge_outgoing(&mut p.a, ALICE_HANDLE, &sent.message_id)
        .unwrap());
    assert!(!p
        .am
        .acknowledge_outgoing(&mut p.a, ALICE_HANDLE, &sent.message_id)
        .unwrap());
    assert!(p
        .am
        .pending_outgoing(&p.a, ALICE_HANDLE)
        .unwrap()
        .is_empty());
}

#[test]
fn pending_outgoing_is_in_send_order() {
    let mut p = memory_peers();
    let sent: Vec<_> = (0u8..5).map(|i| p.alice_sends(&[i])).collect();
    assert_eq!(p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap(), sent);
}

#[test]
fn a_repeated_message_is_a_duplicate_and_advances_nothing() {
    let mut p = memory_peers();
    let sent = p.alice_sends(b"once");
    let first = accepted(p.bob_receives(&sent.wire).unwrap());
    let gen = generation(&mut p.b, p.bob_pk, BOB_HANDLE);

    // Undelivered: the duplicate carries the same message again.
    match p.bob_receives(&sent.wire).unwrap() {
        Received::Duplicate {
            message_id,
            undelivered: Some(m),
        } => {
            assert_eq!(message_id, sent.message_id);
            assert_eq!(m, first);
        }
        other => panic!("expected an undelivered duplicate, got {other:?}"),
    }
    assert_eq!(
        p.bm.pending_incoming(&p.b, BOB_HANDLE).unwrap(),
        vec![first.clone()]
    );

    assert!(p
        .bm
        .acknowledge_incoming(&mut p.b, BOB_HANDLE, &sent.message_id)
        .unwrap());
    assert!(!p
        .bm
        .acknowledge_incoming(&mut p.b, BOB_HANDLE, &sent.message_id)
        .unwrap());
    assert!(p.bm.pending_incoming(&p.b, BOB_HANDLE).unwrap().is_empty());

    // Delivered: still a duplicate, now without plaintext.
    assert_eq!(
        p.bob_receives(&sent.wire).unwrap(),
        Received::Duplicate {
            message_id: sent.message_id,
            undelivered: None
        }
    );
    assert_eq!(generation(&mut p.b, p.bob_pk, BOB_HANDLE), gen);
    // The session keeps working.
    let next = p.alice_sends(b"twice");
    assert_eq!(
        *accepted(p.bob_receives(&next.wire).unwrap()).plaintext,
        b"twice"
    );
}

#[test]
fn acknowledging_an_unknown_incoming_message_is_an_error() {
    let mut p = memory_peers();
    assert!(matches!(
        p.bm.acknowledge_incoming(&mut p.b, BOB_HANDLE, &[7; 32]),
        Err(MessagingError::UnknownMessage)
    ));
}

#[test]
fn a_forged_message_writes_nothing() {
    let mut p = memory_peers();
    let sent = p.alice_sends(b"real");
    let mut forged = sent.wire.clone();
    *forged.last_mut().unwrap() ^= 1;
    assert!(matches!(
        p.bob_receives(&forged),
        Err(MessagingError::Ratchet(RatchetError::Decryption))
    ));
    assert_eq!(generation(&mut p.b, p.bob_pk, BOB_HANDLE), 0);
    assert!(p.bm.pending_incoming(&p.b, BOB_HANDLE).unwrap().is_empty());
    assert!(matches!(
        p.bob_receives(&forged[..10]),
        Err(MessagingError::MalformedMessage)
    ));
    // The real one is still accepted.
    assert_eq!(
        *accepted(p.bob_receives(&sent.wire).unwrap()).plaintext,
        b"real"
    );
}

#[test]
fn out_of_order_messages_are_each_accepted_once() {
    let mut p = memory_peers();
    let m: Vec<_> = (0u8..3).map(|i| p.alice_sends(&[i])).collect();
    for i in [2, 0, 1] {
        assert_eq!(
            *accepted(p.bob_receives(&m[i].wire).unwrap()).plaintext,
            [i as u8]
        );
    }
    for w in &m {
        assert!(matches!(
            p.bob_receives(&w.wire).unwrap(),
            Received::Duplicate { .. }
        ));
    }
}

/// The bytes on the wire are what the in-memory path produced before
/// S2-B2: `header(40) || ciphertext`, readable by a plain ratchet.
#[test]
fn the_wire_format_is_unchanged() {
    let pr = pair();
    let mut a = EncryptedStore::open_in_memory(KEY).unwrap();
    let mut am = Messenger::new();
    let (bob_ad, mut bob) = (pr.bob.ad.clone(), pr.bob.ratchet);
    am.create_session(
        &mut a,
        pr.alice_pk,
        new_session(ALICE_HANDLE, pr.alice, SessionRole::Initiator),
    )
    .unwrap();
    let sent = am
        .send(&mut a, pr.alice_pk, ALICE_HANDLE, &cid(), b"compat")
        .map(new_message)
        .unwrap();
    let header = Header::from_bytes(&sent.wire[..HEADER_SIZE]).unwrap();
    assert_eq!(
        bob.decrypt(&header, &sent.wire[HEADER_SIZE..], &bob_ad)
            .unwrap(),
        b"compat"
    );
}

#[test]
fn a_conversation_survives_reopening_both_stores() {
    let dir = tempfile::tempdir().unwrap();
    let (pa, pb) = (dir.path().join("a.db"), dir.path().join("b.db"));
    let p = setup(
        EncryptedStore::open(&pa, KEY).unwrap(),
        EncryptedStore::open(&pb, KEY).unwrap(),
    );
    let (alice_pk, bob_pk) = (p.alice_pk, p.bob_pk);
    drop(p);
    for i in 0u8..4 {
        let mut p = Peers {
            a: EncryptedStore::open(&pa, KEY).unwrap(),
            b: EncryptedStore::open(&pb, KEY).unwrap(),
            am: Messenger::new(),
            bm: Messenger::new(),
            alice_pk,
            bob_pk,
        };
        let m = p.alice_sends(&[i]);
        assert_eq!(*accepted(p.bob_receives(&m.wire).unwrap()).plaintext, [i]);
        let r = p.bob_sends(&[i, i]);
        assert_eq!(
            *accepted(p.alice_receives(&r.wire).unwrap()).plaintext,
            [i, i]
        );
    }
}

// ── Creation ──────────────────────────────────────────────────────────────

#[test]
fn creation_refuses_an_existing_session_and_a_taken_handle() {
    let mut p = memory_peers();
    let rival = pair();
    // Same peer, another handle: the peer already has a session.
    let mut again = rival.alice;
    again.peer_identity_pk = p.bob_pk;
    let mut ad = p.alice_pk.to_vec();
    ad.extend_from_slice(&p.bob_pk);
    again.ad = ad;
    assert!(matches!(
        p.am.create_session(
            &mut p.a,
            p.alice_pk,
            new_session(77, again, SessionRole::Initiator)
        ),
        Err(MessagingError::AlreadyExists { .. })
    ));
    assert_eq!(p.am.peer_of(&p.a, 77).unwrap(), None, "nothing was written");
    // Another peer on the taken handle.
    assert!(matches!(
        p.am.create_session(
            &mut p.a,
            rival.bob_pk,
            new_session(ALICE_HANDLE, rival.bob, SessionRole::Responder)
        ),
        Err(MessagingError::HandleCollision { .. })
    ));
    assert_eq!(p.am.peer_of(&p.a, ALICE_HANDLE).unwrap(), Some(p.bob_pk));
}

#[test]
fn an_invalid_stored_session_is_reported_and_never_replaced() {
    let mut p = memory_peers();
    let key = session_storage_key(&p.bob_pk);
    p.a.put(&key, b"garbage").unwrap();
    assert!(matches!(
        p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, &cid(), b"x"),
        Err(MessagingError::InvalidSession(
            SessionCheckpointError::Truncated { .. }
        ))
    ));
    let fresh = pair();
    let mut s = fresh.alice;
    s.peer_identity_pk = p.bob_pk;
    let mut ad = p.alice_pk.to_vec();
    ad.extend_from_slice(&p.bob_pk);
    s.ad = ad;
    assert!(matches!(
        p.am.create_session(
            &mut p.a,
            p.alice_pk,
            new_session(5, s, SessionRole::Initiator)
        ),
        Err(MessagingError::AlreadyExists { .. })
    ));
    assert_eq!(p.a.get(&key).unwrap(), b"garbage");
}

#[test]
fn extra_writes_commit_with_the_session_or_not_at_all() {
    let pr = pair();
    let mut s = EncryptedStore::open_in_memory(KEY).unwrap();
    s.put("prekeys/v2", b"old").unwrap();
    let mut m = Messenger::new();
    let stale = SideWrite::replace(
        "prekeys/v2".into(),
        Zeroizing::new(b"not what is stored".to_vec()),
        Zeroizing::new(b"new".to_vec()),
    )
    .unwrap();
    let mut ns = new_session(BOB_HANDLE, pr.bob, SessionRole::Responder);
    ns.extra = vec![stale];
    assert!(matches!(
        m.create_session(&mut s, pr.bob_pk, ns),
        Err(MessagingError::ExtraConflict {
            index: 0,
            conflict: Conflict::RecordChanged
        })
    ));
    assert_eq!(m.peer_of(&s, BOB_HANDLE).unwrap(), None);
    assert!(s.get(&session_storage_key(&pr.alice_pk)).is_err());
    assert_eq!(s.get("prekeys/v2").unwrap(), b"old");
}

#[test]
fn a_side_write_cannot_touch_a_session_record() {
    assert_eq!(
        SideWrite::insert("session:v1/00".into(), Zeroizing::new(vec![1])).err(),
        Some(SideWriteError::ReservedKey)
    );
}

#[test]
fn the_initial_handshake_is_kept_with_the_session() {
    let pr = pair();
    let mut s = EncryptedStore::open_in_memory(KEY).unwrap();
    let mut m = Messenger::new();
    let mut ns = new_session(ALICE_HANDLE, pr.alice, SessionRole::Initiator);
    ns.initial_outbound = Some(vec![1, 2, 3]);
    m.create_session(&mut s, pr.alice_pk, ns).unwrap();
    assert_eq!(
        m.initial_outbound(&s, ALICE_HANDLE).unwrap(),
        Some(vec![1, 2, 3])
    );
}

// ── Competing instances ───────────────────────────────────────────────────

/// Two connections to one database send concurrently. Every send that
/// returned committed a distinct generation and is in the outbox; every
/// failure is a conflict that released nothing; the peer accepts every
/// committed message exactly once.
#[test]
fn concurrent_instances_never_release_two_messages_for_one_position() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.db");
    let mut p = setup(
        EncryptedStore::open(&path, KEY).unwrap(),
        EncryptedStore::open_in_memory(KEY).unwrap(),
    );
    let alice_pk = p.alice_pk;
    let barrier = Arc::new(Barrier::new(2));
    let threads: Vec<_> = (0..2u8)
        .map(|t| {
            let (path, barrier) = (path.clone(), barrier.clone());
            std::thread::spawn(move || {
                let mut db = EncryptedStore::open(&path, KEY).unwrap();
                let mut m = Messenger::new();
                let mut sent = Vec::new();
                let mut conflicts = 0;
                barrier.wait();
                for i in 0..25u8 {
                    match m.send(&mut db, alice_pk, ALICE_HANDLE, &cid(), &[t, i]) {
                        Ok(s) => sent.push(new_message(s)),
                        Err(MessagingError::Conflict(_)) => conflicts += 1,
                        // Lock contention beyond the busy timeout: nothing written.
                        Err(MessagingError::NotCommitted(_)) => conflicts += 1,
                        Err(e) => panic!("unexpected {e:?}"),
                    }
                }
                (sent, conflicts)
            })
        })
        .collect();
    let mut released = Vec::new();
    for t in threads {
        released.extend(t.join().unwrap().0);
    }
    let mut generations: Vec<_> = released.iter().map(|m| m.generation).collect();
    generations.sort_unstable();
    generations.dedup();
    assert_eq!(
        generations.len(),
        released.len(),
        "one message per generation"
    );

    let mut outbox = p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap();
    released.sort_by_key(|m| m.generation);
    outbox.sort_by_key(|m| m.generation);
    assert_eq!(outbox, released, "released exactly what was committed");
    for m in &released {
        assert!(matches!(
            p.bob_receives(&m.wire).unwrap(),
            Received::Accepted(_)
        ));
    }
}

// ── Unknown commit outcome (simulated) ────────────────────────────────────

#[test]
fn an_unknown_send_outcome_releases_nothing_until_recovered() {
    for fault in [CommitFault::UnknownStored, CommitFault::UnknownLost] {
        let mut p = memory_peers();
        test_hooks::inject(fault);
        let r =
            p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, &cid(), b"maybe");
        assert!(matches!(
            r,
            Err(MessagingError::OutcomeUnknown {
                attempted_generation: 1,
                ..
            })
        ));
        assert!(matches!(
            p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, &cid(), b"next"),
            Err(MessagingError::Unresolved {
                attempted_generation: 1
            })
        ));
        let rec =
            p.am.recover(&mut p.a, p.alice_pk, ALICE_HANDLE)
                .unwrap()
                .unwrap();
        let pending = p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap();
        match fault {
            CommitFault::UnknownStored => {
                assert_eq!((rec.stored_generation, rec.artifact_committed), (1, true));
                assert_eq!(pending.len(), 1, "the committed message is in the outbox");
                assert_eq!(
                    *accepted(p.bob_receives(&pending[0].wire).unwrap()).plaintext,
                    b"maybe"
                );
            }
            _ => {
                assert_eq!((rec.stored_generation, rec.artifact_committed), (0, false));
                assert!(pending.is_empty());
            }
        }
        assert_eq!(
            p.am.recover(&mut p.a, p.alice_pk, ALICE_HANDLE).unwrap(),
            None
        );
        let next = p.alice_sends(b"after");
        assert_eq!(
            *accepted(p.bob_receives(&next.wire).unwrap()).plaintext,
            b"after"
        );
    }
}

#[test]
fn an_unknown_receive_outcome_shows_nothing_until_recovered() {
    for fault in [CommitFault::UnknownStored, CommitFault::UnknownLost] {
        let mut p = memory_peers();
        let sent = p.alice_sends(b"in");
        test_hooks::inject(fault);
        assert!(matches!(
            p.bob_receives(&sent.wire),
            Err(MessagingError::OutcomeUnknown { .. })
        ));
        assert!(matches!(
            p.bob_receives(&sent.wire),
            Err(MessagingError::Unresolved { .. })
        ));
        let rec =
            p.bm.recover(&mut p.b, p.bob_pk, BOB_HANDLE)
                .unwrap()
                .unwrap();
        let pending = p.bm.pending_incoming(&p.b, BOB_HANDLE).unwrap();
        match fault {
            CommitFault::UnknownStored => {
                assert!(rec.artifact_committed);
                assert_eq!(*pending[0].plaintext, b"in");
                assert!(matches!(
                    p.bob_receives(&sent.wire).unwrap(),
                    Received::Duplicate { .. }
                ));
            }
            _ => {
                assert!(!rec.artifact_committed);
                assert!(pending.is_empty());
                assert_eq!(
                    *accepted(p.bob_receives(&sent.wire).unwrap()).plaintext,
                    b"in"
                );
            }
        }
    }
}

#[test]
fn a_failed_commit_leaves_the_session_usable_and_consumes_no_position() {
    let mut p = memory_peers();
    test_hooks::inject(CommitFault::NotCommitted);
    assert!(matches!(
        p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, &cid(), b"lost"),
        Err(MessagingError::NotCommitted(_))
    ));
    assert!(p
        .am
        .pending_outgoing(&p.a, ALICE_HANDLE)
        .unwrap()
        .is_empty());
    let sent = p.alice_sends(b"kept");
    let header = Header::from_bytes(&sent.wire[..HEADER_SIZE]).unwrap();
    assert_eq!(header.n, 0, "the failed attempt used no chain position");
    assert_eq!(
        *accepted(p.bob_receives(&sent.wire).unwrap()).plaintext,
        b"kept"
    );
}

mod acceptance;
mod crash;
mod lifecycle;
