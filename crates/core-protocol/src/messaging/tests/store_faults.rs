//! Storage faults under durable messaging (reliability plan, step 2.2).
//!
//! A case runs one operation of [`Messenger`] once without a fault, noting
//! every store operation it makes, and then once per store operation and
//! per outcome the fault layer has (`core_storage::fault`), with that one
//! operation failing. After each failed run it checks what the layer
//! promises of a failure:
//!
//! - the call returns an error, and the error carries the storage failure;
//! - the store holds either what it held before or the records a run
//!   without a fault leaves (compared by key, length and the fixed start of
//!   each record: see [`shape`]), never a part of them;
//! - if the writes are stored, the error says the outcome is unknown: no
//!   error that means "nothing was written" is returned over a stored write;
//! - an unknown outcome is reported as the kind the operation has: a session
//!   transition's leaves the session unresolved, refusing a send, until
//!   `recover`, and `recover` reports what the store holds; any other
//!   operation's can simply be repeated;
//! - after that, repeating the same logical operation ends where a run
//!   without a fault ends, and the two devices can still read each other.
//!
//! # What this does not show
//!
//! - The fault layer returns errors: it does not tear a write, lose an
//!   `fsync` or cut power, and a real I/O error may leave SQLite in a state
//!   the two outcomes copied here do not cover. One fault per run, on an
//!   in-memory store.
//! - Operations not covered: `accept_first_message` (how a responder's
//!   session is created today), `record_provisional_handshake` and
//!   `record_handshake_beside`, `receive_far`, `remove_session`,
//!   `retire_session` and `forget_peer`.
//! - The confirm hook. `mobile-ffi` gives its `Messenger` one
//!   (`with_confirm_hook`), which reads the store and adds a write to the
//!   initiator's first receive; the messengers here have none.
//! - A receive that deletes a handshake recorded beside the session: no
//!   seed here holds one, so only the "none is recorded" check runs.
//! - Records outside the messaging layer's own namespaces ([`NAMESPACES`]):
//!   the store cannot list all its keys, so a write elsewhere would not be
//!   seen. The eight operations here write none.

use super::*;
use core_storage::fault::{self, Op, Outcome};

/// Every namespace the messaging layer writes.
const NAMESPACES: [&str; 8] = [
    "session:", "handle:", "hsout:", "hsin:", "outbox:", "inbox:", "seen:", "sendid:",
];

/// Every record of the messaging layer in a store: key and plaintext.
type Dump = Vec<(String, Vec<u8>)>;

fn dump(store: &EncryptedStore) -> Dump {
    let mut out = Dump::new();
    for namespace in NAMESPACES {
        for key in store.list_keys_with_prefix(namespace).unwrap() {
            let value = store.get(&key).unwrap();
            out.push((key, value));
        }
    }
    out.sort();
    out
}

/// A new store holding the records of `dump`.
fn restore(dump: &Dump) -> EncryptedStore {
    let store = EncryptedStore::open_in_memory(KEY).unwrap();
    for (key, value) in dump {
        store.put(key, value).unwrap();
    }
    store
}

/// What a dump holds apart from the bytes that differ between two runs of
/// the same operation on equal stores (a message's random nonce, and so its
/// id; a new ratchet key): per record, its key without a message id, its
/// length, and the start of its value as far as that is the same in both
/// runs. For every record that is its magic and version, so one kind of
/// record is not taken for another of the same length; for a session
/// checkpoint also its role and generation, for an outbox or inbox record
/// its generation, and a handle or handshake record whole.
type Shape = Vec<(String, usize, Vec<u8>)>;

fn shape(dump: &Dump) -> Shape {
    let mut out: Shape = dump
        .iter()
        .map(|(key, value)| {
            let namespace = &key[..=key.find(':').expect("a namespace")];
            let (by_message_id, same) = match namespace {
                "session:" => (false, 17),
                "outbox:" | "inbox:" => (true, 16),
                "seen:" => (true, 8),
                "sendid:" => (false, 8),
                _ => (false, value.len()),
            };
            let kind = match key.rsplit_once('/') {
                Some((dir, _)) if by_message_id => format!("{dir}/<message id>"),
                _ => key.clone(),
            };
            (kind, value.len(), value[..same.min(value.len())].to_vec())
        })
        .collect();
    out.sort();
    out
}

/// Two devices' stores at one moment, to start any number of equal runs
/// from.
struct Seed {
    a: Dump,
    b: Dump,
    alice_pk: [u8; 32],
    bob_pk: [u8; 32],
}

impl Seed {
    fn of(p: &Peers) -> Self {
        Self {
            a: dump(&p.a),
            b: dump(&p.b),
            alice_pk: p.alice_pk,
            bob_pk: p.bob_pk,
        }
    }

    /// The two devices again, each with a new [`Messenger`], as after a
    /// restart.
    fn peers(&self) -> Peers {
        Peers {
            a: restore(&self.a),
            b: restore(&self.b),
            am: Messenger::new(),
            bm: Messenger::new(),
            alice_pk: self.alice_pk,
            bob_pk: self.bob_pk,
        }
    }
}

/// The device whose store the operation under test writes.
#[derive(Clone, Copy, Debug)]
enum Side {
    Alice,
    Bob,
}

impl Side {
    fn store(self, p: &Peers) -> &EncryptedStore {
        match self {
            Side::Alice => &p.a,
            Side::Bob => &p.b,
        }
    }

    fn unresolved(self, p: &Peers) -> Option<u64> {
        match self {
            Side::Alice => p.am.unresolved_generation(ALICE_HANDLE),
            Side::Bob => p.bm.unresolved_generation(BOB_HANDLE),
        }
    }

    fn send(self, p: &mut Peers, id: &[u8], text: &[u8]) -> Result<SendOutcome, MessagingError> {
        match self {
            Side::Alice => p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, id, text),
            Side::Bob => p.bm.send(&mut p.b, p.bob_pk, BOB_HANDLE, id, text),
        }
    }

    fn recover(self, p: &mut Peers) -> Result<Option<Recovery>, MessagingError> {
        match self {
            Side::Alice => p.am.recover(&mut p.a, p.alice_pk, ALICE_HANDLE),
            Side::Bob => p.bm.recover(&mut p.b, p.bob_pk, BOB_HANDLE),
        }
    }
}

/// The storage failure `error` carries, if it reports one.
fn storage_failure(error: &MessagingError) -> Option<&StorageError> {
    match error {
        MessagingError::Store(e)
        | MessagingError::NotCommitted(e)
        | MessagingError::RepeatableOutcomeUnknown(e)
        | MessagingError::OutcomeUnknown { error: e, .. } => Some(e),
        _ => None,
    }
}

/// One operation to fail in every way the fault layer can.
struct Case<'a, T> {
    name: &'a str,
    seed: &'a Seed,
    side: Side,
    /// The operation under test.
    run: &'a dyn Fn(&mut Peers) -> Result<T, MessagingError>,
    /// Whether it is a session transition, whose unknown outcome leaves the
    /// session unresolved, and not an operation that can simply be repeated.
    transition: bool,
    /// Repeats the logical operation after a failed run (and after
    /// `recover`, where the session was unresolved) and checks where the two
    /// devices end. `took_effect`: the failed run's writes are stored.
    finish: &'a dyn Fn(&mut Peers, bool),
}

/// Runs `case`: see the module documentation. Returns how many failed runs
/// it made.
fn sweep<T: std::fmt::Debug>(case: Case<'_, T>) -> usize {
    let Case {
        name,
        seed,
        side,
        run,
        transition,
        finish,
    } = case;
    let before = dump(side.store(&seed.peers()));

    // Without a fault: which store operations the call makes, and what the
    // store holds afterwards.
    let mut clean = seed.peers();
    let (result, ops) = fault::trace(|| run(&mut clean));
    result.unwrap_or_else(|e| panic!("{name}: failed without a fault: {e:?}"));
    let success = dump(side.store(&clean));
    assert_ne!(success, before, "{name}: the operation writes something");
    let success = shape(&success);
    // What is compared below is the same from run to run.
    let mut second = seed.peers();
    run(&mut second).unwrap_or_else(|e| panic!("{name}: failed without a fault: {e:?}"));
    assert_eq!(
        shape(&dump(side.store(&second))),
        success,
        "{name}: two runs without a fault end alike"
    );
    // `finish` holds after a run without a fault too.
    finish(&mut clean, true);

    let (mut runs, mut stored, mut recovered) = (0, 0, 0);
    for (n, op) in ops.iter().enumerate() {
        let mut outcomes = vec![Outcome::NotRun, Outcome::TransactionEnded];
        if *op == Op::Commit {
            outcomes.push(Outcome::Committed);
        }
        for outcome in outcomes {
            let at = format!("{name}: {outcome:?} at store operation {n} ({op:?})");
            let mut p = seed.peers();
            let armed = match outcome {
                Outcome::Committed => {
                    let earlier = ops[..n].iter().filter(|o| **o == Op::Commit).count();
                    fault::arm(Op::Commit, earlier, outcome)
                }
                _ => fault::arm_any(n, outcome),
            };
            let result = run(&mut p);
            assert!(armed.fired(), "{at}: the fault did not fire");
            drop(armed);

            // The call fails, and says it was the store.
            let error = match result {
                Err(error) => error,
                Ok(value) => panic!("{at}: returned {value:?} over a failed store operation"),
            };
            let failure = storage_failure(&error)
                .unwrap_or_else(|| panic!("{at}: {error:?} does not report a storage failure"));
            assert!(
                fault::is_injected(failure),
                "{at}: {error:?} carries another failure than the injected one"
            );

            // All of it or nothing.
            let after = dump(side.store(&p));
            let took_effect = after != before;
            if took_effect {
                assert_eq!(
                    shape(&after),
                    success,
                    "{at}: the store holds a part of what the operation writes"
                );
            }

            // Stored writes are never reported as not written, and an unknown
            // outcome is reported as the kind the operation has.
            let unknown_of_transition = match &error {
                MessagingError::OutcomeUnknown { .. } => Some(true),
                MessagingError::RepeatableOutcomeUnknown(_) => Some(false),
                _ => None,
            };
            assert!(
                unknown_of_transition.is_some() || !took_effect,
                "{at}: the writes are stored, and the error says otherwise: {error:?}"
            );
            assert!(
                unknown_of_transition.is_none_or(|kind| kind == transition),
                "{at}: the wrong kind of unknown outcome for this operation: {error:?}"
            );
            stored += usize::from(took_effect);

            // An unknown outcome of a session transition leaves the session
            // unresolved until `recover`, which reports what is stored.
            if let MessagingError::OutcomeUnknown {
                attempted_generation,
                ..
            } = error
            {
                assert_eq!(side.unresolved(&p), Some(attempted_generation), "{at}");
                assert!(
                    matches!(
                        side.send(&mut p, b"refused", b"x"),
                        Err(MessagingError::Unresolved { .. })
                    ),
                    "{at}: a send is refused while the session is unresolved"
                );
                assert_eq!(
                    dump(side.store(&p)),
                    after,
                    "{at}: the refused send wrote nothing"
                );
                let recovery = side
                    .recover(&mut p)
                    .unwrap_or_else(|e| panic!("{at}: recover failed: {e:?}"))
                    .unwrap_or_else(|| panic!("{at}: recover found nothing unresolved"));
                assert_eq!(recovery.attempted_generation, attempted_generation, "{at}");
                assert_eq!(recovery.artifact_committed, took_effect, "{at}");
                let stored_generation = match took_effect {
                    true => attempted_generation,
                    false => attempted_generation.saturating_sub(1),
                };
                assert_eq!(recovery.stored_generation, stored_generation, "{at}");
                recovered += 1;
            }
            assert_eq!(side.unresolved(&p), None, "{at}");

            // The logical operation can be completed, once.
            finish(&mut p, took_effect);
            runs += 1;
        }
    }
    // The sweep reached what it is for: a failed run whose writes are
    // stored, and, for a session transition only, an unresolved session.
    assert!(stored > 0, "{name}: no failed run left its writes stored");
    assert_eq!(
        recovered > 0,
        transition,
        "{name}: {recovered} failed runs left the session unresolved"
    );
    runs
}

// ── Scenarios ─────────────────────────────────────────────────────────────

const FIRST: &[u8] = b"first";
const HELLO: &[u8] = b"hello";

/// One message from each device reaches the other.
fn converse(p: &mut Peers) {
    let to_bob = p.alice_sends(b"to bob");
    assert_eq!(
        *accepted(p.bob_receives(&to_bob.wire).unwrap()).plaintext,
        b"to bob"
    );
    let to_alice = p.bob_sends(b"to alice");
    assert_eq!(
        *accepted(p.alice_receives(&to_alice.wire).unwrap()).plaintext,
        b"to alice"
    );
}

/// Both sessions exist; nothing was sent.
fn fresh() -> Seed {
    Seed::of(&memory_peers())
}

/// Alice committed `HELLO` under the logical id `FIRST`.
fn alice_sent() -> (Seed, OutgoingMessage) {
    let mut p = memory_peers();
    let message = new_message(
        p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, FIRST, HELLO)
            .unwrap(),
    );
    (Seed::of(&p), message)
}

/// As [`alice_sent`], and Bob accepted it.
fn bob_received() -> (Peers, OutgoingMessage) {
    let mut p = memory_peers();
    let message = new_message(
        p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, FIRST, HELLO)
            .unwrap(),
    );
    accepted(p.bob_receives(&message.wire).unwrap());
    (p, message)
}

/// After a failed receive of `wire` (whose text is `text`) on `side`: the
/// message is accepted exactly once and waits in the inbox with `others`
/// accepted before it.
fn finish_receive(
    p: &mut Peers,
    side: Side,
    wire: &[u8],
    text: &[u8],
    others: usize,
    took_effect: bool,
) {
    let again = match side {
        Side::Alice => p.alice_receives(wire),
        Side::Bob => p.bob_receives(wire),
    }
    .unwrap();
    let message = match (took_effect, again) {
        (false, Received::Accepted(message)) => message,
        (
            true,
            Received::Duplicate {
                undelivered: Some(message),
                ..
            },
        ) => message,
        (_, other) => panic!("took_effect {took_effect}: {other:?}"),
    };
    assert_eq!(*message.plaintext, text);
    let pending = match side {
        Side::Alice => p.am.pending_incoming(&p.a, ALICE_HANDLE),
        Side::Bob => p.bm.pending_incoming(&p.b, BOB_HANDLE),
    }
    .unwrap();
    assert_eq!(pending.len(), others + 1);
    assert_eq!(
        pending
            .iter()
            .filter(|m| m.message_id == message.message_id)
            .count(),
        1
    );
    converse(p);
}

#[test]
fn a_send_survives_every_store_fault() {
    let seed = fresh();
    sweep(Case {
        name: "send",
        seed: &seed,
        side: Side::Alice,
        run: &|p| p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, FIRST, HELLO),
        transition: true,
        finish: &|p, took_effect| {
            let again =
                p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, FIRST, HELLO)
                    .unwrap();
            let message = match (took_effect, again) {
                (false, SendOutcome::Sent(message)) => message,
                (true, SendOutcome::AlreadyPending(message)) => message,
                (_, other) => panic!("took_effect {took_effect}: {other:?}"),
            };
            assert_eq!(
                p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap(),
                std::slice::from_ref(&message),
                "one message for the logical id"
            );
            let header = Header::from_bytes(&message.wire[..HEADER_SIZE]).unwrap();
            assert_eq!(
                header.n, 0,
                "the failed run used no chain position of its own"
            );
            assert_eq!(
                *accepted(p.bob_receives(&message.wire).unwrap()).plaintext,
                HELLO
            );
            converse(p);
        },
    });
}

/// The first message from the peer on a responder session stored without
/// one, as builds before ARCIUM-SESSION-CONFIRMATION-001 stored it on a
/// handshake (`DurableSession::is_legacy_unconfirmed`). A responder's
/// session is created by `accept_first_message` today, which is not covered
/// here.
#[test]
fn a_first_receive_on_a_legacy_responder_session_survives_every_store_fault() {
    let (seed, message) = alice_sent();
    sweep(Case {
        name: "first receive on a legacy responder session",
        seed: &seed,
        side: Side::Bob,
        run: &|p| p.bob_receives(&message.wire),
        transition: true,
        finish: &|p, took_effect| {
            finish_receive(p, Side::Bob, &message.wire, HELLO, 0, took_effect)
        },
    });
}

/// A receive on a session that has received before.
#[test]
fn a_later_receive_survives_every_store_fault() {
    let (mut p, _) = bob_received();
    let second = p.alice_sends(b"second");
    let seed = Seed::of(&p);
    sweep(Case {
        name: "later receive",
        seed: &seed,
        side: Side::Bob,
        run: &|p| p.bob_receives(&second.wire),
        transition: true,
        finish: &|p, took_effect| {
            finish_receive(p, Side::Bob, &second.wire, b"second", 1, took_effect)
        },
    });
}

/// The initiator's first message from the peer.
#[test]
fn an_initiators_first_receive_survives_every_store_fault() {
    let (mut p, _) = bob_received();
    let reply = p.bob_sends(b"reply");
    let seed = Seed::of(&p);
    sweep(Case {
        name: "initiator's first receive",
        seed: &seed,
        side: Side::Alice,
        run: &|p| p.alice_receives(&reply.wire),
        transition: true,
        finish: &|p, took_effect| {
            finish_receive(p, Side::Alice, &reply.wire, b"reply", 0, took_effect)
        },
    });
}

#[test]
fn acknowledging_an_outgoing_message_survives_every_store_fault() {
    let (seed, message) = alice_sent();
    sweep(Case {
        name: "acknowledge_outgoing",
        seed: &seed,
        side: Side::Alice,
        run: &|p| {
            p.am.acknowledge_outgoing(&mut p.a, ALICE_HANDLE, &message.message_id)
        },
        transition: false,
        finish: &|p, took_effect| {
            let still_pending =
                p.am.acknowledge_outgoing(&mut p.a, ALICE_HANDLE, &message.message_id)
                    .unwrap();
            assert_eq!(still_pending, !took_effect);
            assert!(p
                .am
                .pending_outgoing(&p.a, ALICE_HANDLE)
                .unwrap()
                .is_empty());
            assert_eq!(
                p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, FIRST, HELLO)
                    .unwrap(),
                SendOutcome::AlreadyAcknowledged {
                    message_id: message.message_id
                },
                "the logical id is not encrypted again"
            );
            assert_eq!(
                *accepted(p.bob_receives(&message.wire).unwrap()).plaintext,
                HELLO
            );
            converse(p);
        },
    });
}

#[test]
fn abandoning_an_outgoing_message_survives_every_store_fault() {
    let (seed, message) = alice_sent();
    sweep(Case {
        name: "abandon_outgoing",
        seed: &seed,
        side: Side::Alice,
        run: &|p| {
            p.am.abandon_outgoing(&mut p.a, ALICE_HANDLE, &message.message_id)
        },
        transition: false,
        finish: &|p, took_effect| {
            let still_pending =
                p.am.abandon_outgoing(&mut p.a, ALICE_HANDLE, &message.message_id)
                    .unwrap();
            assert_eq!(still_pending, !took_effect);
            assert!(p
                .am
                .pending_outgoing(&p.a, ALICE_HANDLE)
                .unwrap()
                .is_empty());
            assert_eq!(
                p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, FIRST, HELLO)
                    .unwrap(),
                SendOutcome::Abandoned {
                    message_id: message.message_id
                },
                "the logical id is not encrypted again"
            );
            converse(p);
        },
    });
}

#[test]
fn acknowledging_an_incoming_message_survives_every_store_fault() {
    let (p, message) = bob_received();
    let seed = Seed::of(&p);
    sweep(Case {
        name: "acknowledge_incoming",
        seed: &seed,
        side: Side::Bob,
        run: &|p| {
            p.bm.acknowledge_incoming(&mut p.b, BOB_HANDLE, &message.message_id)
        },
        transition: false,
        finish: &|p, took_effect| {
            let undelivered =
                p.bm.acknowledge_incoming(&mut p.b, BOB_HANDLE, &message.message_id)
                    .unwrap();
            assert_eq!(undelivered, !took_effect);
            assert!(p.bm.pending_incoming(&p.b, BOB_HANDLE).unwrap().is_empty());
            assert_eq!(
                p.bob_receives(&message.wire).unwrap(),
                Received::Duplicate {
                    message_id: message.message_id,
                    undelivered: None
                },
                "still recognised, and not shown again"
            );
            converse(p);
        },
    });
}

/// Creating the initiator's session, with its handshake stored beside it.
#[test]
fn creating_a_session_survives_every_store_fault() {
    // As `pair`, keeping what a new initiator session is made from: each run
    // creates its own, with a ratchet key of its own.
    let alice_pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes();
    let bob_pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes();
    let ad = [alice_pk, bob_pk].concat();
    let spk = StaticSecret::random_from_rng(OsRng);
    let spk_public = PublicKey::from(&spk);
    let root = [9u8; 32];
    let bob = Session {
        ratchet: DoubleRatchet::init_bob(&root, spk),
        ad: ad.clone(),
        peer_identity_pk: alice_pk,
    };
    let mut b = EncryptedStore::open_in_memory(KEY).unwrap();
    Messenger::new()
        .create_session(
            &mut b,
            bob_pk,
            new_session(BOB_HANDLE, bob, SessionRole::Responder),
        )
        .unwrap();
    let seed = Seed {
        a: Dump::new(),
        b: dump(&b),
        alice_pk,
        bob_pk,
    };
    let create = |p: &mut Peers| {
        let session = Session {
            ratchet: DoubleRatchet::init_alice(&root, spk_public),
            ad: ad.clone(),
            peer_identity_pk: bob_pk,
        };
        p.am.create_session(
            &mut p.a,
            alice_pk,
            NewSession {
                handle: ALICE_HANDLE,
                session,
                role: SessionRole::Initiator,
                initial_outbound: Some(b"handshake".to_vec()),
                extra: Vec::new(),
            },
        )
    };
    sweep(Case {
        name: "create_session",
        seed: &seed,
        side: Side::Alice,
        run: &create,
        transition: true,
        finish: &|p, took_effect| {
            match (took_effect, create(p)) {
                (false, Ok(())) => {}
                (
                    true,
                    Err(MessagingError::AlreadyExists {
                        handle: ALICE_HANDLE,
                    }),
                ) => {}
                (_, other) => panic!("took_effect {took_effect}: {other:?}"),
            }
            assert_eq!(
                p.am.initial_outbound(&p.a, ALICE_HANDLE).unwrap(),
                Some(b"handshake".to_vec())
            );
            converse(p);
        },
    });
}
