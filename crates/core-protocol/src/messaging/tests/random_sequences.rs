//! Random sequences of messaging operations against a model (reliability
//! plan, step 2.3).
//!
//! Two devices, each with a store and a [`Messenger`]. A seeded generator
//! picks one operation after another: send a new logical message, send one
//! again, deliver any message ever sent (late, again, out of order),
//! acknowledge or abandon an outgoing message, acknowledge an incoming one,
//! `recover`, restart a device's messenger. For about a quarter of them it
//! arms one storage fault (`core_storage::fault`). A model of a few lists
//! says what each call returns and what each device holds. Every call's
//! result is checked against it. After every step the device the step names
//! is compared with it: the session generation, the outbox and the inbox in
//! order, the unresolved state. After every eighth step and at the end both
//! devices are, and with them what a repeated send of every logical message
//! ever committed reports.
//!
//! The sequences are the same on every run (fixed seeds); the message bytes
//! are not, since encryption draws a nonce, and the model takes each message
//! from what the call returned or, after a commit whose result was lost,
//! from the outbox. The test ends by requiring that the sequences met each
//! of the cases in [`CASES`].
//!
//! # What this does not show
//!
//! - Anything outside the model: session creation and removal, handshakes
//!   recorded beside a session, `receive_far`, `forget_peer`, the confirm
//!   hook, and all of `mobile-ffi`. The responder's session here is created
//!   by `create_session`, the form builds before
//!   ARCIUM-SESSION-CONFIRMATION-001 stored, not by `accept_first_message`.
//! - A record left behind that the model does not ask about: the store is
//!   read through the calls above, not dumped (`store_faults.rs` dumps it,
//!   for single operations).
//! - More than one [`Messenger`] or connection on a store at a time, and a
//!   store reopened from its file: the stores are in memory, and a restart
//!   here is a new `Messenger` on the same connection.
//! - Gaps the ratchet cannot cross or keys it has dropped: a sequence sends
//!   far fewer than `MAX_SKIP` messages.
//! - Real I/O failures: the fault layer returns errors, one per operation.
//! - That the model is right. It is short so that it can be read; a mistake
//!   shared by the model and the code would pass.

use super::store_faults::storage_failure;
use super::*;
use core_storage::fault::{self, Op, Outcome};

/// SplitMix64: the same sequence for the same seed, on every platform.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A number below `n`; `n` is not zero.
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Who {
    Alice,
    Bob,
}

impl Who {
    fn peer(self) -> Who {
        match self {
            Who::Alice => Who::Bob,
            Who::Bob => Who::Alice,
        }
    }
}

fn parts(p: &mut Peers, who: Who) -> (&mut Messenger, &mut EncryptedStore, [u8; 32], u64) {
    match who {
        Who::Alice => (&mut p.am, &mut p.a, p.alice_pk, ALICE_HANDLE),
        Who::Bob => (&mut p.bm, &mut p.b, p.bob_pk, BOB_HANDLE),
    }
}

// ── The model ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outgoing {
    Pending,
    Acknowledged,
    Abandoned,
}

/// A logical message a device committed.
#[derive(Debug)]
struct Sent {
    message: OutgoingMessage,
    text: Vec<u8>,
    state: Outgoing,
    /// Its commit's result was lost: the model read it from the outbox.
    result_lost: bool,
}

/// A message a device accepted.
#[derive(Debug)]
struct Got {
    message_id: MessageId,
    generation: u64,
    text: Vec<u8>,
    acknowledged: bool,
}

#[derive(Debug, Default)]
struct Device {
    /// How many transitions the session committed.
    generation: u64,
    /// In the order sent.
    sent: Vec<Sent>,
    /// In the order accepted.
    got: Vec<Got>,
    /// A transition whose commit had an unknown outcome and was not
    /// recovered: the generation it attempted, and whether its writes are
    /// stored.
    unresolved: Option<(u64, bool)>,
}

#[derive(Debug, Default)]
struct Model {
    alice: Device,
    bob: Device,
}

impl Model {
    fn of(&self, who: Who) -> &Device {
        match who {
            Who::Alice => &self.alice,
            Who::Bob => &self.bob,
        }
    }

    fn of_mut(&mut self, who: Who) -> &mut Device {
        match who {
            Who::Alice => &mut self.alice,
            Who::Bob => &mut self.bob,
        }
    }

    /// The initiator can always send; the responder has no sending chain
    /// before it accepted a message.
    fn can_send(&self, who: Who) -> bool {
        who == Who::Alice || !self.bob.got.is_empty()
    }
}

// ── Steps ─────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
enum Step {
    /// A logical message not sent before.
    SendNew {
        who: Who,
        client_id: Vec<u8>,
        text: Vec<u8>,
    },
    /// The logical message `who` sent as its `index`-th.
    SendAgain {
        who: Who,
        index: usize,
    },
    /// The `index`-th message the peer of `to` sent, whatever became of it.
    Deliver {
        to: Who,
        index: usize,
    },
    AcknowledgeOutgoing {
        who: Who,
        index: usize,
    },
    Abandon {
        who: Who,
        index: usize,
    },
    /// The `index`-th message `who` accepted, or with `None` a message it
    /// never saw.
    AcknowledgeIncoming {
        who: Who,
        index: Option<usize>,
    },
    Recover {
        who: Who,
    },
    /// A new `Messenger` for `who`: what a process start leaves of the old
    /// one's memory.
    Restart {
        who: Who,
    },
}

impl Step {
    fn who(&self) -> Who {
        match self {
            Step::SendNew { who, .. }
            | Step::SendAgain { who, .. }
            | Step::AcknowledgeOutgoing { who, .. }
            | Step::Abandon { who, .. }
            | Step::AcknowledgeIncoming { who, .. }
            | Step::Recover { who }
            | Step::Restart { who } => *who,
            Step::Deliver { to, .. } => *to,
        }
    }

    /// A session transition: its unknown outcome leaves the session
    /// unresolved.
    fn is_transition(&self) -> bool {
        matches!(self, Step::SendNew { .. } | Step::Deliver { .. })
    }

    /// An operation whose unknown outcome is settled by repeating it.
    fn is_repeatable(&self) -> bool {
        matches!(
            self,
            Step::AcknowledgeOutgoing { .. }
                | Step::Abandon { .. }
                | Step::AcknowledgeIncoming { .. }
        )
    }
}

/// What a call returned.
#[derive(Debug, PartialEq)]
enum Returned {
    Send(SendOutcome),
    Receive(Received),
    Flag(bool),
    Recover(Option<Recovery>),
    Nothing,
}

/// What the model says a call without a fault returns.
#[derive(Debug)]
enum Expected {
    /// A new message committed at this generation.
    Sent {
        generation: u64,
    },
    Exactly(Returned),
    /// Refused: the session is unresolved at this attempted generation.
    Unresolved(u64),
    /// The responder has not accepted a message yet.
    NoSendingChain,
    UnknownMessage,
}

const NEVER_SEEN: MessageId = [0xEE; 32];

fn message_of(model: &Model, to: Who, index: usize) -> &Sent {
    &model.of(to.peer()).sent[index]
}

fn expected(model: &Model, step: &Step) -> Expected {
    let device = model.of(step.who());
    let refused = device
        .unresolved
        .map(|(attempted, _)| Expected::Unresolved(attempted));
    match step {
        Step::SendNew { who, .. } => refused.unwrap_or(match model.can_send(*who) {
            true => Expected::Sent {
                generation: device.generation + 1,
            },
            false => Expected::NoSendingChain,
        }),
        Step::SendAgain { index, .. } => refused.unwrap_or_else(|| {
            Expected::Exactly(Returned::Send(repeated_send(&device.sent[*index])))
        }),
        Step::Deliver { to, index } => refused.unwrap_or_else(|| {
            let sent = message_of(model, *to, *index);
            let message_id = sent.message.message_id;
            let received = match device.got.iter().find(|g| g.message_id == message_id) {
                Some(got) => Received::Duplicate {
                    message_id,
                    undelivered: (!got.acknowledged).then(|| IncomingMessage {
                        message_id,
                        generation: got.generation,
                        plaintext: Zeroizing::new(got.text.clone()),
                    }),
                },
                None => Received::Accepted(IncomingMessage {
                    message_id,
                    generation: device.generation + 1,
                    plaintext: Zeroizing::new(sent.text.clone()),
                }),
            };
            Expected::Exactly(Returned::Receive(received))
        }),
        Step::AcknowledgeOutgoing { index, .. } | Step::Abandon { index, .. } => Expected::Exactly(
            Returned::Flag(device.sent[*index].state == Outgoing::Pending),
        ),
        Step::AcknowledgeIncoming { index, .. } => match index {
            Some(index) => Expected::Exactly(Returned::Flag(!device.got[*index].acknowledged)),
            None => Expected::UnknownMessage,
        },
        Step::Recover { .. } => Expected::Exactly(Returned::Recover(device.unresolved.map(
            |(attempted_generation, artifact_committed)| Recovery {
                attempted_generation,
                stored_generation: device.generation,
                artifact_committed,
            },
        ))),
        Step::Restart { .. } => Expected::Exactly(Returned::Nothing),
    }
}

/// What a send of a logical message committed before reports.
fn repeated_send(sent: &Sent) -> SendOutcome {
    let message_id = sent.message.message_id;
    match sent.state {
        Outgoing::Pending => SendOutcome::AlreadyPending(sent.message.clone()),
        Outgoing::Acknowledged => SendOutcome::AlreadyAcknowledged { message_id },
        Outgoing::Abandoned => SendOutcome::Abandoned { message_id },
    }
}

/// Whether `step` commits a write when nothing fails.
fn writes(model: &Model, step: &Step) -> bool {
    let device = model.of(step.who());
    match step {
        Step::SendNew { who, .. } => device.unresolved.is_none() && model.can_send(*who),
        Step::Deliver { to, index } => {
            let id = message_of(model, *to, *index).message.message_id;
            device.unresolved.is_none() && device.got.iter().all(|g| g.message_id != id)
        }
        Step::AcknowledgeOutgoing { index, .. } | Step::Abandon { index, .. } => {
            device.sent[*index].state == Outgoing::Pending
        }
        Step::AcknowledgeIncoming { index, .. } => {
            index.is_some_and(|index| !device.got[index].acknowledged)
        }
        Step::SendAgain { .. } | Step::Recover { .. } | Step::Restart { .. } => false,
    }
}

/// Records in the model what `step` wrote. `new_message`: the message a
/// `SendNew` committed.
fn apply(model: &mut Model, step: &Step, new_message: Option<OutgoingMessage>) {
    match step {
        Step::SendNew { who, text, .. } => {
            let message = new_message.expect("the message a new send committed");
            let device = model.of_mut(*who);
            device.generation += 1;
            assert_eq!(message.generation, device.generation);
            device.sent.push(Sent {
                message,
                text: text.clone(),
                state: Outgoing::Pending,
                result_lost: false,
            });
        }
        Step::Deliver { to, index } => {
            let sent = message_of(model, *to, *index);
            let (message_id, text) = (sent.message.message_id, sent.text.clone());
            let device = model.of_mut(*to);
            device.generation += 1;
            device.got.push(Got {
                message_id,
                generation: device.generation,
                text,
                acknowledged: false,
            });
        }
        Step::AcknowledgeOutgoing { who, index } => {
            model.of_mut(*who).sent[*index].state = Outgoing::Acknowledged
        }
        Step::Abandon { who, index } => model.of_mut(*who).sent[*index].state = Outgoing::Abandoned,
        Step::AcknowledgeIncoming { who, index } => {
            model.of_mut(*who).got[index.expect("a message it accepted")].acknowledged = true
        }
        Step::SendAgain { .. } | Step::Recover { .. } | Step::Restart { .. } => {}
    }
}

/// Makes the call `step` names.
fn call(p: &mut Peers, model: &Model, step: &Step) -> Result<Returned, MessagingError> {
    let (messenger, store, our, handle) = parts(p, step.who());
    match step {
        Step::SendNew {
            client_id, text, ..
        } => messenger
            .send(store, our, handle, client_id, text)
            .map(Returned::Send),
        Step::SendAgain { who, index } => {
            let sent = &model.of(*who).sent[*index];
            messenger
                .send(
                    store,
                    our,
                    handle,
                    &sent.message.client_message_id,
                    &sent.text,
                )
                .map(Returned::Send)
        }
        Step::Deliver { to, index } => messenger
            .receive(
                store,
                our,
                handle,
                &message_of(model, *to, *index).message.wire,
            )
            .map(Returned::Receive),
        Step::AcknowledgeOutgoing { who, index } => messenger
            .acknowledge_outgoing(
                store,
                handle,
                &model.of(*who).sent[*index].message.message_id,
            )
            .map(Returned::Flag),
        Step::Abandon { who, index } => messenger
            .abandon_outgoing(
                store,
                handle,
                &model.of(*who).sent[*index].message.message_id,
            )
            .map(Returned::Flag),
        Step::AcknowledgeIncoming { who, index } => {
            let id = index.map_or(NEVER_SEEN, |index| model.of(*who).got[index].message_id);
            messenger
                .acknowledge_incoming(store, handle, &id)
                .map(Returned::Flag)
        }
        Step::Recover { .. } => messenger.recover(store, our, handle).map(Returned::Recover),
        Step::Restart { .. } => {
            *messenger = Messenger::new();
            Ok(Returned::Nothing)
        }
    }
}

/// The cases the sequences must meet, each at least once: what the module
/// documentation says the generator does. A case missing from a run means
/// the sequences no longer exercise it.
const CASES: [&str; 25] = [
    "a fault fired",
    "a fault fired inside recover",
    "a send stored behind an error",
    "a receive stored behind an error",
    "an acknowledgement or abandonment stored behind an error",
    "a session left unresolved with its writes stored",
    "a session left unresolved with nothing stored",
    "a call refused while the session was unresolved",
    "a recovery that found the writes",
    "a recovery that found none",
    "a restart",
    "a restart while the session was unresolved",
    "a duplicate before it was acknowledged",
    "a duplicate after it was acknowledged",
    "a message accepted before an earlier one of the peer",
    "a repeated send of a pending message",
    "a repeated send of an acknowledged message",
    "a repeated send of an abandoned message",
    "a repeated send of a message whose commit result was lost",
    "a send refused for want of a sending chain",
    "an outgoing message acknowledged",
    "an outgoing message abandoned",
    "an incoming message acknowledged",
    "an acknowledgement or abandonment that found nothing pending",
    "an acknowledgement of a message never seen",
];

/// How often the sequences met each of [`CASES`].
#[derive(Debug, Default)]
struct Tally(std::collections::BTreeMap<&'static str, usize>);

impl Tally {
    fn met(&mut self, case: &'static str) {
        assert!(CASES.contains(&case), "not one of CASES: {case}");
        *self.0.entry(case).or_default() += 1;
    }

    fn add(&mut self, other: Tally) {
        for (case, count) in other.0 {
            *self.0.entry(case).or_default() += count;
        }
    }
}

/// Runs `step`, with `fault` armed if any, and checks the call's result
/// against the model, which it then brings up to date.
fn run(
    p: &mut Peers,
    model: &mut Model,
    step: &Step,
    fault: Option<(Outcome, usize)>,
    tally: &mut Tally,
    at: &str,
) {
    let who = step.who();
    let want = expected(model, step);
    let armed = fault.map(|(outcome, nth)| match outcome {
        Outcome::Committed => fault::arm(Op::Commit, 0, outcome),
        _ => fault::arm_any(nth, outcome),
    });
    let result = call(p, model, step);
    let fired = armed.as_ref().is_some_and(|armed| armed.fired());
    drop(armed);

    if fired {
        tally.met("a fault fired");
        if matches!(step, Step::Recover { .. }) {
            tally.met("a fault fired inside recover");
        }
        let stored = fault.is_some_and(|(outcome, _)| outcome == Outcome::Committed);
        let error = match result {
            Err(error) => error,
            Ok(value) => panic!("{at}: returned {value:?} over a failed store operation"),
        };
        let failure = storage_failure(&error)
            .unwrap_or_else(|| panic!("{at}: {error:?} does not report a storage failure"));
        assert!(fault::is_injected(failure), "{at}: {error:?}");
        if stored {
            assert!(
                writes(model, step),
                "{at}: a commit where the model has none"
            );
            match step {
                Step::SendNew { client_id, .. } => {
                    // Its result was lost: the outbox is where it is found.
                    let (messenger, store, _, handle) = parts(p, who);
                    let mut found: Vec<OutgoingMessage> = messenger
                        .pending_outgoing(store, handle)
                        .unwrap()
                        .into_iter()
                        .filter(|m| &m.client_message_id == client_id)
                        .collect();
                    assert_eq!(found.len(), 1, "{at}: one message for the logical id");
                    let message = found.pop().expect("one");
                    assert_eq!(message.message_id, message_id(&message.wire), "{at}");
                    apply(model, step, Some(message));
                    let sent = model.of_mut(who).sent.last_mut().expect("just added");
                    sent.result_lost = true;
                    tally.met("a send stored behind an error");
                }
                Step::Deliver { .. } => {
                    apply(model, step, None);
                    tally.met("a receive stored behind an error");
                }
                _ => {
                    apply(model, step, None);
                    tally.met("an acknowledgement or abandonment stored behind an error");
                }
            }
        }
        match &error {
            &MessagingError::OutcomeUnknown {
                attempted_generation,
                ..
            } => {
                assert!(step.is_transition(), "{at}: {error:?}");
                let device = model.of_mut(who);
                let attempted = device.generation + u64::from(!stored);
                assert_eq!(attempted_generation, attempted, "{at}");
                device.unresolved = Some((attempted, stored));
                tally.met(match stored {
                    true => "a session left unresolved with its writes stored",
                    false => "a session left unresolved with nothing stored",
                });
            }
            MessagingError::RepeatableOutcomeUnknown(_) => {
                assert!(step.is_repeatable(), "{at}: {error:?}");
            }
            _ => assert!(
                !stored,
                "{at}: the writes are stored, and the error says otherwise: {error:?}"
            ),
        }
        return;
    }

    match (want, result) {
        (Expected::Sent { generation }, Ok(Returned::Send(SendOutcome::Sent(message)))) => {
            let Step::SendNew { client_id, .. } = step else {
                panic!("{at}: only a new send commits a new message");
            };
            assert_eq!(&message.client_message_id, client_id, "{at}");
            assert_eq!(message.generation, generation, "{at}");
            assert_eq!(message.message_id, message_id(&message.wire), "{at}");
            apply(model, step, Some(message));
        }
        (Expected::Exactly(want), Ok(got)) => {
            assert_eq!(got, want, "{at}");
            match (&got, step) {
                (Returned::Receive(Received::Duplicate { undelivered, .. }), _) => {
                    tally.met(match undelivered {
                        Some(_) => "a duplicate before it was acknowledged",
                        None => "a duplicate after it was acknowledged",
                    })
                }
                (Returned::Receive(Received::Accepted(_)), Step::Deliver { to, index }) => {
                    let got = &model.of(*to).got;
                    let earlier_missing = model.of(to.peer()).sent[..*index]
                        .iter()
                        .any(|s| got.iter().all(|g| g.message_id != s.message.message_id));
                    if earlier_missing {
                        tally.met("a message accepted before an earlier one of the peer");
                    }
                }
                (Returned::Send(outcome), Step::SendAgain { who, index }) => {
                    tally.met(match outcome {
                        SendOutcome::AlreadyAcknowledged { .. } => {
                            "a repeated send of an acknowledged message"
                        }
                        SendOutcome::Abandoned { .. } => "a repeated send of an abandoned message",
                        _ => "a repeated send of a pending message",
                    });
                    if model.of(*who).sent[*index].result_lost {
                        tally.met("a repeated send of a message whose commit result was lost");
                    }
                }
                (Returned::Recover(Some(recovery)), _) => {
                    tally.met(match recovery.artifact_committed {
                        true => "a recovery that found the writes",
                        false => "a recovery that found none",
                    })
                }
                (Returned::Nothing, _) => {
                    tally.met("a restart");
                    if model.of(who).unresolved.is_some() {
                        tally.met("a restart while the session was unresolved");
                    }
                }
                (Returned::Flag(true), Step::AcknowledgeOutgoing { .. }) => {
                    tally.met("an outgoing message acknowledged")
                }
                (Returned::Flag(true), Step::Abandon { .. }) => {
                    tally.met("an outgoing message abandoned")
                }
                (Returned::Flag(true), Step::AcknowledgeIncoming { .. }) => {
                    tally.met("an incoming message acknowledged")
                }
                (Returned::Flag(false), _) => {
                    tally.met("an acknowledgement or abandonment that found nothing pending")
                }
                _ => {}
            }
            if writes(model, step) {
                apply(model, step, None);
            }
            if matches!(step, Step::Recover { .. } | Step::Restart { .. }) {
                model.of_mut(who).unresolved = None;
            }
        }
        (
            Expected::Unresolved(attempted),
            Err(MessagingError::Unresolved {
                attempted_generation,
            }),
        ) => {
            assert_eq!(attempted_generation, attempted, "{at}");
            tally.met("a call refused while the session was unresolved");
        }
        (Expected::NoSendingChain, Err(MessagingError::Ratchet(RatchetError::NotInitialized))) => {
            tally.met("a send refused for want of a sending chain")
        }
        (Expected::UnknownMessage, Err(MessagingError::UnknownMessage)) => {
            tally.met("an acknowledgement of a message never seen")
        }
        (want, got) => panic!("{at}: the model expects {want:?}, the call returned {got:?}"),
    }
}

/// Compares what both devices hold with the model, each logical message
/// included. No fault is armed.
fn compare(p: &mut Peers, model: &Model, at: &str) {
    for who in [Who::Alice, Who::Bob] {
        compare_device(p, model, who, true, at);
    }
}

/// Compares what `who` holds with the model. `every_logical_message`: also
/// ask of each logical message it ever committed what a repeated send
/// reports (a transaction each, so not after every step).
fn compare_device(p: &mut Peers, model: &Model, who: Who, every_logical_message: bool, at: &str) {
    let device = model.of(who);
    let (messenger, store, our, handle) = parts(p, who);
    assert_eq!(
        messenger.unresolved_generation(handle),
        device.unresolved.map(|(attempted, _)| attempted),
        "{at}: {who:?}'s unresolved generation"
    );
    assert_eq!(
        generation(store, our, handle),
        device.generation,
        "{at}: {who:?}'s session generation"
    );
    let pending: Vec<OutgoingMessage> = device
        .sent
        .iter()
        .filter(|s| s.state == Outgoing::Pending)
        .map(|s| s.message.clone())
        .collect();
    assert_eq!(
        messenger.pending_outgoing(store, handle).unwrap(),
        pending,
        "{at}: {who:?}'s outbox"
    );
    let undelivered: Vec<IncomingMessage> = device
        .got
        .iter()
        .filter(|g| !g.acknowledged)
        .map(|g| IncomingMessage {
            message_id: g.message_id,
            generation: g.generation,
            plaintext: Zeroizing::new(g.text.clone()),
        })
        .collect();
    assert_eq!(
        messenger.pending_incoming(store, handle).unwrap(),
        undelivered,
        "{at}: {who:?}'s inbox"
    );
    // Every logical message ever committed is still known, as what it
    // became: none can be encrypted a second time.
    let peer_pk = match who {
        Who::Alice => p.bob_pk,
        Who::Bob => p.alice_pk,
    };
    let (messenger, store, _, _) = parts(p, who);
    let asked = match every_logical_message {
        true => &device.sent[..],
        false => &[],
    };
    for sent in asked {
        assert_eq!(
            messenger
                .prior_send(store, &peer_pk, &sent.message.client_message_id)
                .unwrap(),
            Some(repeated_send(sent)),
            "{at}: {who:?}'s logical message {:?}",
            sent.message.client_message_id
        );
    }
}

/// The next step of a sequence: one the model's state allows, by weight.
fn pick(rng: &mut Rng, model: &Model, serial: &mut u64) -> Step {
    let who = [Who::Alice, Who::Bob][rng.below(2)];
    let device = model.of(who);
    let from_peer = model.of(who.peer()).sent.len();
    let mut choices: Vec<(usize, u8)> = vec![(22, 0), (2, 7)];
    if !device.sent.is_empty() {
        choices.extend([(8, 1), (8, 3), (4, 4)]);
    }
    if from_peer > 0 {
        choices.push((30, 2));
    }
    choices.push((if device.got.is_empty() { 1 } else { 10 }, 5));
    choices.push((if device.unresolved.is_some() { 12 } else { 1 }, 6));
    let total: usize = choices.iter().map(|(weight, _)| weight).sum();
    let mut roll = rng.below(total);
    let kind = choices
        .iter()
        .find(|(weight, _)| {
            let here = roll < *weight;
            roll = roll.saturating_sub(*weight);
            here
        })
        .expect("a choice")
        .1;
    match kind {
        0 => {
            *serial += 1;
            Step::SendNew {
                who,
                client_id: format!("{who:?}-{serial}").into_bytes(),
                text: format!("text {serial} from {who:?}").into_bytes(),
            }
        }
        1 => Step::SendAgain {
            who,
            index: rng.below(device.sent.len()),
        },
        2 => Step::Deliver {
            to: who,
            index: rng.below(from_peer),
        },
        3 => Step::AcknowledgeOutgoing {
            who,
            index: rng.below(device.sent.len()),
        },
        4 => Step::Abandon {
            who,
            index: rng.below(device.sent.len()),
        },
        5 => Step::AcknowledgeIncoming {
            who,
            index: (!device.got.is_empty() && rng.below(12) > 0)
                .then(|| rng.below(device.got.len())),
        },
        6 => Step::Recover { who },
        _ => Step::Restart { who },
    }
}

/// One sequence of `length` steps from `seed`, then every message delivered.
fn sequence(seed: u64, length: usize, tally: &mut Tally) {
    let mut rng = Rng(seed);
    let mut p = memory_peers();
    let mut model = Model::default();
    let mut serial = 0;
    let mut log: Vec<String> = Vec::new();
    for n in 0..length {
        let step = pick(&mut rng, &model, &mut serial);
        let fault = (rng.below(4) == 0).then(|| {
            let outcome = [
                Outcome::NotRun,
                Outcome::TransactionEnded,
                Outcome::Committed,
            ][rng.below(3)];
            (outcome, rng.below(14))
        });
        log.push(format!("{n}: {step:?} fault {fault:?}"));
        let at = format!(
            "seed {seed}, step {n} ({step:?}, fault {fault:?}); the steps before it:\n{}\n",
            log[log.len().saturating_sub(12)..].join("\n")
        );
        run(&mut p, &mut model, &step, fault, tally, &at);
        // A step touches the store of the device it names only. That one is
        // compared after every step, both in full after every eighth.
        match n % 8 == 7 {
            true => compare(&mut p, &model, &at),
            false => compare_device(&mut p, &model, step.who(), false, &at),
        }
    }

    // The end of every sequence: with nothing unresolved, each device
    // accepts whatever its peer sent and it has not accepted, and then holds
    // every message the peer ever committed, once.
    for who in [Who::Alice, Who::Bob] {
        let at = format!("seed {seed}, the end, {who:?}");
        run(&mut p, &mut model, &Step::Recover { who }, None, tally, &at);
        for index in 0..model.of(who.peer()).sent.len() {
            run(
                &mut p,
                &mut model,
                &Step::Deliver { to: who, index },
                None,
                tally,
                &at,
            );
        }
        compare(&mut p, &model, &at);
        assert_eq!(
            model.of(who).got.len(),
            model.of(who.peer()).sent.len(),
            "{at}: every message of the peer was accepted once"
        );
    }
}

/// How many sequences run, and how many steps each takes before the
/// deliveries that end it.
const SEQUENCES: u64 = 64;
const LENGTH: usize = 64;

#[test]
fn random_sequences_agree_with_the_model() {
    // Four threads, so that the sequences run side by side. A fault is
    // armed for the thread that arms it, so they do not meet.
    const THREADS: u64 = 4;
    let mut tally = Tally::default();
    std::thread::scope(|scope| {
        let parts: Vec<_> = (0..THREADS)
            .map(|part| {
                scope.spawn(move || {
                    let mut tally = Tally::default();
                    for seed in (0..SEQUENCES).filter(|seed| seed % THREADS == part) {
                        sequence(seed, LENGTH, &mut tally);
                    }
                    tally
                })
            })
            .collect();
        for part in parts {
            match part.join() {
                Ok(met) => tally.add(met),
                Err(panic) => std::panic::resume_unwind(panic),
            }
        }
    });
    for case in CASES {
        assert!(
            tally.0.get(case).is_some_and(|count| *count > 0),
            "no sequence met: {case}. Met: {tally:?}"
        );
    }
}
