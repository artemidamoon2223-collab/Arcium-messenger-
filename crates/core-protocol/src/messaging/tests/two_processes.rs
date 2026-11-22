//! Two operating-system processes on one database (reliability plan, step
//! 2.4).
//!
//! The children are this test binary, run again to execute only
//! `two_processes_child`. Each opens the fixture's database files by itself,
//! so the two share nothing but the files, and they meet through marker
//! files in the fixture's directory: one process writes a marker where it
//! is, the other waits for it.
//!
//! What must hold: one process commits a session generation, never two. A
//! process that staged a transition before the other committed loses its
//! commit, releases nothing, and its next attempt takes a ratchet position
//! of its own. A message both processes receive is accepted by one.
//!
//! # What this does not show
//!
//! - A phone. These are processes of the host OS on its file system; SQLite
//!   locks through that, and Android's may behave otherwise.
//! - More than two processes, and one of them dying while the other runs
//!   (`crash.rs` kills a process that runs alone).
//! - Operations other than a send and a receive racing: the
//!   acknowledgements, an abandonment, removing a session, `forget_peer`.
//!   The free race is of sends only.
//! - A lock held too long. No test makes a process wait out the store's
//!   busy timeout; a send refused as busy in the free race is counted and
//!   proves nothing, and a commit with an unknown outcome there fails the
//!   test instead of being followed.
//! - `mobile-ffi`. Its network layer keeps state in memory that a second
//!   process would not share: what was sent and when, notes of forgotten
//!   chains, the messages to name as gone, and its copy of the far-skip
//!   waits (those are stored too, so the copy can go stale). Whether the
//!   app may have a second process is a decision for the Owner.
//! - Timing. The first two tests place the second process by markers, so
//!   they show the outcome of that one interleaving; the third lets two
//!   processes run freely and shows what those runs met, not every
//!   schedule.

use super::crash::{fixture, Fixture};
use super::*;
use std::time::{Duration, Instant};

const CHILD_ENV: &str = "ARCIUM_MSG_PROCESS";
const DIR_ENV: &str = "ARCIUM_MSG_PROCESS_DIR";
const ID_ENV: &str = "ARCIUM_MSG_PROCESS_ID";

/// Sends each process of the free race attempts.
const RACE_SENDS: usize = 60;

fn mark(dir: &Path, name: &str) {
    std::fs::write(dir.join(name), b"").unwrap();
}

/// Waits until another process wrote the marker `name`.
fn wait_for(dir: &Path, name: &str) {
    let path = dir.join(name);
    let deadline = Instant::now() + Duration::from_secs(60);
    while !path.exists() {
        assert!(Instant::now() < deadline, "waited a minute for {name}");
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// As [`wait_for`], without sleeping: the processes of the free race leave
/// it together.
fn spin_until(dir: &Path, name: &str) {
    let path = dir.join(name);
    let deadline = Instant::now() + Duration::from_secs(60);
    while !path.exists() {
        assert!(Instant::now() < deadline, "waited a minute for {name}");
        std::thread::yield_now();
    }
}

/// What a process that lost a generation is told: the session it loaded at
/// `expected` is stored at `found` now.
fn lost_generation(expected: u64, found: u64) -> String {
    format!("conflict: loaded at generation {expected}, stored at {found}")
}

/// How a call ended, in words for the parent to read.
fn outcome_of<T>(result: &Result<T, MessagingError>, ok: impl Fn(&T) -> &'static str) -> String {
    match result {
        Ok(value) => ok(value).to_string(),
        Err(MessagingError::Conflict(Conflict::GenerationMismatch { expected, found })) => {
            lost_generation(*expected, *found)
        }
        Err(MessagingError::Conflict(other)) => format!("conflict: {other:?}"),
        // The store's busy timeout ran out before the lock was free: nothing
        // was staged or written.
        Err(MessagingError::NotCommitted(e) | MessagingError::Store(e)) if is_busy(e) => {
            "busy".to_string()
        }
        Err(e) => panic!("unexpected {e:?}"),
    }
}

/// SQLite's `SQLITE_BUSY`, by its message: this crate has no name for the
/// error's type.
fn is_busy(error: &StorageError) -> bool {
    matches!(error, StorageError::Db(e) if e.to_string().contains("database is locked"))
}

fn kind_of_receive(received: &Received) -> &'static str {
    match received {
        Received::Accepted(_) => "accepted",
        Received::Duplicate {
            undelivered: Some(_),
            ..
        } => "duplicate, undelivered",
        Received::Duplicate {
            undelivered: None, ..
        } => "duplicate, acknowledged",
    }
}

/// Lets the next transition of this process stop between staging and its
/// transaction: it marks `staged` and goes on when another process marks
/// `go`.
fn stop_after_staging(dir: &Path) {
    let dir = dir.to_path_buf();
    crate::messaging::race_hook::set(move || {
        mark(&dir, "staged");
        wait_for(&dir, "go");
    });
}

#[test]
fn two_processes_child() {
    let (Ok(role), Ok(dir)) = (std::env::var(CHILD_ENV), std::env::var(DIR_ENV)) else {
        return; // Not a child run.
    };
    let dir = PathBuf::from(dir);
    let ids = std::fs::read(dir.join("ids")).unwrap();
    let fx = Fixture {
        dir: dir.clone(),
        alice_pk: ids[..32].try_into().unwrap(),
        bob_pk: ids[32..].try_into().unwrap(),
    };
    let mut p = fx.peers();
    let write = |name: &str, bytes: &[u8]| std::fs::write(dir.join(name), bytes).unwrap();
    match role.as_str() {
        // Stages a send, lets the other process commit, then commits; and
        // sends the same logical message again.
        "slow_send" => {
            stop_after_staging(&dir);
            let first =
                p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, b"slow", b"slow text");
            write("slow-first", outcome_of(&first, |_| "sent").as_bytes());
            let known = p.am.prior_send(&mut p.a, &p.bob_pk, b"slow").unwrap();
            let known = if known.is_some() { "known" } else { "unknown" };
            write("slow-known", known.as_bytes());
            let again =
                p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, b"slow", b"slow text")
                    .map(new_message)
                    .unwrap();
            write("slow-wire", &again.wire);
        }
        "fast_send" => {
            wait_for(&dir, "staged");
            let sent =
                p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, b"fast", b"fast text")
                    .map(new_message)
                    .unwrap();
            write("fast-wire", &sent.wire);
            mark(&dir, "go");
        }
        // The other process's transition is a receive on the same session.
        "fast_receive_on_alice" => {
            wait_for(&dir, "staged");
            let wire = std::fs::read(dir.join("to-alice")).unwrap();
            accepted(p.alice_receives(&wire).unwrap());
            mark(&dir, "go");
        }
        // Stages the receive of a message, lets the other process accept
        // it, then commits; and receives it again.
        "slow_receive" => {
            let wire = std::fs::read(dir.join("to-bob")).unwrap();
            stop_after_staging(&dir);
            let first = p.bob_receives(&wire);
            write("slow-first", outcome_of(&first, kind_of_receive).as_bytes());
            let again = p.bob_receives(&wire);
            write("slow-again", outcome_of(&again, kind_of_receive).as_bytes());
        }
        "fast_receive" => {
            wait_for(&dir, "staged");
            let wire = std::fs::read(dir.join("to-bob")).unwrap();
            accepted(p.bob_receives(&wire).unwrap());
            mark(&dir, "go");
        }
        // Sends as fast as it can, beside another process doing the same.
        "race" => {
            let id = std::env::var(ID_ENV).unwrap();
            mark(&dir, &format!("ready-{id}"));
            spin_until(&dir, "start");
            let mut lines = Vec::new();
            for i in 0..RACE_SENDS {
                let client = format!("{id}-{i}");
                let result = p.am.send(
                    &mut p.a,
                    p.alice_pk,
                    ALICE_HANDLE,
                    client.as_bytes(),
                    client.as_bytes(),
                );
                lines.push(format!("{client} {}", outcome_of(&result, |_| "sent")));
                if let Ok(outcome) = result {
                    write(&format!("wire-{client}"), &new_message(outcome).wire);
                }
            }
            write(&format!("result-{id}"), lines.join("\n").as_bytes());
        }
        other => panic!("unknown role {other}"),
    }
}

/// Child processes, ended if the test fails while they run.
struct Children(Vec<std::process::Child>);

impl Drop for Children {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Runs the roles, each in a process of its own and all at once, and waits
/// for them to end. `(role, id)`: the id is for the free race.
fn run_processes(dir: &Path, roles: &[(&str, &str)], after_spawn: impl FnOnce()) {
    let children: Vec<_> = roles
        .iter()
        .map(|(role, id)| {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "messaging::tests::two_processes::two_processes_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD_ENV, role)
                .env(DIR_ENV, dir)
                .env(ID_ENV, id)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    let mut children = Children(children);
    after_spawn();
    for (child, (role, _)) in std::mem::take(&mut children.0).into_iter().zip(roles) {
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "the {role} process failed: {:?}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn read(dir: &Path, name: &str) -> Vec<u8> {
    std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn text(dir: &Path, name: &str) -> String {
    String::from_utf8(read(dir, name)).unwrap()
}

/// The ratchet position of a message: the sender's ratchet key and the
/// message's number in that chain. Two messages at one position would be
/// encrypted under one key.
fn position(wire: &[u8]) -> ([u8; 32], u32) {
    let header = Header::from_bytes(&wire[..HEADER_SIZE]).unwrap();
    (header.dh, header.n)
}

fn all_distinct<T: Ord + Clone>(items: &[T]) -> bool {
    let mut sorted = items.to_vec();
    sorted.sort();
    sorted.dedup();
    sorted.len() == items.len()
}

/// One process stages a send. Before its transaction, another process
/// commits a transition of the same session: a send, or a receive. The
/// first process's commit is refused, it has released nothing and nothing
/// of its attempt is stored; its next attempt commits the following
/// generation at a ratchet position no other message has.
#[test]
fn a_process_that_staged_a_send_before_another_committed_loses_the_generation() {
    for fast in ["fast_send", "fast_receive_on_alice"] {
        let dir = tempfile::tempdir().unwrap();
        let fx = fixture(dir.path());
        let before = {
            let mut p = fx.peers();
            if fast == "fast_receive_on_alice" {
                let hello = p.alice_sends(b"hello");
                accepted(p.bob_receives(&hello.wire).unwrap());
                std::fs::write(dir.path().join("to-alice"), p.bob_sends(b"reply").wire).unwrap();
            }
            generation(&mut p.a, p.alice_pk, ALICE_HANDLE)
        };

        run_processes(dir.path(), &[("slow_send", ""), (fast, "")], || ());

        assert_eq!(
            text(dir.path(), "slow-first"),
            lost_generation(before, before + 1),
            "{fast}: the commit staged before the other process's was refused, as the \
             session had moved on by one generation"
        );
        assert_eq!(
            text(dir.path(), "slow-known"),
            "unknown",
            "{fast}: nothing of the refused send is stored"
        );
        let mut p = fx.peers();
        assert_eq!(
            generation(&mut p.a, p.alice_pk, ALICE_HANDLE),
            before + 2,
            "{fast}: two transitions were committed, one by each process"
        );
        let outbox = p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap();
        let slow = outbox
            .iter()
            .find(|m| m.client_message_id == b"slow")
            .unwrap_or_else(|| panic!("{fast}: the slow process's message is in the outbox"));
        assert_eq!(slow.wire, read(dir.path(), "slow-wire"), "{fast}");
        assert_eq!(
            slow.generation,
            before + 2,
            "{fast}: the slow process took the generation after the other's"
        );
        let positions: Vec<_> = outbox.iter().map(|m| position(&m.wire)).collect();
        assert!(
            all_distinct(&positions),
            "{fast}: no two messages at one ratchet position: {positions:?}"
        );
        // The outbox holds the slow process's message and one other.
        assert_eq!(outbox.len(), 2, "{fast}");
        let other = outbox
            .iter()
            .find(|m| m.client_message_id != b"slow")
            .expect("two messages");
        if fast == "fast_send" {
            // The other is the fast process's, as it returned it.
            let fast_wire = read(dir.path(), "fast-wire");
            assert_eq!(other.wire, fast_wire);
            assert_eq!(other.generation, before + 1);
            assert_eq!(
                position(&fast_wire).1,
                0,
                "the first position went to the fast send"
            );
            assert_eq!(position(&slow.wire).1, 1, "and the slow send took the next");
            assert_eq!(
                *accepted(p.bob_receives(&fast_wire).unwrap()).plaintext,
                b"fast text"
            );
        } else {
            // The other is `hello`, sent before the reply arrived. The
            // receive turned the ratchet, so the slow send opens a chain.
            assert_ne!(position(&slow.wire).0, position(&other.wire).0);
            assert_eq!(position(&slow.wire).1, 0);
        }
        assert_eq!(
            *accepted(p.bob_receives(&slow.wire).unwrap()).plaintext,
            b"slow text",
            "{fast}"
        );
    }
}

/// Both processes receive the same message. The one that staged first and
/// committed second is refused, and on asking again is told the message is
/// a duplicate: it is accepted once, and the session advanced once.
///
/// The refusal is a conflict, not yet "duplicate": a commit checks the
/// session's own record first, and that has moved on. The inbox record the
/// other process wrote is found by the next call, which looks before it
/// stages anything.
#[test]
fn two_processes_receiving_one_message_accept_it_once() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path());
    {
        let mut p = fx.peers();
        std::fs::write(dir.path().join("to-bob"), p.alice_sends(b"once").wire).unwrap();
    }

    run_processes(
        dir.path(),
        &[("slow_receive", ""), ("fast_receive", "")],
        || (),
    );

    assert_eq!(
        text(dir.path(), "slow-first"),
        lost_generation(0, 1),
        "the receive staged before the other process's was refused, as the session had \
         moved on by one generation"
    );
    assert_eq!(
        text(dir.path(), "slow-again"),
        "duplicate, undelivered",
        "and then found the message already accepted"
    );
    let mut p = fx.peers();
    assert_eq!(generation(&mut p.b, p.bob_pk, BOB_HANDLE), 1);
    let inbox = p.bm.pending_incoming(&p.b, BOB_HANDLE).unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(*inbox[0].plaintext, b"once");
}

/// What one free race met.
struct Race {
    /// Sends refused because the session had moved on: a staged transition
    /// that lost its generation to the other process.
    lost: usize,
    /// Sends refused because the store stayed locked past its busy timeout.
    /// Nothing was staged; they show nothing about a lost generation.
    busy: usize,
    /// How often, along the generations, the committing process changed.
    /// Two or more: one process committed both before and after a commit
    /// of the other.
    turns: usize,
}

/// Two processes send as fast as they can, with nothing placing them. Every
/// send that returned a message committed a generation no other did, at a
/// ratchet position no other has; the outbox holds exactly those messages;
/// and the peer reads each of them.
fn race() -> Race {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path());
    let ids = ["p", "q"];

    run_processes(dir.path(), &[("race", ids[0]), ("race", ids[1])], || {
        for id in ids {
            wait_for(dir.path(), &format!("ready-{id}"));
        }
        mark(dir.path(), "start");
    });

    // (logical id, wire) of every send that returned a message, and how
    // many were refused, by why.
    let mut released: Vec<(String, Vec<u8>)> = Vec::new();
    let (mut lost, mut busy) = (0, 0);
    for id in ids {
        let result = text(dir.path(), &format!("result-{id}"));
        assert_eq!(result.lines().count(), RACE_SENDS, "process {id}");
        for line in result.lines() {
            let (client, outcome) = line.split_once(' ').unwrap();
            match outcome {
                "sent" => released.push((
                    client.to_string(),
                    read(dir.path(), &format!("wire-{client}")),
                )),
                "busy" => busy += 1,
                // The only conflict a send of a new logical message can
                // meet here: the session moved on under it.
                lost_one if lost_one.starts_with("conflict: loaded at generation ") => lost += 1,
                other => panic!("{client}: {other}"),
            }
        }
    }

    let mut p = fx.peers();
    let mut outbox = p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap();
    outbox.sort_by_key(|m| m.generation);
    let generations: Vec<u64> = outbox.iter().map(|m| m.generation).collect();
    assert_eq!(
        generations,
        (1..=released.len() as u64).collect::<Vec<_>>(),
        "one message for each generation, and none besides ({lost} sends lost a generation, \
         {busy} found the store busy)"
    );
    assert_eq!(
        generation(&mut p.a, p.alice_pk, ALICE_HANDLE),
        released.len() as u64
    );
    let mut stored: Vec<(String, Vec<u8>)> = outbox
        .iter()
        .map(|m| {
            (
                String::from_utf8(m.client_message_id.clone()).unwrap(),
                m.wire.clone(),
            )
        })
        .collect();
    stored.sort();
    released.sort();
    assert_eq!(stored, released, "released exactly what was committed");
    let positions: Vec<_> = outbox.iter().map(|m| position(&m.wire)).collect();
    assert!(
        all_distinct(&positions),
        "no two messages at one ratchet position"
    );
    for message in &outbox {
        assert_eq!(
            *accepted(p.bob_receives(&message.wire).unwrap()).plaintext,
            message.client_message_id,
            "the peer reads every committed message"
        );
    }

    let owners: Vec<bool> = outbox
        .iter()
        .map(|m| m.client_message_id.starts_with(b"p-"))
        .collect();
    Race {
        lost,
        busy,
        turns: owners.windows(2).filter(|pair| pair[0] != pair[1]).count(),
    }
}

/// The free race, run until the two processes were seen to commit turn
/// about and a send was seen to lose its generation to the other process
/// (in the same run or not): nothing places them, so one run may show
/// neither. Every run is checked in full.
#[test]
fn two_processes_sending_at_once_commit_each_generation_once() {
    const RUNS: usize = 20;
    let (mut interleaved, mut lost, mut busy) = (false, 0, 0);
    for _ in 0..RUNS {
        let race = race();
        interleaved |= race.turns >= 2;
        lost += race.lost;
        busy += race.busy;
        if interleaved && lost > 0 {
            return;
        }
    }
    panic!(
        "{RUNS} free races: the processes committed turn about: {interleaved}; sends that lost \
         a generation: {lost}; sends that found the store busy: {busy}"
    );
}
