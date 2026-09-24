//! Real process deaths around the store transaction.

use super::*;

// ── Process termination ───────────────────────────────────────────────────
//
// The child is this test binary, re-run to execute only `crash_child`. It
// performs one operation on a file database and dies by `abort()` —
// either inside the store transaction (`CRASH_AT_ENV`) or right after the
// operation returned. The parent then reopens the database. These are real
// process deaths on the host OS; they are not power-loss tests.

const CHILD_ENV: &str = "ARCIUM_MSG_CHILD";
const DIR_ENV: &str = "ARCIUM_MSG_DIR";

struct Fixture {
    dir: PathBuf,
    alice_pk: [u8; 32],
    bob_pk: [u8; 32],
}

fn fixture(dir: &Path) -> Fixture {
    let p = setup(
        EncryptedStore::open(dir.join("a.db"), KEY).unwrap(),
        EncryptedStore::open(dir.join("b.db"), KEY).unwrap(),
    );
    std::fs::write(dir.join("ids"), [p.alice_pk, p.bob_pk].concat()).unwrap();
    Fixture {
        dir: dir.to_path_buf(),
        alice_pk: p.alice_pk,
        bob_pk: p.bob_pk,
    }
}

impl Fixture {
    fn peers(&self) -> Peers {
        Peers {
            a: EncryptedStore::open(self.dir.join("a.db"), KEY).unwrap(),
            b: EncryptedStore::open(self.dir.join("b.db"), KEY).unwrap(),
            am: Messenger::new(),
            bm: Messenger::new(),
            alice_pk: self.alice_pk,
            bob_pk: self.bob_pk,
        }
    }
}

#[test]
fn crash_child() {
    let (Ok(scenario), Ok(dir)) = (std::env::var(CHILD_ENV), std::env::var(DIR_ENV)) else {
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
    match scenario.as_str() {
        "send" => {
            let m = p.alice_sends(b"crash");
            // Published: the caller had the bytes and handed them on.
            std::fs::write(dir.join("published"), &m.wire).unwrap();
        }
        "receive" => {
            let wire = std::fs::read(dir.join("wire")).unwrap();
            accepted(p.bob_receives(&wire).unwrap());
        }
        "create" => {
            let pr = pair();
            let mut ns = new_session(42, pr.bob, SessionRole::Responder);
            ns.extra = vec![SideWrite::replace(
                "prekeys/v2".into(),
                Zeroizing::new(b"old".to_vec()),
                Zeroizing::new(b"rotated".to_vec()),
            )
            .unwrap()];
            std::fs::write(dir.join("created_peer"), pr.alice_pk).unwrap();
            p.bm.create_session(&mut p.b, pr.bob_pk, ns).unwrap();
        }
        "remove" => {
            p.am.remove_session(&mut p.a, p.alice_pk, ALICE_HANDLE)
                .unwrap()
        }
        other => panic!("unknown scenario {other}"),
    }
    // Died after the operation returned, before acknowledging anything.
    std::process::abort();
}

/// Runs `scenario` in a child process that dies at `point`
/// (`before_commit`, `after_commit`, or `after_return`).
#[cfg(unix)]
fn run_child(fx: &Fixture, scenario: &str, point: &str) {
    use std::os::unix::process::ExitStatusExt;
    let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
    cmd.args([
        "--exact",
        "messaging::tests::crash::crash_child",
        "--nocapture",
        "--test-threads=1",
    ])
    .env(CHILD_ENV, scenario)
    .env(DIR_ENV, &fx.dir);
    if point != "after_return" {
        cmd.env(CRASH_AT_ENV, point);
    }
    let status = cmd.status().unwrap();
    assert_eq!(
        status.signal(),
        Some(6),
        "child must die by abort(): {status:?}"
    );
}

#[cfg(unix)]
#[test]
fn process_killed_before_commit_of_a_send_leaves_no_trace() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path());
    run_child(&fx, "send", "before_commit");
    let mut p = fx.peers();
    assert_eq!(generation(&mut p.a, p.alice_pk, ALICE_HANDLE), 0);
    assert!(p
        .am
        .pending_outgoing(&p.a, ALICE_HANDLE)
        .unwrap()
        .is_empty());
    let m = p.alice_sends(b"retry");
    assert_eq!(Header::from_bytes(&m.wire[..HEADER_SIZE]).unwrap().n, 0);
    assert_eq!(
        *accepted(p.bob_receives(&m.wire).unwrap()).plaintext,
        b"retry"
    );
}

#[cfg(unix)]
#[test]
fn process_killed_after_commit_of_a_send_keeps_the_message_for_resending() {
    for point in ["after_commit", "after_return"] {
        let dir = tempfile::tempdir().unwrap();
        let fx = fixture(dir.path());
        run_child(&fx, "send", point);
        let mut p = fx.peers();
        assert_eq!(generation(&mut p.a, p.alice_pk, ALICE_HANDLE), 1, "{point}");
        let pending = p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap();
        assert_eq!(pending.len(), 1, "{point}");
        if point == "after_return" {
            let published = std::fs::read(dir.path().join("published")).unwrap();
            assert_eq!(
                pending[0].wire, published,
                "byte-identical across the crash"
            );
        }
        // Resend twice (e.g. delivery unknown): same bytes, one acceptance.
        drop(p);
        let mut p = fx.peers();
        let again = p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap();
        assert_eq!(again, pending);
        assert_eq!(
            *accepted(p.bob_receives(&again[0].wire).unwrap()).plaintext,
            b"crash"
        );
        assert!(matches!(
            p.bob_receives(&pending[0].wire).unwrap(),
            Received::Duplicate { .. }
        ));
        // The conversation continues in both directions.
        let r = p.bob_sends(b"reply");
        assert_eq!(
            *accepted(p.alice_receives(&r.wire).unwrap()).plaintext,
            b"reply"
        );
        let m = p.alice_sends(b"more");
        assert_eq!(
            *accepted(p.bob_receives(&m.wire).unwrap()).plaintext,
            b"more"
        );
    }
}

#[cfg(unix)]
#[test]
fn process_killed_during_a_receive_loses_nothing_and_accepts_once() {
    for point in ["before_commit", "after_commit", "after_return"] {
        let dir = tempfile::tempdir().unwrap();
        let fx = fixture(dir.path());
        let wire = fx.peers().alice_sends(b"inbound").wire;
        std::fs::write(dir.path().join("wire"), &wire).unwrap();
        run_child(&fx, "receive", point);
        let mut p = fx.peers();
        let pending = p.bm.pending_incoming(&p.b, BOB_HANDLE).unwrap();
        if point == "before_commit" {
            assert_eq!(generation(&mut p.b, p.bob_pk, BOB_HANDLE), 0);
            assert!(pending.is_empty());
            assert_eq!(
                *accepted(p.bob_receives(&wire).unwrap()).plaintext,
                b"inbound"
            );
        } else {
            assert_eq!(generation(&mut p.b, p.bob_pk, BOB_HANDLE), 1, "{point}");
            assert_eq!(*pending[0].plaintext, b"inbound", "committed, undelivered");
            assert!(matches!(
                p.bob_receives(&wire).unwrap(),
                Received::Duplicate {
                    undelivered: Some(_),
                    ..
                }
            ));
            assert_eq!(generation(&mut p.b, p.bob_pk, BOB_HANDLE), 1);
            p.bm.acknowledge_incoming(&mut p.b, BOB_HANDLE, &pending[0].message_id)
                .unwrap();
        }
        let r = p.bob_sends(b"back");
        assert_eq!(
            *accepted(p.alice_receives(&r.wire).unwrap()).plaintext,
            b"back"
        );
    }
}

/// The responder shape: prekey rotation and session creation are one
/// transaction, so a crash leaves both or neither.
#[cfg(unix)]
#[test]
fn process_killed_during_session_creation_leaves_both_records_or_neither() {
    for point in ["before_commit", "after_commit"] {
        let dir = tempfile::tempdir().unwrap();
        let fx = fixture(dir.path());
        fx.peers().b.put("prekeys/v2", b"old").unwrap();
        run_child(&fx, "create", point);
        let p = fx.peers();
        let created: [u8; 32] = std::fs::read(dir.path().join("created_peer"))
            .unwrap()
            .try_into()
            .unwrap();
        let handle = p.bm.peer_of(&p.b, 42).unwrap();
        let session = p.b.get(&session_storage_key(&created));
        let prekeys = p.b.get("prekeys/v2").unwrap();
        if point == "before_commit" {
            assert_eq!(handle, None);
            assert!(matches!(session, Err(StorageError::NotFound)));
            assert_eq!(prekeys, b"old", "prekey not consumed");
        } else {
            assert_eq!(handle, Some(created));
            assert!(session.is_ok());
            assert_eq!(prekeys, b"rotated");
        }
    }
}

// ── Q1: unknown commit outcome, then the process dies ─────────────────────────

#[test]
fn unknown_outcome_child() {
    let (Ok(scenario), Ok(dir)) = (
        std::env::var("ARCIUM_UNKNOWN_CHILD"),
        std::env::var(DIR_ENV),
    ) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let ids = std::fs::read(dir.join("ids")).unwrap();
    let fx = Fixture {
        dir: dir.clone(),
        alice_pk: ids[..32].try_into().unwrap(),
        bob_pk: ids[32..].try_into().unwrap(),
    };
    let mut p = fx.peers();
    let (op, fault) = scenario.split_once('/').unwrap();
    test_hooks::inject(if fault == "stored" {
        CommitFault::UnknownStored
    } else {
        CommitFault::UnknownLost
    });
    let r = match op {
        "send" => {
            p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, b"L1", b"once")
                .map(|_| ())
        }
        _ => {
            let wire = std::fs::read(dir.join("wire")).unwrap();
            p.bm.receive(&mut p.b, p.bob_pk, BOB_HANDLE, &wire)
                .map(|_| ())
        }
    };
    assert!(matches!(r, Err(MessagingError::OutcomeUnknown { .. })));
    // Nothing was handed out; the process dies before any recovery.
    std::process::abort();
}

#[cfg(unix)]
fn run_unknown_child(fx: &Fixture, scenario: &str) {
    use std::os::unix::process::ExitStatusExt;
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "messaging::tests::crash::unknown_outcome_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ARCIUM_UNKNOWN_CHILD", scenario)
        .env(DIR_ENV, &fx.dir)
        .status()
        .unwrap();
    assert_eq!(status.signal(), Some(6), "{status:?}");
}

/// Q1 for sends: after `OutcomeUnknown` and a crash, the restarted process
/// repeats the logical send. Whichever way the commit went, exactly one
/// ciphertext exists for it and the peer accepts it once.
#[cfg(unix)]
#[test]
fn unknown_send_outcome_then_crash_never_duplicates_or_forks() {
    for (fault, committed) in [("stored", true), ("lost", false)] {
        let dir = tempfile::tempdir().unwrap();
        let fx = fixture(dir.path());
        run_unknown_child(&fx, &format!("send/{fault}"));
        let mut p = fx.peers();
        assert_eq!(
            generation(&mut p.a, p.alice_pk, ALICE_HANDLE),
            u64::from(committed)
        );
        let m = match p
            .am
            .send(&mut p.a, p.alice_pk, ALICE_HANDLE, b"L1", b"once")
            .unwrap()
        {
            SendOutcome::AlreadyPending(m) if committed => m,
            SendOutcome::Sent(m) if !committed => m,
            other => panic!("{fault}: {other:?}"),
        };
        assert_eq!(Header::from_bytes(&m.wire[..HEADER_SIZE]).unwrap().n, 0);
        assert_eq!(
            p.am.pending_outgoing(&p.a, ALICE_HANDLE).unwrap(),
            vec![m.clone()]
        );
        assert_eq!(
            *accepted(p.bob_receives(&m.wire).unwrap()).plaintext,
            b"once"
        );
        let next = p.alice_sends(b"next");
        assert_eq!(
            *accepted(p.bob_receives(&next.wire).unwrap()).plaintext,
            b"next"
        );
    }
}

/// Q1 for receives: after `OutcomeUnknown` and a crash, the message is
/// delivered to the application exactly as the store recorded it, and
/// receiving it again never advances the ratchet a second time.
#[cfg(unix)]
#[test]
fn unknown_receive_outcome_then_crash_accepts_once() {
    for (fault, committed) in [("stored", true), ("lost", false)] {
        let dir = tempfile::tempdir().unwrap();
        let fx = fixture(dir.path());
        let wire = fx.peers().alice_sends(b"in").wire;
        std::fs::write(dir.path().join("wire"), &wire).unwrap();
        run_unknown_child(&fx, &format!("receive/{fault}"));
        let mut p = fx.peers();
        assert_eq!(
            generation(&mut p.b, p.bob_pk, BOB_HANDLE),
            u64::from(committed)
        );
        let pending = p.bm.pending_incoming(&p.b, BOB_HANDLE).unwrap();
        assert_eq!(pending.len(), usize::from(committed));
        match p.bob_receives(&wire).unwrap() {
            Received::Duplicate {
                undelivered: Some(m),
                ..
            } if committed => assert_eq!(*m.plaintext, b"in"),
            Received::Accepted(m) if !committed => assert_eq!(*m.plaintext, b"in"),
            other => panic!("{fault}: {other:?}"),
        }
        assert_eq!(generation(&mut p.b, p.bob_pk, BOB_HANDLE), 1);
    }
}

/// Scenario 7: a process death before the removal's commit leaves the session
/// and every record as they were; after it, the session is gone and the
/// records that detect repeats remain.
#[cfg(unix)]
#[test]
fn process_killed_around_a_removal_loses_no_obligation() {
    for point in [
        "remove_before_commit",
        "remove_after_commit",
        "after_return",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let fx = fixture(dir.path());
        let mut p = fx.peers();
        let m = new_message(
            p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, b"L", b"x")
                .unwrap(),
        );
        p.am.abandon_outgoing(&mut p.a, ALICE_HANDLE, &m.message_id)
            .unwrap();
        drop(p);
        run_child(&fx, "remove", point);
        let mut p = fx.peers();
        let present = p.am.peer_of(&p.a, ALICE_HANDLE).unwrap().is_some();
        assert_eq!(present, point == "remove_before_commit", "{point}");
        if present {
            assert_eq!(generation(&mut p.a, p.alice_pk, ALICE_HANDLE), 1);
            p.am.remove_session(&mut p.a, p.alice_pk, ALICE_HANDLE)
                .unwrap();
        }
        assert!(p.a.list_keys_with_prefix("session:").unwrap().is_empty());
        // The logical id keeps its outcome for any later session.
        let again = pair();
        let mut ad = p.alice_pk.to_vec();
        ad.extend_from_slice(&p.bob_pk);
        let s = Session {
            ad,
            peer_identity_pk: p.bob_pk,
            ..again.alice
        };
        p.am.create_session(
            &mut p.a,
            p.alice_pk,
            new_session(ALICE_HANDLE, s, SessionRole::Initiator),
        )
        .unwrap();
        assert_eq!(
            p.am.send(&mut p.a, p.alice_pk, ALICE_HANDLE, b"L", b"x")
                .unwrap(),
            SendOutcome::Abandoned {
                message_id: m.message_id
            }
        );
    }
}
