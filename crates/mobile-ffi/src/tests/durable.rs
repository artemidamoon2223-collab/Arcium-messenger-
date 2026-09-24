//! S2-B2 tests: durable sessions and messages through the FFI, including
//! real process deaths.

use super::*;

// ── S2-B2: durable sessions and messages ─────────────────────────────────

/// A database path that outlives the core, so a test can reopen it.
fn db_path() -> String {
    tempdir()
        .unwrap()
        .keep()
        .join("db")
        .to_str()
        .unwrap()
        .to_string()
}

fn open_at(path: &str, byte: u8) -> Arc<ArciumCore> {
    ArciumCore::new(path.to_string(), key32(byte)).unwrap()
}

/// Alice and Bob with an established session (handle 1 on both sides), each
/// in a file database. Returns the two paths.
fn established_pair() -> (String, String) {
    let (pa, pb) = (db_path(), db_path());
    let bob = open_at(&pb, 1);
    bob.save_identity(Identity::generate()).unwrap();
    bob.establish_prekeys().unwrap();
    let alice = open_at(&pa, 2);
    alice.save_identity(Identity::generate()).unwrap();
    let hs = alice
        .establish_session_initiator(1, bob.export_prekey_bundle().unwrap())
        .unwrap();
    bob.establish_session_responder(1, hs).unwrap();
    (pa, pb)
}

/// Before S2-B2 a session lived only in memory: a new `ArciumCore` on the
/// same database had none. Now both sides reopen and keep talking.
#[test]
fn sessions_survive_reopening_the_database() {
    let (pa, pb) = established_pair();
    for i in 0u8..3 {
        let (alice, bob) = (open_at(&pa, 2), open_at(&pb, 1));
        assert!(alice.has_session(1).unwrap() && bob.has_session(1).unwrap());
        let m = send(&alice, 1, vec![i]).unwrap();
        drop(alice);
        assert_eq!(recv(&bob, 1, m).unwrap(), vec![i]);
        let r = send(&bob, 1, vec![i, i]).unwrap();
        drop(bob);
        assert_eq!(recv(&open_at(&pa, 2), 1, r).unwrap(), vec![i, i]);
    }
}

#[test]
fn the_initiator_handshake_can_be_read_again_after_reopening() {
    let bob = fresh_core(3);
    bob.save_identity(Identity::generate()).unwrap();
    bob.establish_prekeys().unwrap();
    let pa = db_path();
    let alice = open_at(&pa, 4);
    alice.save_identity(Identity::generate()).unwrap();
    let hs = alice
        .establish_session_initiator(9, bob.export_prekey_bundle().unwrap())
        .unwrap();
    drop(alice);
    // Lost before sending: read it back from the reopened store.
    let again = open_at(&pa, 4).initiator_handshake(9).unwrap();
    assert_eq!(again, Some(hs.clone()));
    bob.establish_session_responder(9, again.unwrap()).unwrap();
    assert_eq!(bob.initiator_handshake(9).unwrap(), None);
}

#[test]
fn outgoing_messages_are_resent_byte_for_byte_and_accepted_once() {
    let (pa, pb) = established_pair();
    let alice = open_at(&pa, 2);
    let sent = alice.send_message(1, b"resend me".to_vec()).unwrap();
    drop(alice);

    let alice = open_at(&pa, 2);
    let pending = alice.pending_outgoing(1).unwrap();
    assert_eq!(
        pending,
        vec![sent.clone()],
        "same id, same bytes after reopening"
    );

    let bob = open_at(&pb, 1);
    match bob.receive_message(1, pending[0].wire.clone()).unwrap() {
        ReceiveResult::Accepted { message } => {
            assert_eq!(message.plaintext, b"resend me");
            assert_eq!(message.message_id, sent.message_id);
        }
        other => panic!("{other:?}"),
    }
    // The retransmission of the same bytes is a duplicate, still undelivered.
    match bob.receive_message(1, sent.wire.clone()).unwrap() {
        ReceiveResult::Duplicate {
            message_id,
            undelivered: Some(m),
        } => {
            assert_eq!(message_id, sent.message_id);
            assert_eq!(m.plaintext, b"resend me");
        }
        other => panic!("{other:?}"),
    }
    assert!(bob
        .acknowledge_incoming(1, sent.message_id.clone())
        .unwrap());
    assert!(!bob
        .acknowledge_incoming(1, sent.message_id.clone())
        .unwrap());
    assert_eq!(
        bob.receive_message(1, sent.wire.clone()).unwrap(),
        ReceiveResult::Duplicate {
            message_id: sent.message_id.clone(),
            undelivered: None
        }
    );
    assert!(alice
        .acknowledge_outgoing(1, sent.message_id.clone())
        .unwrap());
    assert!(alice.pending_outgoing(1).unwrap().is_empty());
    assert!(bob.pending_incoming(1).unwrap().is_empty());
}

/// Two `ArciumCore` objects on one database — what reopening the store
/// without closing the old handle produces. Neither caches a session, so
/// alternating between them never forks the ratchet.
#[test]
fn two_cores_on_one_database_share_one_session_state() {
    let (pa, pb) = established_pair();
    let (a1, a2) = (open_at(&pa, 2), open_at(&pa, 2));
    let bob = open_at(&pb, 1);
    for i in 0u8..6 {
        let core = if i % 2 == 0 { &a1 } else { &a2 };
        let m = send(core, 1, vec![i]).unwrap();
        assert_eq!(recv(&bob, 1, m).unwrap(), vec![i]);
    }
    assert_eq!(a1.pending_outgoing(1).unwrap().len(), 6);
    assert_eq!(
        a1.pending_outgoing(1).unwrap(),
        a2.pending_outgoing(1).unwrap()
    );
}

/// Two cores sending concurrently: every returned message has a distinct
/// chain position, is in the outbox, and is accepted by the peer; every
/// failure is a conflict or a busy store that released nothing.
#[test]
fn concurrent_cores_release_one_message_per_position() {
    let (pa, pb) = established_pair();
    let gate = Arc::new(std::sync::Barrier::new(2));
    let joins: Vec<_> = (0u8..2)
        .map(|t| {
            let (pa, gate) = (pa.clone(), gate.clone());
            std::thread::spawn(move || {
                let core = open_at(&pa, 2);
                gate.wait();
                (0u8..20)
                    .filter_map(|i| match core.send_message(1, vec![t, i]) {
                        Ok(m) => Some(m),
                        Err(CoreError::SessionConflict { .. } | CoreError::Storage { .. }) => None,
                        Err(e) => panic!("{e:?}"),
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let mut released: Vec<_> = joins.into_iter().flat_map(|j| j.join().unwrap()).collect();
    let mut outbox = open_at(&pa, 2).pending_outgoing(1).unwrap();
    released.sort_by(|x, y| x.message_id.cmp(&y.message_id));
    outbox.sort_by(|x, y| x.message_id.cmp(&y.message_id));
    assert_eq!(
        released, outbox,
        "exactly the committed messages were released"
    );
    let mut positions: Vec<_> = released
        .iter()
        .map(|m| m.wire[..HEADER_SIZE].to_vec())
        .collect();
    positions.sort();
    positions.dedup();
    assert_eq!(
        positions.len(),
        released.len(),
        "no two messages share a header"
    );
    let bob = open_at(&pb, 1);
    for m in &released {
        assert!(matches!(
            bob.receive_message(1, m.wire.clone()).unwrap(),
            ReceiveResult::Accepted { .. }
        ));
    }
}

/// A corrupt stored session is reported and never replaced — neither by
/// messaging on it nor by establishing a new session with that peer.
#[test]
fn a_corrupt_session_record_is_reported_and_not_overwritten() {
    let (pa, _pb) = established_pair();
    let alice = open_at(&pa, 2);
    // Find the session record: the only `session:` key.
    let key = {
        let store = alice.store.lock().unwrap();
        let keys = store.list_keys_with_prefix("session:").unwrap();
        assert_eq!(keys.len(), 1);
        keys[0].clone()
    };
    alice.store.lock().unwrap().put(&key, b"corrupt").unwrap();
    assert!(matches!(
        alice.send_message(1, b"x".to_vec()),
        Err(CoreError::InvalidSessionState { session_id: 1, .. })
    ));
    assert!(matches!(
        alice.receive_message(1, vec![0u8; HEADER_SIZE + 40]),
        Err(CoreError::InvalidSessionState { session_id: 1, .. })
    ));
    assert_eq!(alice.store.lock().unwrap().get(&key).unwrap(), b"corrupt");
}

#[test]
fn acknowledging_an_unknown_message_is_reported() {
    let (_pa, pb) = established_pair();
    let bob = open_at(&pb, 1);
    assert!(matches!(
        bob.acknowledge_incoming(1, vec![0u8; 32]),
        Err(CoreError::UnknownMessage { session_id: 1 })
    ));
    assert!(matches!(
        bob.acknowledge_incoming(1, vec![0u8; 5]),
        Err(CoreError::UnknownMessage { session_id: 1 })
    ));
    assert!(!bob.acknowledge_outgoing(1, vec![0u8; 32]).unwrap());
}

// ── S2-B2: process termination ───────────────────────────────────────────
//
// The child is this test binary running only `ffi_crash_child`. It does one
// FFI call on a file database, records what it returned, and dies by
// `abort()` before acknowledging anything. Real process deaths on the host;
// not power-loss tests. Deaths inside the transaction are covered in
// `core_protocol::messaging`.

const FFI_CHILD_ENV: &str = "ARCIUM_FFI_CHILD";
const FFI_DIR_ENV: &str = "ARCIUM_FFI_DIR";

#[test]
fn ffi_crash_child() {
    let (Ok(scenario), Ok(dir)) = (std::env::var(FFI_CHILD_ENV), std::env::var(FFI_DIR_ENV)) else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let read = |n: &str| std::fs::read_to_string(dir.join(n)).unwrap();
    match scenario.as_str() {
        "send" => {
            let m = open_at(&read("a"), 2)
                .send_message(1, b"in flight".to_vec())
                .unwrap();
            std::fs::write(dir.join("published"), m.wire).unwrap();
        }
        "receive" => {
            let wire = std::fs::read(dir.join("wire")).unwrap();
            recv(&open_at(&read("b"), 1), 1, wire).unwrap();
        }
        "respond" => {
            let hs = std::fs::read(dir.join("handshake")).unwrap();
            open_at(&read("b"), 1)
                .establish_session_responder(5, hs)
                .unwrap();
        }
        other => panic!("unknown scenario {other}"),
    }
    std::process::abort();
}

#[cfg(unix)]
fn run_ffi_child(dir: &std::path::Path, scenario: &str) {
    use std::os::unix::process::ExitStatusExt;
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::durable::ffi_crash_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(FFI_CHILD_ENV, scenario)
        .env(FFI_DIR_ENV, dir)
        .status()
        .unwrap();
    assert_eq!(
        status.signal(),
        Some(6),
        "child must die by abort(): {status:?}"
    );
}

fn crash_dir(pa: &str, pb: &str) -> std::path::PathBuf {
    let dir = tempdir().unwrap().keep();
    std::fs::write(dir.join("a"), pa).unwrap();
    std::fs::write(dir.join("b"), pb).unwrap();
    dir
}

#[cfg(unix)]
#[test]
fn killed_after_sending_the_message_is_resent_byte_for_byte() {
    let (pa, pb) = established_pair();
    let dir = crash_dir(&pa, &pb);
    run_ffi_child(&dir, "send");
    let published = std::fs::read(dir.join("published")).unwrap();
    let alice = open_at(&pa, 2);
    let pending = alice.pending_outgoing(1).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].wire, published);
    let bob = open_at(&pb, 1);
    assert_eq!(recv(&bob, 1, published).unwrap(), b"in flight");
    let r = send(&bob, 1, b"ack".to_vec()).unwrap();
    assert_eq!(recv(&alice, 1, r).unwrap(), b"ack");
}

#[cfg(unix)]
#[test]
fn killed_before_delivering_the_message_it_is_still_pending() {
    let (pa, pb) = established_pair();
    let dir = crash_dir(&pa, &pb);
    let wire = send(&open_at(&pa, 2), 1, b"undelivered".to_vec()).unwrap();
    std::fs::write(dir.join("wire"), &wire).unwrap();
    run_ffi_child(&dir, "receive");
    let bob = open_at(&pb, 1);
    let pending = bob.pending_incoming(1).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].plaintext, b"undelivered");
    assert!(matches!(
        bob.receive_message(1, wire).unwrap(),
        ReceiveResult::Duplicate {
            undelivered: Some(_),
            ..
        }
    ));
    assert!(bob
        .acknowledge_incoming(1, pending[0].message_id.clone())
        .unwrap());
}

/// The responder's prekey rotation and session are committed together,
/// so after a kill right after the call both are there.
#[cfg(unix)]
#[test]
fn killed_after_answering_a_handshake_the_session_and_rotation_both_persist() {
    let pb = db_path();
    let bob = open_at(&pb, 1);
    bob.save_identity(Identity::generate()).unwrap();
    bob.establish_prekeys().unwrap();
    let published = current_opk_id(&bob).unwrap();
    let alice = fresh_core(6);
    alice.save_identity(Identity::generate()).unwrap();
    let hs = alice
        .establish_session_initiator(5, bob.export_prekey_bundle().unwrap())
        .unwrap();
    drop(bob);
    let dir = crash_dir("", &pb);
    std::fs::write(dir.join("handshake"), &hs).unwrap();
    run_ffi_child(&dir, "respond");

    let bob = open_at(&pb, 1);
    assert!(bob.has_session(5).unwrap());
    assert_ne!(current_opk_id(&bob).unwrap(), published, "prekey consumed");
    // The same handshake cannot be answered twice.
    assert!(matches!(
        bob.establish_session_responder(6, hs),
        Err(CoreError::OneTimePrekeyUnavailable { .. })
    ));
    let m = send(&alice, 5, b"after restart".to_vec()).unwrap();
    assert_eq!(recv(&bob, 5, m).unwrap(), b"after restart");
}
