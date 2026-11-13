//! A commit whose outcome is unknown, followed by the application's own next
//! steps (`docs/NET-MESSAGING.md`, section 7; `docs/S2-B2-DURABLE-MESSAGING.md`,
//! section 7). The session is unresolved until `recover_session`; the network
//! layer has to run that itself, because it is what sends and the Android
//! application never calls it.
//!
//! The failed `COMMIT` is real: a second SQLite connection holds a read lock
//! on the store, so `COMMIT` returns `SQLITE_BUSY` after the busy timeout
//! (the technique of `core-storage`'s
//! `commit_blocked_by_a_reader_fails_and_publishes_nothing`). Each blocked
//! commit therefore takes about five seconds.

use super::net_harness::*;
use crate::network::chat::ChatEntryState as S;
use rusqlite::Connection;

fn meet(a: &Device, b: &Device) {
    a.net
        .add_named_contact(b.core.contact_card().unwrap(), "peer".into())
        .unwrap();
    b.net
        .add_named_contact(a.core.contact_card().unwrap(), "peer".into())
        .unwrap();
}

/// Sends the text `app_id` under that id; the entry's state, or the error text.
fn say(from: &Device, to: &Device, app_id: &str) -> Result<S, String> {
    from.net
        .chat_send(to.pk.clone(), app_id.as_bytes().to_vec(), app_id.into())
        .map(|e| e.state)
        .map_err(|e| e.to_string())
}

/// `d`'s history with `with`: (outgoing, state, text).
fn chat(d: &Device, with: &Device) -> Vec<(bool, S, String)> {
    d.net
        .chat_entries(with.pk.clone())
        .unwrap()
        .into_iter()
        .map(|e| (e.outgoing, e.state, e.text.0))
        .collect()
}

fn handle(of: &Device) -> u64 {
    core_crypto::session_handle::local_session_handle(of.pk.as_slice().try_into().unwrap())
}

/// Every `COMMIT` on `d`'s store fails while the returned connection holds
/// its read transaction; reads still work. `release` ends it.
fn block_commits(d: &Device) -> Connection {
    let reader = Connection::open(&d.path).unwrap();
    reader.execute_batch("BEGIN DEFERRED").unwrap();
    let _: i64 = reader
        .query_row("SELECT count(*) FROM kv", [], |r| r.get(0))
        .unwrap();
    reader
}

fn release(reader: Connection) {
    reader.execute_batch("ROLLBACK").unwrap();
}

/// One `sync_conversations` per device; none may report an error.
fn rounds(devices: &[&Device], n: usize) {
    for _ in 0..n {
        for d in devices {
            let r = d.net.sync_conversations();
            assert!(r.errors.is_empty(), "{:?}", r.errors);
        }
    }
}

/// A commit fails while a message is being received, and the user then sends
/// a text. Without recovery on the sending side, that send is refused, the
/// text stays queued, and every later round stops at it before reaching the
/// relay — for every contact, until the process restarts.
#[test]
fn a_send_after_an_unknown_commit_outcome_recovers_and_no_contact_is_stalled() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob, carol) = (
        Device::new(&addr, 1),
        Device::new(&addr, 2),
        Device::new(&addr, 3),
    );
    meet(&alice, &bob);
    meet(&alice, &carol);
    rounds(&[&bob, &carol], 1);
    assert_eq!(say(&alice, &bob, "a0"), Ok(S::Queued));
    assert_eq!(say(&alice, &carol, "c0"), Ok(S::Queued));
    rounds(&[&alice, &bob, &carol], 3);
    assert_eq!(chat(&alice, &bob), vec![(true, S::Delivered, "a0".into())]);
    assert_eq!(
        chat(&alice, &carol),
        vec![(true, S::Delivered, "c0".into())]
    );

    // Bob's text waits on the relay; Alice's commit of its acceptance fails.
    say(&bob, &alice, "b1").unwrap();
    rounds(&[&bob], 1);
    let reader = block_commits(&alice);
    let faulted = alice.net.sync_conversations();
    release(reader);
    assert!(
        faulted
            .errors
            .iter()
            .any(|e| e.contains("commit outcome unknown")),
        "the fault was not injected: {:?}",
        faulted.errors
    );

    // The fault is gone. Carol writes, and Alice's user sends to both.
    say(&carol, &alice, "k1").unwrap();
    rounds(&[&carol], 1);
    assert_eq!(
        say(&alice, &bob, "a1"),
        Ok(S::Pending),
        "recovered, then committed"
    );
    assert_eq!(say(&alice, &carol, "c1"), Ok(S::Pending));

    rounds(&[&alice, &bob, &carol], 3);
    assert_eq!(
        chat(&alice, &bob),
        vec![
            (true, S::Delivered, "a0".into()),
            (true, S::Delivered, "a1".into()),
            (false, S::Received, "b1".into()),
        ]
    );
    assert_eq!(
        chat(&alice, &carol),
        vec![
            (true, S::Delivered, "c0".into()),
            (true, S::Delivered, "c1".into()),
            (false, S::Received, "k1".into()),
        ]
    );
    assert_eq!(
        chat(&bob, &alice),
        vec![
            (false, S::Received, "a0".into()),
            (true, S::Delivered, "b1".into()),
            (false, S::Received, "a1".into()),
        ]
    );
    relay.stop();
}

/// The commit that fails is the creation of a session. Nothing was stored,
/// and the next round starts the session again. (Creating a session never
/// required recovery first; this pins that the text still goes out now that
/// the round recovers the handle before it gets there.)
#[test]
fn an_unknown_outcome_while_starting_a_session_does_not_keep_the_text_queued() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    meet(&alice, &bob);
    rounds(&[&bob, &alice], 1); // both bundles are on the relay
    assert_eq!(say(&alice, &bob, "a0"), Ok(S::Queued));

    let reader = block_commits(&alice);
    let faulted = alice.net.sync_conversations();
    release(reader);
    assert!(
        faulted
            .errors
            .iter()
            .any(|e| e.contains("commit outcome unknown")),
        "the fault was not injected: {:?}",
        faulted.errors
    );
    assert!(
        !alice.core.has_session(handle(&bob)).unwrap(),
        "nothing was stored"
    );

    rounds(&[&alice, &bob], 3);
    assert_eq!(chat(&alice, &bob), vec![(true, S::Delivered, "a0".into())]);
    assert_eq!(chat(&bob, &alice), vec![(false, S::Received, "a0".into())]);
    relay.stop();
}
