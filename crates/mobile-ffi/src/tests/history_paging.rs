//! R-3: the history in pages, and the record of outgoing entries not yet
//! final (`chat-open`), which `refresh` walks instead of the whole history
//! (docs/NET-MESSAGING.md, section 10).

use std::time::Instant;

use super::net_harness::*;
use crate::network::chat::{ChatEntryState as S, ChatSessionState};

fn canary() -> String {
    String::from_utf8(CANARY.to_vec()).unwrap()
}

fn meet(a: &Device, b: &Device) {
    a.net.add_named_contact(b.core.contact_card().unwrap(), "peer".into()).unwrap();
    b.net.add_named_contact(a.core.contact_card().unwrap(), "peer".into()).unwrap();
}

fn say(from: &Device, to: &Device, app_id: &str, text: &str) {
    from.net
        .chat_send(to.pk.clone(), app_id.as_bytes().to_vec(), format!("{text}{}", canary()))
        .unwrap();
}

fn round(devices: &[&Device]) {
    for d in devices {
        let r = d.net.sync_conversations();
        assert!(r.errors.is_empty(), "{:?}", r.errors);
    }
}

/// Alice and Bob with an established conversation of `n` texts each way.
fn talking(addr: &str, n: usize) -> (Device, Device) {
    let (alice, bob) = (Device::new(addr, 1), Device::new(addr, 2));
    meet(&alice, &bob);
    round(&[&bob]);
    for i in 0..n {
        say(&alice, &bob, &format!("a{i}"), &format!("from alice {i}"));
        say(&bob, &alice, &format!("b{i}"), &format!("from bob {i}"));
        if i % 20 == 19 || i + 1 == n {
            for _ in 0..2 {
                round(&[&alice, &bob]);
            }
        }
    }
    for _ in 0..2 {
        round(&[&alice, &bob]);
    }
    (alice, bob)
}

fn seqs(d: &Device, with: &Device, before: Option<u64>, limit: u32) -> Vec<u64> {
    d.net
        .chat_entries_page(with.pk.clone(), before, limit)
        .unwrap()
        .into_iter()
        .map(|e| e.seq)
        .collect()
}

/// Walks the whole history backwards in pages of `limit`.
fn all_pages(d: &Device, with: &Device, limit: u32) -> Vec<u64> {
    let mut pages = Vec::new();
    let mut before = None;
    loop {
        let page = seqs(d, with, before, limit);
        if page.is_empty() {
            break;
        }
        assert!(page.len() <= limit as usize);
        assert!(page.windows(2).all(|w| w[1] == w[0] + 1), "a page is contiguous and oldest first");
        before = Some(page[0]);
        pages.push(page);
    }
    pages.reverse();
    pages.concat()
}

/// Pages of 1, 7 and 200 cover the history exactly once, in order, and
/// equal the full read. Entries that arrive while paging backwards do not
/// shift the pages already read or those still to come.
#[test]
fn pages_cover_the_history_exactly_once_in_order() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr, 30);
    let full: Vec<u64> = alice.net.chat_entries(bob.pk.clone()).unwrap().iter().map(|e| e.seq).collect();
    assert_eq!(full, (1..=60).collect::<Vec<u64>>());
    for limit in [1, 7, 200] {
        assert_eq!(all_pages(&alice, &bob, limit), full, "limit {limit}");
    }
    // The newest page is the end of the history; a page ends before its bound.
    assert_eq!(seqs(&alice, &bob, None, 7), (54..=60).collect::<Vec<u64>>());
    assert_eq!(seqs(&alice, &bob, Some(10), 7), (3..=9).collect::<Vec<u64>>());
    assert_eq!(seqs(&alice, &bob, Some(3), 7), vec![1, 2]);
    assert!(seqs(&alice, &bob, Some(1), 7).is_empty());

    // New entries while paging: the walk from a fixed start is unaffected.
    let first = seqs(&alice, &bob, None, 7);
    let mut before = Some(first[0]);
    let mut walked = first.clone();
    let mut extra = 0;
    loop {
        say(&alice, &bob, &format!("late{extra}"), "late");
        extra += 1;
        let page = seqs(&alice, &bob, before, 7);
        if page.is_empty() {
            break;
        }
        before = Some(page[0]);
        walked.splice(0..0, page);
    }
    assert_eq!(walked, full, "no gap and no repeat");
    assert_eq!(seqs(&alice, &bob, None, 200).len(), 60 + extra);

    for bad in [0, 201] {
        assert!(alice.net.chat_entries_page(bob.pk.clone(), None, bad).is_err(), "limit {bad}");
    }
    relay.stop();
}

/// A small deterministic generator, so a failure names its seed.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self, n: u64) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.0 >> 33) % n
    }
}

/// The record equals a full scan after every step of random sends, rounds
/// (receipts, receives) on both sides, and once a history written without
/// it (dropped here, as a build before it wrote none) is read again.
#[test]
fn the_open_entry_record_always_equals_a_full_scan() {
    for seed in [1u64, 7, 42] {
        let relay = start_relay();
        let addr = relay.addr().to_string();
        let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
        meet(&alice, &bob);
        round(&[&bob]);
        let mut rng = Lcg(seed);
        for step in 0..120 {
            match rng.next(6) {
                0 | 1 => say(&alice, &bob, &format!("a{step}"), "a"),
                2 => say(&bob, &alice, &format!("b{step}"), "b"),
                3 => round(&[&alice]),
                4 => round(&[&bob]),
                _ => {
                    // An install from before the record: dropped, rebuilt.
                    alice.net.drop_open_record(&bob.pk);
                    assert!(!alice.net.has_open_record(&bob.pk));
                }
            }
            for (d, w) in [(&alice, &bob), (&bob, &alice)] {
                let (record, scan) = d.net.open_record_and_scan(&w.pk);
                assert_eq!(record, scan, "seed {seed} step {step}");
            }
        }
        for _ in 0..3 {
            round(&[&alice, &bob]);
        }
        let (record, scan) = alice.net.open_record_and_scan(&bob.pk);
        assert_eq!((record.as_slice(), scan.as_slice()), (&[][..], &[][..]), "seed {seed}: all final");
        relay.stop();
    }
}

/// A conflict resolution marks texts NotDelivered: they leave the record.
#[test]
fn texts_given_up_in_a_conflict_leave_the_record() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    meet(&alice, &bob);
    round(&[&alice, &bob]);
    say(&alice, &bob, "a", "from alice");
    say(&bob, &alice, "b", "from bob");
    alice.net.start_session(bob.pk.clone()).unwrap();
    bob.net.start_session(alice.pk.clone()).unwrap();
    round(&[&alice, &bob]);
    round(&[&alice, &bob]);
    let (g, s) = if alice.pk > bob.pk { (&alice, &bob) } else { (&bob, &alice) };
    assert_eq!(g.net.conversation(s.pk.clone()).unwrap().session, ChatSessionState::Conflict { can_resolve: true });
    assert_eq!(g.net.open_record_and_scan(&s.pk).0.len(), 1);
    g.net.resolve_session_conflict(s.pk.clone()).unwrap();
    let (record, scan) = g.net.open_record_and_scan(&s.pk);
    assert_eq!(record, scan);
    assert!(record.is_empty(), "the given-up text is final");
    let given_up = g.net.chat_entries(s.pk.clone()).unwrap();
    assert_eq!(given_up.iter().filter(|e| e.outgoing).map(|e| e.state).collect::<Vec<_>>(), vec![S::NotDelivered]);
    relay.stop();
}

/// The conversation summary reads only what is unread: its unread count and
/// last entry match the full history.
#[test]
fn the_conversation_summary_matches_the_full_history() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = talking(&addr, 10);
    let c = alice.net.conversation(bob.pk.clone()).unwrap();
    let full = alice.net.chat_entries(bob.pk.clone()).unwrap();
    assert_eq!(c.unread, 10);
    assert_eq!(c.last.as_ref().map(|e| e.seq), full.last().map(|e| e.seq));
    alice.net.mark_seen(bob.pk.clone()).unwrap();
    let c = alice.net.conversation(bob.pk.clone()).unwrap();
    assert_eq!(c.unread, 0);
    assert_eq!(c.last.map(|e| e.seq), full.last().map(|e| e.seq), "last entry read by seq when nothing is unread");
    say(&bob, &alice, "more", "more");
    round(&[&bob, &alice]);
    assert_eq!(alice.net.conversation(bob.pk.clone()).unwrap().unread, 1);
    relay.stop();
}

/// Process death after the one-time build of the record, and after a queued
/// text's commit: after the restart the record equals a full scan, and the
/// text is sent once.
#[cfg(unix)]
#[test]
fn the_record_survives_a_crash_after_each_new_write() {
    for (scenario, point) in [("chat_sync", "chat_after_open_build"), ("chat_send", "chat_after_queue")] {
        let relay = start_relay();
        let addr = relay.addr().to_string();
        let (alice, bob) = talking(&addr, 5);
        say(&alice, &bob, "pending", "pending");
        alice.net.drop_open_record(&bob.pk);
        super::network_crash::run_child(&alice, &addr, scenario, Some(point), &bob.pk);
        let alice = alice.restart(&addr);
        let (record, scan) = alice.net.open_record_and_scan(&bob.pk);
        assert_eq!(record, scan, "{point}");
        for _ in 0..3 {
            round(&[&alice, &bob]);
        }
        let (record, scan) = alice.net.open_record_and_scan(&bob.pk);
        assert_eq!(record, scan, "{point}");
        assert!(record.is_empty(), "{point}: everything final");
        let got: Vec<String> = bob
            .net
            .chat_entries(alice.pk.clone())
            .unwrap()
            .into_iter()
            .filter(|e| !e.outgoing)
            .map(|e| e.text.0.replace(&canary(), ""))
            .collect();
        let once = |t: &str| got.iter().filter(|g| g.as_str() == t).count();
        assert_eq!(once("pending"), 1, "{point}: {got:?}");
        if scenario == "chat_send" {
            // The child's own text (tests::network_crash, "chat_send").
            assert_eq!(once("sent from the chat"), 1, "{point}: sent once: {got:?}");
        }
        relay.stop();
    }
}

/// Measurement, not a pass/fail check (run with `--ignored --nocapture`):
/// the cost of an idle round, of the conversation list and of reading the
/// newest page, at 50, 500 and 5000 history entries, debug build.
#[test]
#[ignore]
fn measure_history_cost() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = (Device::new(&addr, 1), Device::new(&addr, 2));
    meet(&alice, &bob);
    round(&[&bob]);
    let mut n = 0u32;
    let build = Instant::now();
    for target in [50u32, 500, 5000] {
        while n < target {
            alice.net.chat_send(bob.pk.clone(), format!("m{n}").into_bytes(), "x".repeat(40)).unwrap();
            n += 1;
            if n.is_multiple_of(200) || n == target {
                for _ in 0..2 {
                    alice.net.sync_conversations();
                    bob.net.sync_conversations();
                }
                alice.net.sync_conversations();
            }
        }
        let time = |f: &dyn Fn()| {
            let t = Instant::now();
            f();
            t.elapsed().as_millis()
        };
        let idle = time(&|| assert!(alice.net.sync_conversations().errors.is_empty()));
        let list = time(&|| {
            alice.net.conversations().unwrap();
        });
        let page = time(&|| {
            alice.net.chat_entries_page(bob.pk.clone(), None, 50).unwrap();
            alice.net.mark_seen(bob.pk.clone()).unwrap();
            alice.net.conversation(bob.pk.clone()).unwrap();
        });
        let full = time(&|| {
            alice.net.chat_entries(bob.pk.clone()).unwrap();
        });
        println!(
            "MEASURE history={n}: idle sync_conversations={idle} ms | conversations()={list} ms | \
             newest page of 50 + markSeen + conversation={page} ms | full chat_entries={full} ms | built in {} s",
            build.elapsed().as_secs()
        );
    }
    relay.stop();
}
