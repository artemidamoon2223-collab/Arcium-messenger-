//! R-4 and R-5: time bounds of the network layer and retransmission backoff
//! (docs/NET-MESSAGING.md, section 7). The bounds are scaled down here with
//! `NetworkMessenger::set_limits`; the production values are 30 s per
//! request, 120 s per round and 5 minutes between retransmissions.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::net_harness::*;
use crate::network::NetworkMessenger;
use relay::protocol::{read_frame, write_frame};

/// A relay that answers every request with a frame header announcing 1 MiB
/// and then sends one byte every 100 ms: each read succeeds within any
/// per-read timeout, so only a bound on the request as a whole ends it.
fn trickle_relay() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let _ = s.write_all(&(1024u32 * 1024).to_be_bytes());
                loop {
                    std::thread::sleep(Duration::from_millis(100));
                    if s.write_all(&[0]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// A transparent proxy to `relay` that holds every response for `delay`.
fn slow_relay(relay: &str, delay: Duration) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let target = relay.to_string();
    std::thread::spawn(move || {
        for mut client in listener.incoming().flatten() {
            let target = target.clone();
            std::thread::spawn(move || {
                let Ok(mut server) = TcpStream::connect(&target) else {
                    return;
                };
                while let Ok(Some(req)) = read_frame(&mut client) {
                    if write_frame(&mut server, &req).is_err() {
                        break;
                    }
                    let Ok(Some(resp)) = read_frame(&mut server) else {
                        break;
                    };
                    std::thread::sleep(delay);
                    if write_frame(&mut client, &resp).is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// L1. The trickling relay of the 2026-11-10 review: before the per-request
/// deadline, a sync with a 300 ms timeout did not return within 20 s (one
/// 1 MiB frame at this rate takes about 29 hours). Now it returns, with an
/// error, within the deadline (1 s here) plus a margin.
#[test]
fn a_trickling_relay_cannot_hold_a_round_past_the_request_deadline() {
    let addr = trickle_relay();
    let device = Device::new(&addr, 9);
    let net = NetworkMessenger::new(device.core.clone(), addr, 0, 300);
    net.set_limits(Duration::from_secs(1), Duration::from_secs(120), Duration::from_secs(300));
    let (tx, rx) = mpsc::channel();
    let started = Instant::now();
    std::thread::spawn(move || {
        let _ = tx.send(net.sync().errors);
    });
    let errors = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("sync must return within the request deadline plus a margin");
    let took = started.elapsed();
    assert!(!errors.is_empty(), "a request that ran out is an error");
    assert!(took < Duration::from_secs(3), "took {took:?}");
}

/// L2 and progress on a slow link. Every relay answer takes 150 ms and a
/// round may spend 1 s on the relay. 300 texts wait in the mailbox (two
/// pages). A round runs out of budget, ends with the budget error, and keeps
/// what it processed; the following rounds continue. Every text arrives
/// exactly once.
#[test]
fn a_slow_relay_ends_rounds_at_the_budget_and_every_text_still_arrives_once() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    const N: usize = 300;
    for i in 0..N {
        alice.send(&bob, &format!("m{i}"), &format!("text {i}"));
    }
    let r = alice.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(stored_messages(&relay, &bob).len(), N);

    let slow = slow_relay(&addr, Duration::from_millis(150));
    let net = NetworkMessenger::new(bob.core.clone(), slow, 0, 2000);
    net.set_limits(Duration::from_secs(2), Duration::from_secs(1), Duration::from_secs(300));
    let (mut accepted, mut duplicates, mut budget_errors, mut rounds) = (0, 0, 0, 0);
    while accepted < N as u32 && rounds < 20 {
        let r = net.sync();
        rounds += 1;
        accepted += r.accepted;
        duplicates += r.duplicates;
        budget_errors += r.errors.iter().filter(|e| e.contains("round budget exhausted")).count();
        for e in &r.errors {
            assert!(e.contains("round budget exhausted"), "unexpected error: {e}");
        }
    }
    assert_eq!(accepted, N as u32, "every text accepted, in {rounds} rounds");
    assert_eq!(duplicates, 0, "nothing processed twice");
    assert!(budget_errors >= 1, "at least one round ran out of budget");
    let texts = bob.texts(&alice);
    assert_eq!(texts.len(), N, "each text once");
    for i in 0..N {
        assert!(texts.contains(&format!("text {i}")), "text {i}");
    }
    println!("{N} texts over a slow relay: {rounds} rounds, {budget_errors} ran out of budget");
    relay.stop();
}

/// L3. A peer that never answers: one text is retransmitted after 50 ms, then
/// after twice as long each time, up to 3 s (the production 5 s and 5 min,
/// scaled by 1/100). Over 6 s (10 minutes scaled) it is sent at most 9 times.
/// With the wait held at 50 ms (the old fixed interval) it is sent far more.
#[test]
fn retransmissions_back_off_to_the_cap() {
    let mut counts = Vec::new();
    for cap in [Duration::from_secs(3), Duration::from_millis(50)] {
        let relay = start_relay();
        let addr = relay.addr().to_string();
        let (alice, bob) = connected(&addr);
        let net = NetworkMessenger::new(alice.core.clone(), addr.clone(), 50, 2000);
        net.set_limits(Duration::from_secs(30), Duration::from_secs(120), cap);
        net.send_text(bob.pk.clone(), b"backoff".to_vec(), [b"never answered".as_slice(), CANARY].concat())
            .unwrap();
        // The relay stores an identical envelope once, so the sends are
        // counted from the reports: nothing else is pending for Alice.
        let started = Instant::now();
        let mut sends = 0;
        while started.elapsed() < Duration::from_secs(6) {
            let r = net.sync();
            assert!(r.errors.is_empty(), "{:?}", r.errors);
            sends += r.published as usize;
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(stored_messages(&relay, &bob).len(), 1);
        counts.push(sends);
        relay.stop();
    }
    println!("sends over 10 scaled minutes: with backoff {}, fixed interval {}", counts[0], counts[1]);
    assert!((5..=9).contains(&counts[0]), "with backoff: {}", counts[0]);
    assert!(counts[1] > 3 * counts[0], "fixed interval: {}", counts[1]);
}

/// L3 with the production values: the waits after each send.
#[test]
fn the_retransmit_waits_double_from_five_seconds_to_five_minutes() {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let device = Device::new(&addr, 7);
    let net = NetworkMessenger::new(device.core.clone(), addr, 5_000, 10_000);
    let cap = crate::network::RETRANSMIT_CAP;
    let waits: Vec<u64> = (1..=10).map(|n| net.retransmit_wait(n, cap).as_secs()).collect();
    assert_eq!(waits, vec![5, 10, 20, 40, 80, 160, 300, 300, 300, 300]);
    assert_eq!(net.retransmit_wait(u32::MAX, cap).as_secs(), 300);
    relay.stop();
}
