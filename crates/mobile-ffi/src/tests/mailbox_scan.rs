//! A-2: envelopes a round leaves on the relay no longer hide the envelopes
//! behind them. A round pages through the mailbox with FETCH_AFTER, in two
//! bounded passes (handshakes, then everything else), and deletes only what it
//! processed to completion. See `network.rs`, `NetworkMessenger::scan`.
//!
//! The retained prefix is made of genuine envelopes: Carol's messages to Bob,
//! whose handshake is held back, so Bob keeps them (no session yet). Every
//! envelope is produced by a device on a production relay, captured there and
//! placed on a fresh relay in the order a test needs. Nothing is forged.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::OnceLock;

use relay::protocol::{MAX_FETCH, MIN_PAGE};
use relay::server::{serve, RelayConfig, RelayHandle};

use super::net_harness::*;
use super::*;
use crate::network::wire::Envelope;
use crate::network::{scan_hook, NetworkMessenger, Pass, MAX_SCAN_ENVELOPES, MAX_SCAN_PAGES};

fn key(d: &Device) -> [u8; 32] {
    d.pk.as_slice().try_into().unwrap()
}

fn conn(addr: &str) -> relay::client::Connection {
    relay::client::Connection::connect(addr, std::time::Duration::from_secs(5)).unwrap()
}

fn handle_of(d: &Device) -> u64 {
    local_session_handle(d.pk.clone()).unwrap()
}

/// Envelopes stored for `to`, bytes only, in relay order.
fn stored(relay: &RelayHandle, to: &Device) -> Vec<Vec<u8>> {
    relay.stored(&key(to)).into_iter().map(|(_, e)| e).collect()
}

/// A fresh relay holding `envs` for `to`, in this order.
fn mailbox(envs: &[Vec<u8>], to: &Device) -> (RelayHandle, String) {
    mailbox_with(envs, to, RelayConfig::default())
}

fn mailbox_with(envs: &[Vec<u8>], to: &Device, config: RelayConfig) -> (RelayHandle, String) {
    let relay = serve(std::net::TcpListener::bind("127.0.0.1:0").unwrap(), config).unwrap();
    let addr = relay.addr().to_string();
    let mut c = conn(&addr);
    for e in envs {
        c.send(key(to), e.clone()).unwrap();
    }
    assert_eq!(relay.stored(&key(to)).len(), envs.len(), "all distinct");
    (relay, addr)
}

/// Removes and returns everything waiting for `to` on the production relay.
fn take_all(relay: &RelayHandle, addr: &str, to: &Device) -> Vec<(u64, Vec<u8>)> {
    let items = relay.stored(&key(to));
    conn(addr)
        .delete(key(to), items.iter().map(|(s, _)| *s).collect())
        .unwrap();
    items
}

/// Alice, Bob and Carol on a production relay. Alice and Bob have a session.
/// Carol, a pinned contact of Bob, started one too, but her handshake was
/// held back: `carol_msgs` are her OPEN message and texts to Bob, which Bob
/// can only keep until the handshake arrives.
struct World {
    relay: RelayHandle,
    addr: String,
    alice: Device,
    bob: Device,
    carol: Device,
    carol_hs: Vec<u8>,
    carol_msgs: Vec<Vec<u8>>,
}

fn world(carol_messages: usize) -> World {
    world_with(carol_messages, "waits for its handshake")
}

fn world_with(carol_messages: usize, text: &str) -> World {
    let relay = start_relay();
    let addr = relay.addr().to_string();
    let (alice, bob) = connected(&addr);
    let carol = Device::new(&addr, 3);
    carol.knows(&bob);
    bob.knows(&carol);
    carol.net.start_session(bob.pk.clone()).unwrap();
    for i in 1..carol_messages {
        carol.send(&bob, &format!("c{i}"), text);
    }
    carol.sync();
    let mut carol_hs = None;
    let mut carol_msgs = Vec::new();
    for (_, env) in take_all(&relay, &addr, &bob) {
        match Envelope::decode(&env) {
            Some(Envelope::Handshake { .. }) => carol_hs = Some(env),
            Some(Envelope::Message { sender, .. }) if sender == key(&carol) => carol_msgs.push(env),
            other => panic!("unexpected envelope for Bob: {other:?}"),
        }
    }
    assert_eq!(carol_msgs.len(), carol_messages);
    World {
        relay,
        addr,
        alice,
        bob,
        carol,
        carol_hs: carol_hs.expect("Carol's handshake"),
        carol_msgs,
    }
}

impl World {
    /// A new text from Alice to Bob: the exact envelope Alice's device
    /// published, taken off the production relay.
    fn alice_text(&self, id: &str, text: &str) -> Vec<u8> {
        let mid = self.alice.send(&self.bob, id, text);
        self.alice.sync();
        take_all(&self.relay, &self.addr, &self.bob)
            .into_iter()
            .map(|(_, e)| e)
            .find(|e| match Envelope::decode(e) {
                Some(Envelope::Message { wire, .. }) => {
                    core_protocol::messaging::message_id(&wire).as_slice() == mid.as_slice()
                }
                _ => false,
            })
            .expect("Alice's text on the relay")
    }

    /// Bob, pointed at another relay.
    fn bob_on(&self, addr: &str) -> Device {
        self.bob.restart(addr)
    }

    /// Bob has neither a session nor a recorded handshake with Carol: none of
    /// her kept messages moved anything.
    fn assert_nothing_from_carol(&self, bob: &Device) {
        assert!(!bob.core.has_session(handle_of(&self.carol)).unwrap());
        let (store, messenger) = bob.core.lock().unwrap();
        assert!(messenger
            .provisional_handshake(&store, handle_of(&self.carol))
            .unwrap()
            .is_none());
    }
}

/// Carol's messages, generated once for the whole file: producing 4095 real
/// envelopes takes a while, and every test only reads them. One test at a
/// time; a test that fails does not fail the others through a poisoned lock.
fn big_world() -> std::sync::MutexGuard<'static, World> {
    static W: OnceLock<std::sync::Mutex<World>> = OnceLock::new();
    W.get_or_init(|| std::sync::Mutex::new(world(DEFAULT_MAX_MAILBOX - 1)))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

use relay::protocol::DEFAULT_MAX_MAILBOX;

/// Counts FETCH_AFTER pages per pass for the next rounds on this thread.
fn count_pages() -> Rc<RefCell<[usize; 2]>> {
    let pages = Rc::new(RefCell::new([0usize; 2]));
    let p = pages.clone();
    scan_hook::set(move |pass, _| p.borrow_mut()[(pass == Pass::Messages) as usize] += 1);
    pages
}

// ── The original A-2 shape ────────────────────────────────────────────────────

/// A retained prefix of any length up to a full mailbox: the later message is
/// accepted once, every kept envelope stays on the relay byte for byte, and
/// nothing about Carol moved. `MAX_FETCH` and more used to hide it for good.
#[test]
fn a_retained_prefix_of_any_length_no_longer_hides_a_later_message() {
    let w = big_world();
    let mut prev_gen = w.bob.generation_with(&w.alice);
    let m = MAX_FETCH as usize;
    for k in [
        0,
        m - 1,
        m,
        m + 1,
        2 * m,
        3 * m + 7,
        DEFAULT_MAX_MAILBOX - 1,
    ] {
        let text = format!("after {k} kept envelopes");
        let later = w.alice_text(&format!("a{k}"), &text);
        let mut envs = w.carol_msgs[..k].to_vec();
        envs.push(later);
        let (r2, addr) = mailbox(&envs, &w.bob);
        let bob = w.bob_on(&addr);
        let pages = count_pages();
        let r = bob.sync();
        scan_hook::clear();
        assert!(r.errors.is_empty(), "k={k}: {:?}", r.errors);
        assert_eq!(
            (r.accepted, r.deferred, r.fetched),
            (1, k as u32, k as u32 + 1),
            "k={k}"
        );
        let [hs_pages, msg_pages] = *pages.borrow();
        assert!(
            hs_pages <= MAX_SCAN_PAGES && msg_pages <= MAX_SCAN_PAGES,
            "k={k}"
        );
        assert_eq!(
            stored(&r2, &bob),
            w.carol_msgs[..k],
            "k={k}: kept, in order"
        );
        assert!(bob.texts(&w.alice).contains(&text), "k={k}");
        // One acceptance and one receipt: the ratchet with Alice moved twice,
        // nothing else moved.
        assert_eq!(bob.generation_with(&w.alice), prev_gen + 2, "k={k}");
        prev_gen += 2;
        w.assert_nothing_from_carol(&bob);
        assert!(
            stored(&r2, &w.carol).is_empty(),
            "k={k}: no receipt to Carol"
        );
        // Exactly once: the next round finds only the kept envelopes.
        let again = bob.sync();
        assert_eq!((again.accepted, again.deferred), (0, k as u32), "k={k}");
        assert_eq!(stored(&r2, &bob), w.carol_msgs[..k]);
        for t in bob.net.received_texts(w.alice.pk.clone()).unwrap() {
            bob.net.mark_read(w.alice.pk.clone(), t.message_id).unwrap();
        }
        r2.stop();
    }
}

/// Kept and deleted envelopes interleaved over several pages: exactly the
/// processed ones leave the relay.
#[test]
fn kept_and_deleted_envelopes_mixed_across_pages() {
    let w = big_world();
    let stranger = [0x5Au8; 32];
    let mut envs = Vec::new();
    let mut want_kept = Vec::new();
    let mut texts = Vec::new();
    for (i, carol) in w.carol_msgs[..700].iter().enumerate() {
        envs.push(carol.clone());
        want_kept.push(carol.clone());
        if i % 97 == 0 {
            envs.push(format!("not an envelope {i}").into_bytes());
            envs.push(
                Envelope::Message {
                    sender: stranger,
                    wire: vec![i as u8; 64],
                }
                .encode(),
            );
        }
        if i % 250 == 3 {
            let t = format!("mixed {i}");
            envs.push(w.alice_text(&format!("mix{i}"), &t));
            texts.push(t);
        }
    }
    let (r2, addr) = mailbox(&envs, &w.bob);
    let bob = w.bob_on(&addr);
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.accepted as usize, texts.len());
    assert_eq!(r.deferred, 700);
    assert_eq!(r.dropped, 2 * 8, "8 garbage and 8 unknown-sender envelopes");
    assert_eq!(stored(&r2, &bob), want_kept);
    let got = bob.texts(&w.alice);
    assert!(texts.iter().all(|t| got.contains(t)), "{got:?}");
    for t in bob.net.received_texts(w.alice.pk.clone()).unwrap() {
        bob.net.mark_read(w.alice.pk.clone(), t.message_id).unwrap();
    }
    r2.stop();
}

// ── Handshakes behind a retained prefix ───────────────────────────────────────

/// Dave, a new contact of Bob, starts a session; returns his handshake and
/// his first message as published.
fn dave_starts(w: &World, byte: u8) -> (Device, Vec<u8>, Vec<u8>) {
    // Bob's current bundle on the production relay: earlier first contacts
    // consumed the one-time prekey it named.
    NetworkMessenger::new(w.bob.core.clone(), w.addr.clone(), 0, 2000)
        .publish_prekeys()
        .unwrap();
    let dave = Device::new(&w.addr, byte);
    dave.knows(&w.bob);
    w.bob.knows(&dave);
    dave.net.start_session(w.bob.pk.clone()).unwrap();
    dave.sync();
    let (mut hs, mut first) = (None, None);
    for (_, env) in take_all(&w.relay, &w.addr, &w.bob) {
        match Envelope::decode(&env) {
            Some(Envelope::Handshake { .. }) => hs = Some(env),
            Some(Envelope::Message { .. }) => first = Some(env),
            None => panic!("garbage"),
        }
    }
    (dave, hs.unwrap(), first.unwrap())
}

/// The handshake a message needs may lie anywhere behind a retained prefix,
/// before or after the message, on another page. One round records it and
/// then authenticates the message; nothing is deleted for lack of it.
#[test]
fn a_handshake_behind_a_retained_prefix_still_opens_its_session() {
    let w = big_world();
    let prefix = &w.carol_msgs[..300];
    type Order = fn(&[Vec<u8>], Vec<u8>, Vec<u8>) -> Vec<Vec<u8>>;
    let orders: [(&str, Order); 3] = [
        ("prefix, handshake, message", |p, h, m| {
            [p, &[h, m]].concat()
        }),
        ("prefix, message, handshake", |p, h, m| {
            [p, &[m, h]].concat()
        }),
        ("message, prefix, handshake", |p, h, m| {
            [&[m][..], p, &[h]].concat()
        }),
    ];
    for (i, (name, order)) in orders.into_iter().enumerate() {
        let (dave, hs, first) = dave_starts(&w, 20 + i as u8);
        let (r2, addr) = mailbox(&order(prefix, hs, first), &w.bob);
        let bob = w.bob_on(&addr);
        let r = bob.sync();
        assert!(r.errors.is_empty(), "{name}: {:?}", r.errors);
        assert_eq!(
            (r.sessions_accepted, r.accepted, r.deferred),
            (1, 1, 300),
            "{name}"
        );
        assert!(bob.core.has_session(handle_of(&dave)).unwrap(), "{name}");
        assert_eq!(stored(&r2, &bob), prefix, "{name}: only the prefix is left");
        w.assert_nothing_from_carol(&bob);
        r2.stop();
    }
}

/// Bob has recorded an earlier handshake from Dave's identity; Dave (on a new
/// device) sends a new one. The new handshake's first message comes a page
/// before the handshake itself. Taken page by page, that message would have
/// been tried against the older handshake, failed, and been deleted; here
/// the newer handshake is recorded first and the message authenticates.
#[test]
fn a_first_message_a_page_ahead_of_its_handshake_is_not_lost() {
    let w = big_world();
    let (dave, old_hs, _) = dave_starts(&w, 30);
    let (r_old, addr_old) = mailbox(&[old_hs], &w.bob);
    let r = w.bob_on(&addr_old).sync();
    assert!(r.errors.is_empty() && r.sessions_accepted == 0, "{r:?}");
    r_old.stop();
    // Dave's identity on a second, empty database: a genuine new handshake.
    NetworkMessenger::new(w.bob.core.clone(), w.addr.clone(), 0, 2000)
        .publish_prekeys()
        .unwrap();
    let path = tempdir().unwrap().keep().join("db");
    let path = path.to_str().unwrap().to_string();
    let second = ArciumCore::new(path.clone(), key32(31)).unwrap();
    second
        .save_identity(dave.core.load_identity().unwrap())
        .unwrap();
    drop(second);
    let dave2 = Device::reopen(&path, 31, &w.addr);
    dave2.knows(&w.bob);
    dave2.net.start_session(w.bob.pk.clone()).unwrap();
    dave2.sync();
    let (mut hs, mut first) = (None, None);
    for (_, env) in take_all(&w.relay, &w.addr, &w.bob) {
        match Envelope::decode(&env) {
            Some(Envelope::Handshake { .. }) => hs = Some(env),
            _ => first = Some(env),
        }
    }
    let prefix = &w.carol_msgs[..300];
    let envs = [&[first.unwrap()][..], prefix, &[hs.unwrap()]].concat();
    let (r2, addr) = mailbox(&envs, &w.bob);
    let bob = w.bob_on(&addr);
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(
        (r.sessions_accepted, r.accepted, r.dropped),
        (1, 1, 0),
        "{r:?}"
    );
    assert!(bob.core.has_session(handle_of(&dave)).unwrap());
    assert_eq!(stored(&r2, &bob), prefix);
    r2.stop();
}

/// Carol's handshake finally arrives, behind her own messages and a full page
/// more: one round opens her session and accepts every message once.
#[test]
fn a_late_handshake_releases_every_message_kept_for_it() {
    let w = world(400);
    let (r2, addr) = mailbox(&w.carol_msgs, &w.bob);
    let bob = w.bob_on(&addr);
    assert_eq!(bob.sync().deferred, 400);
    conn(&addr).send(key(&bob), w.carol_hs.clone()).unwrap();
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(
        (r.sessions_accepted, r.accepted, r.deferred),
        (1, 400, 0),
        "{r:?}"
    );
    assert!(stored(&r2, &bob).is_empty());
    assert_eq!(
        bob.texts(&w.carol).len(),
        399,
        "the OPEN message is not a text"
    );
    assert_eq!(bob.sync().accepted, 0, "once");
    r2.stop();
}

// ── The mailbox changing during a round ───────────────────────────────────────

#[test]
fn entries_deleted_or_appended_between_pages_neither_break_nor_repeat_a_round() {
    let w = big_world();
    let first = w.alice_text("d1", "on the last page");
    let appended = w.alice_text("d2", "appended during the round");
    let mut envs = w.carol_msgs[..600].to_vec();
    envs.push(first);
    let (r2, addr) = mailbox(&envs, &w.bob);
    let bob = w.bob_on(&addr);
    let victims: Vec<u64> = r2.stored(&key(&bob))[300..310]
        .iter()
        .map(|x| x.0)
        .collect();
    let (hook_addr, bob_key) = (addr.clone(), key(&bob));
    scan_hook::set(move |pass, page| {
        let mut c = conn(&hook_addr);
        if pass == Pass::Handshakes && page == 0 {
            c.delete(bob_key, victims.clone()).unwrap();
        }
        if pass == Pass::Messages && page == 0 {
            c.send(bob_key, appended.clone()).unwrap();
        }
    });
    let r = bob.sync();
    scan_hook::clear();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    // The deleted entries are skipped; the appended one lies past the end of
    // this round's scan and waits for the next.
    assert_eq!((r.accepted, r.deferred), (1, 590), "{r:?}");
    let r = bob.sync();
    assert_eq!((r.accepted, r.deferred), (1, 590), "{r:?}");
    assert_eq!(bob.sync().accepted, 0);
    r2.stop();
}

/// A relay (or a flood of senders) that keeps the mailbox non-empty cannot
/// make a round go on for ever: each pass stops after `MAX_SCAN_ENVELOPES`.
#[test]
fn a_mailbox_that_never_runs_dry_is_scanned_a_bounded_amount() {
    let w = big_world();
    let (r2, addr) = mailbox_with(
        &[],
        &w.bob,
        RelayConfig {
            max_mailbox: 100_000,
            ..RelayConfig::default()
        },
    );
    let bob = w.bob_on(&addr);
    let pages = Rc::new(RefCell::new([0usize; 2]));
    let (p, hook_addr, bob_key) = (pages.clone(), addr.clone(), key(&bob));
    let mut n = 0u32;
    // Full pages from the start, so no page is the relay's last.
    let mut c = conn(&addr);
    for _ in 0..MAX_FETCH {
        n += 1;
        c.send(bob_key, format!("junk {n}").into_bytes()).unwrap();
    }
    scan_hook::set(move |pass, _| {
        p.borrow_mut()[(pass == Pass::Messages) as usize] += 1;
        let mut c = conn(&hook_addr);
        for _ in 0..MAX_FETCH {
            n += 1;
            c.send(bob_key, format!("junk {n}").into_bytes()).unwrap();
        }
    });
    let r = bob.sync();
    scan_hook::clear();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    let [a, b] = *pages.borrow();
    let full = MAX_SCAN_ENVELOPES / MAX_FETCH as usize;
    assert_eq!(
        (a, b),
        (full, full),
        "each pass stops at its envelope budget"
    );
    assert_eq!(r.fetched as usize, MAX_SCAN_ENVELOPES);
    assert_eq!(
        r.dropped as usize, MAX_SCAN_ENVELOPES,
        "each junk entry once"
    );
    r2.stop();
}

/// The prefix expires while the round is between pages, and a new text
/// arrives meanwhile: the next page skips the expired entries and reaches it.
#[test]
fn entries_that_expire_during_a_round_are_skipped() {
    let w = big_world();
    let ttl = std::time::Duration::from_millis(1000);
    let (r2, addr) = mailbox_with(
        &w.carol_msgs[..300],
        &w.bob,
        RelayConfig {
            ttl,
            ..RelayConfig::default()
        },
    );
    let later = w.alice_text("e1", "outlives the prefix");
    let bob = w.bob_on(&addr);
    let (hook_addr, bob_key) = (addr.clone(), key(&bob));
    let mut later = Some(later);
    scan_hook::set(move |pass, page| {
        if pass == Pass::Handshakes && page == 0 {
            // Every prefix entry is older than the TTL once this returns; the
            // new text is not.
            std::thread::sleep(ttl + std::time::Duration::from_millis(200));
            conn(&hook_addr)
                .send(bob_key, later.take().unwrap())
                .unwrap();
        }
    });
    let r = bob.sync();
    scan_hook::clear();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.accepted, 1, "{r:?}");
    assert_eq!(r.fetched, 257, "the first page, then only the new text");
    assert!(bob
        .texts(&w.alice)
        .contains(&"outlives the prefix".to_string()));
    assert!(stored(&r2, &bob).is_empty());
    for t in bob.net.received_texts(w.alice.pk.clone()).unwrap() {
        bob.net.mark_read(w.alice.pk.clone(), t.message_id).unwrap();
    }
    r2.stop();
}

// ── Failures between pages ────────────────────────────────────────────────────

/// A FETCH_AFTER answer lost on the second page, a DELETE that never
/// arrives, and a relay that stops mid-scan: each round fails, the next one
/// completes, the later message is accepted once and the prefix stays.
#[test]
fn failures_between_pages_leave_the_next_round_safe() {
    let w = big_world();
    let prefix = &w.carol_msgs[..600];
    for step in ["fetch answer lost", "delete lost", "relay stopped"] {
        let text = format!("through: {step}");
        let later = w.alice_text(&format!("f{step}"), &text);
        let envs = [prefix, std::slice::from_ref(&later)].concat();
        let (r2, addr) = mailbox(&envs, &w.bob);
        let proxy = Proxy::start(&addr);
        let bob = w.bob_on(&proxy.addr);
        let before = bob.generation_with(&w.alice);
        let relay_cell = Rc::new(RefCell::new(Some(r2)));
        match step {
            "fetch answer lost" => {
                let armed = Rc::new(proxy);
                let a = armed.clone();
                scan_hook::set(move |pass, page| {
                    if pass == Pass::Handshakes && page == 0 {
                        a.arm(6, Cut::Response);
                    }
                });
                let r = bob.sync();
                scan_hook::clear();
                assert!(!r.errors.is_empty(), "{step}");
                assert_eq!(
                    r.accepted, 0,
                    "{step}: nothing processed before the failure"
                );
                let bob = w.bob_on(&armed.addr);
                check_recovers(&w, &bob, &relay_cell, prefix, &text, before, step);
            }
            "delete lost" => {
                proxy.arm(5, Cut::Request);
                let r = bob.sync();
                assert!(!r.errors.is_empty(), "{step}");
                assert_eq!(r.accepted, 1, "{step}: accepted and committed");
                let bob = w.bob_on(&proxy.addr);
                check_recovers(&w, &bob, &relay_cell, prefix, &text, before, step);
            }
            _ => {
                let rc = relay_cell.clone();
                scan_hook::set(move |pass, page| {
                    if pass == Pass::Handshakes && page == 0 {
                        rc.borrow_mut().take().unwrap().stop();
                    }
                });
                let r = bob.sync();
                scan_hook::clear();
                assert!(!r.errors.is_empty(), "{step}");
                assert_eq!(r.accepted, 0, "{step}");
                // The relay comes back empty; the sender retransmits.
                let (r3, addr3) = mailbox(&envs, &w.bob);
                *relay_cell.borrow_mut() = Some(r3);
                let bob = w.bob_on(&addr3);
                check_recovers(&w, &bob, &relay_cell, prefix, &text, before, step);
            }
        }
        let last = relay_cell.borrow_mut().take();
        if let Some(r) = last {
            r.stop();
        }
    }
}

fn check_recovers(
    w: &World,
    bob: &Device,
    relay: &Rc<RefCell<Option<RelayHandle>>>,
    prefix: &[Vec<u8>],
    text: &str,
    before: u64,
    step: &str,
) {
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{step}: {:?}", r.errors);
    assert_eq!(r.deferred as usize, prefix.len(), "{step}");
    let relay = relay.borrow();
    assert_eq!(stored(relay.as_ref().unwrap(), bob), prefix, "{step}");
    let got: Vec<_> = bob
        .texts(&w.alice)
        .into_iter()
        .filter(|t| t == text)
        .collect();
    assert_eq!(got.len(), 1, "{step}: shown once");
    // Accepted once, one receipt; a repeat is a duplicate and moves nothing
    // but a receipt.
    let gen = bob.generation_with(&w.alice);
    assert!(
        gen == before + 2 || gen == before + 3,
        "{step}: {before} -> {gen}"
    );
    assert_eq!(bob.sync().accepted, 0, "{step}");
    for t in bob.net.received_texts(w.alice.pk.clone()).unwrap() {
        bob.net.mark_read(w.alice.pk.clone(), t.message_id).unwrap();
    }
}

/// The same starvation counted in bytes: kept texts of the largest size a chat
/// allows fill more than one frame long before `MAX_FETCH` entries. The relay
/// pages them by size, so the later message is still reached.
#[test]
fn a_retained_prefix_of_large_texts_no_longer_hides_a_later_message() {
    let w = world_with(
        100,
        &"x".repeat(crate::network::chat::MAX_TEXT_LEN - CANARY.len()),
    );
    let size: usize = w.carol_msgs.iter().map(|e| 12 + e.len()).sum();
    assert!(
        size > relay::protocol::MAX_FRAME,
        "the prefix needs several frames"
    );
    let text = "after large kept envelopes";
    let later = w.alice_text("big", text);
    let envs = [&w.carol_msgs[..], &[later]].concat();
    let (r2, addr) = mailbox(&envs, &w.bob);
    let bob = w.bob_on(&addr);
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.accepted, r.deferred), (1, 100));
    assert_eq!(stored(&r2, &bob), w.carol_msgs, "kept, in order");
    assert!(bob.texts(&w.alice).contains(&text.to_string()));
    w.assert_nothing_from_carol(&bob);
    r2.stop();
    w.relay.stop();
}

// ── A process death between pages ─────────────────────────────────────────────

/// Bob's process dies right after the first page of the message pass: one
/// text accepted and committed, nothing deleted yet, the second text not
/// reached. The restarted device shows each text once and keeps the prefix.
#[cfg(unix)]
#[test]
fn a_device_killed_between_pages_shows_each_message_once() {
    let w = big_world();
    let first = w.alice_text("k1", "on the first page");
    let second = w.alice_text("k2", "behind the prefix");
    let prefix = &w.carol_msgs[..300];
    let envs = [&[first][..], prefix, &[second][..]].concat();
    let (r2, addr) = mailbox(&envs, &w.bob);
    let before = w.bob.generation_with(&w.alice);
    super::network_crash::run_child(&w.bob, &addr, "sync", Some("after_page"), &w.alice.pk);

    let bob = w.bob_on(&addr);
    assert_eq!(
        bob.generation_with(&w.alice),
        before + 2,
        "the first text and its receipt were committed before the death, nothing else"
    );
    assert_eq!(stored(&r2, &bob).len(), envs.len(), "nothing was deleted");
    let r = bob.sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.accepted, r.deferred), (1, 300), "only the second is new");
    assert_eq!(stored(&r2, &bob), prefix, "the prefix stays, in order");
    let texts = bob.texts(&w.alice);
    for t in ["on the first page", "behind the prefix"] {
        assert_eq!(
            texts.iter().filter(|x| *x == t).count(),
            1,
            "{t}: shown once"
        );
    }
    assert!(!stored(&r2, &w.alice).is_empty(), "receipts go out");
    assert_eq!(bob.sync().accepted, 0);
    w.assert_nothing_from_carol(&bob);
    for t in bob.net.received_texts(w.alice.pk.clone()).unwrap() {
        bob.net.mark_read(w.alice.pk.clone(), t.message_id).unwrap();
    }
    r2.stop();
}

// ── A relay that misbehaves ───────────────────────────────────────────────────

/// A local stand-in for a relay that misbehaves while paging: it answers every
/// FETCH_AFTER with `page(after)` and every other request with success.
/// Returns its address and the number of FETCH_AFTER requests it answered.
fn fake_relay(
    page: impl Fn(u64) -> Vec<(u64, Vec<u8>)> + Send + 'static,
) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use relay::protocol::{read_frame, write_frame, Request, Response};
    use std::sync::atomic::Ordering;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let fetches = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let f = fetches.clone();
    std::thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { return };
            let _ = s.set_nodelay(true);
            while let Ok(Some(body)) = read_frame(&mut s) {
                let response = match Request::decode(&body) {
                    Ok(Request::FetchAfter { after, .. }) => {
                        f.fetch_add(1, Ordering::SeqCst);
                        Response::Items(page(after))
                    }
                    Ok(Request::Send { .. }) => Response::Accepted { seq: 1 },
                    Ok(Request::GetBundle { .. }) => Response::NotFound,
                    _ => Response::Ok,
                };
                if write_frame(&mut s, &response.encode()).is_err() {
                    break;
                }
            }
        }
    });
    (addr, fetches)
}

fn junk(from: u64, n: u64) -> Vec<(u64, Vec<u8>)> {
    (from..from + n).map(|s| (s, b"junk".to_vec())).collect()
}

/// Pages that never end, each just long enough to promise more: a round still
/// makes at most `2 * MAX_SCAN_PAGES` requests and considers at most
/// `MAX_SCAN_ENVELOPES` envelopes a pass.
#[test]
fn endless_minimal_pages_are_read_a_bounded_amount() {
    let w = big_world();
    let (addr, fetches) = fake_relay(|after| junk(after + 1, MIN_PAGE as u64));
    let r = w.bob_on(&addr).sync();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(
        fetches.load(std::sync::atomic::Ordering::SeqCst),
        2 * MAX_SCAN_PAGES
    );
    assert_eq!(r.fetched as usize, MAX_SCAN_ENVELOPES);
    assert_eq!(r.dropped as usize, MAX_SCAN_ENVELOPES);
}

/// A relay that pages backwards, or returns more than asked for, ends the
/// round with an error at once: the cursor cannot be made to loop.
#[test]
fn a_relay_that_breaks_paging_ends_the_round() {
    let w = big_world();
    type Page = fn(u64) -> Vec<(u64, Vec<u8>)>;
    let cases: [(&str, Page, usize); 3] = [
        ("out of order", |_| junk(1, MIN_PAGE as u64), 2),
        (
            "out of order",
            |_| vec![(5, b"junk".to_vec()), (5, b"junk".to_vec())],
            1,
        ),
        (
            "more envelopes than asked",
            |_| junk(1, MAX_FETCH as u64 + 1),
            1,
        ),
    ];
    for (want, page, n) in cases {
        let (addr, fetches) = fake_relay(page);
        let r = w.bob_on(&addr).sync();
        assert_eq!(r.errors.len(), 1, "{want}");
        assert!(r.errors[0].contains(want), "{want}: {:?}", r.errors);
        assert_eq!(
            fetches.load(std::sync::atomic::Ordering::SeqCst),
            n,
            "{want}"
        );
        assert_eq!((r.accepted, r.dropped), (0, 0), "{want}: nothing deleted");
    }
}
