//! Untrusted store-and-forward relay for Arcium Messenger. Specification:
//! `docs/NET-MESSAGING.md`.

pub mod client;
mod disk;
pub mod protocol;
pub mod server;

#[cfg(test)]
mod tests {
    use super::client::Connection;
    use super::protocol::*;
    use super::server::{serve, RelayConfig};
    use std::net::TcpListener;
    use std::time::Duration;

    fn start(config: RelayConfig) -> super::server::RelayHandle {
        serve(TcpListener::bind("127.0.0.1:0").unwrap(), config).unwrap()
    }

    fn conn(h: &super::server::RelayHandle) -> Connection {
        Connection::connect(&h.addr().to_string(), Duration::from_secs(5)).unwrap()
    }

    #[test]
    fn mailboxes_store_until_deleted_and_dedup_identical_envelopes() {
        let relay = start(RelayConfig::default());
        let mut c = conn(&relay);
        let bob = [2u8; 32];
        let s1 = c.send(bob, b"one".to_vec()).unwrap();
        let s2 = c.send(bob, b"two".to_vec()).unwrap();
        assert_eq!(c.send(bob, b"one".to_vec()).unwrap(), s1);
        assert!(s2 > s1);
        let items = c.fetch(bob, 10).unwrap();
        assert_eq!(items, vec![(s1, b"one".to_vec()), (s2, b"two".to_vec())]);
        c.delete(bob, vec![s1, 999]).unwrap();
        assert_eq!(c.fetch(bob, 10).unwrap(), vec![(s2, b"two".to_vec())]);
        assert!(c.fetch([3; 32], 10).unwrap().is_empty());
        relay.stop();
    }

    #[test]
    fn bundles_limits_and_full_mailboxes() {
        let relay = start(RelayConfig {
            max_mailbox: 2,
            ..RelayConfig::default()
        });
        let mut c = conn(&relay);
        assert_eq!(c.get_bundle([1; 32]).unwrap(), None);
        c.put_bundle([1; 32], vec![5; 204]).unwrap();
        assert_eq!(c.get_bundle([1; 32]).unwrap(), Some(vec![5; 204]));
        assert!(c.put_bundle([1; 32], vec![0; MAX_BUNDLE + 1]).is_err());
        assert!(c.send([2; 32], vec![0; MAX_ENVELOPE + 1]).is_err());
        c.send([2; 32], vec![1]).unwrap();
        c.send([2; 32], vec![2]).unwrap();
        assert!(matches!(
            c.send([2; 32], vec![3]),
            Err(super::client::ClientError::Refused(ErrorCode::Full))
        ));
        relay.stop();
    }

    #[test]
    fn expired_envelopes_are_not_returned() {
        let relay = start(RelayConfig {
            ttl: Duration::from_millis(50),
            ..RelayConfig::default()
        });
        let mut c = conn(&relay);
        c.send([2; 32], vec![1]).unwrap();
        std::thread::sleep(Duration::from_millis(80));
        assert!(c.fetch([2; 32], 10).unwrap().is_empty());
        relay.stop();
    }

    #[test]
    fn a_malformed_request_is_refused_and_the_relay_keeps_serving() {
        let relay = start(RelayConfig::default());
        let mut raw = std::net::TcpStream::connect(relay.addr()).unwrap();
        write_frame(&mut raw, &[9, 9, 9]).unwrap();
        let body = read_frame(&mut raw).unwrap().unwrap();
        assert_eq!(body, vec![2]);
        let mut c = conn(&relay);
        assert!(c.fetch([0; 32], 1).unwrap().is_empty());
        relay.stop();
    }

    #[test]
    fn a_stopped_relay_is_unreachable_and_a_restart_starts_empty() {
        let relay = start(RelayConfig::default());
        let addr = relay.addr();
        conn(&relay).send([2; 32], vec![1]).unwrap();
        relay.stop();
        assert!(
            Connection::connect(&addr.to_string(), Duration::from_millis(500))
                .and_then(|mut c| c.fetch([2; 32], 1))
                .is_err()
        );
        let again = serve(TcpListener::bind(addr).unwrap(), RelayConfig::default()).unwrap();
        assert!(conn(&again).fetch([2; 32], 10).unwrap().is_empty());
        again.stop();
    }

    /// With a database file, what the relay accepted survives a restart:
    /// envelopes not deleted, deletions, bundles and the sequence counter.
    /// Duplicate detection works on the loaded envelopes too.
    #[test]
    fn a_relay_with_a_database_keeps_mailboxes_and_bundles_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let config = RelayConfig {
            db: Some(dir.path().join("relay.db")),
            ..RelayConfig::default()
        };
        let bob = [2u8; 32];
        let relay = start(config.clone());
        let mut c = conn(&relay);
        let s1 = c.send(bob, b"one".to_vec()).unwrap();
        let s2 = c.send(bob, b"two".to_vec()).unwrap();
        c.put_bundle([1; 32], vec![5; 204]).unwrap();
        c.put_bundle([1; 32], vec![6; 204]).unwrap();
        c.delete(bob, vec![s1]).unwrap();
        relay.stop();

        let again = start(config.clone());
        let mut c = conn(&again);
        assert_eq!(c.fetch(bob, 10).unwrap(), vec![(s2, b"two".to_vec())]);
        assert_eq!(c.get_bundle([1; 32]).unwrap(), Some(vec![6; 204]));
        assert_eq!(c.send(bob, b"two".to_vec()).unwrap(), s2, "duplicate of a loaded envelope");
        let s3 = c.send(bob, b"three".to_vec()).unwrap();
        assert!(s3 > s2, "the counter continues after a restart");
        again.stop();

        let third = start(config);
        assert_eq!(
            conn(&third).fetch(bob, 10).unwrap(),
            vec![(s2, b"two".to_vec()), (s3, b"three".to_vec())]
        );
        third.stop();
    }

    /// An envelope that expires while the relay runs is deleted from the
    /// file too: a restart with a longer TTL does not bring it back.
    #[test]
    fn an_envelope_that_expires_while_running_leaves_the_database() {
        let dir = tempfile::tempdir().unwrap();
        let db = Some(dir.path().join("relay.db"));
        let relay = start(RelayConfig {
            ttl: Duration::from_millis(100),
            db: db.clone(),
            ..RelayConfig::default()
        });
        let mut c = conn(&relay);
        c.send([2; 32], vec![1]).unwrap();
        std::thread::sleep(Duration::from_millis(150));
        assert!(c.fetch([2; 32], 10).unwrap().is_empty(), "expired in memory");
        relay.stop();
        let again = start(RelayConfig {
            db,
            ..RelayConfig::default()
        });
        assert!(again.stored(&[2; 32]).is_empty(), "and deleted from the file");
        again.stop();
    }

    /// A total-size cap smaller than one envelope is refused at start.
    #[test]
    fn a_total_size_cap_below_one_envelope_is_refused() {
        let err = serve(
            TcpListener::bind("127.0.0.1:0").unwrap(),
            RelayConfig {
                max_total_bytes: MAX_ENVELOPE - 1,
                ..RelayConfig::default()
            },
        )
        .err()
        .expect("refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    /// An envelope older than the TTL is not loaded after a restart.
    #[test]
    fn a_restarted_relay_does_not_load_expired_envelopes() {
        let dir = tempfile::tempdir().unwrap();
        let config = RelayConfig {
            ttl: Duration::from_millis(100),
            db: Some(dir.path().join("relay.db")),
            ..RelayConfig::default()
        };
        let relay = start(config.clone());
        conn(&relay).send([2; 32], vec![1]).unwrap();
        relay.stop();
        std::thread::sleep(Duration::from_millis(150));
        let again = start(config);
        assert!(again.stored(&[2; 32]).is_empty());
        assert!(conn(&again).fetch([2; 32], 10).unwrap().is_empty());
        again.stop();
    }

    /// Paging with FETCH_AFTER reaches every envelope of a full mailbox
    /// while all of them stay stored, and each page starts after the cursor
    /// whatever was deleted or appended in between.
    #[test]
    fn fetch_after_pages_through_a_mailbox_without_removing_anything() {
        let relay = start(RelayConfig::default());
        let mut c = conn(&relay);
        let bob = [2u8; 32];
        let n = DEFAULT_MAX_MAILBOX;
        let seqs: Vec<u64> = (0..n)
            .map(|i| c.send(bob, (i as u32).to_be_bytes().to_vec()).unwrap())
            .collect();
        // The old FETCH only ever sees the first page.
        assert_eq!(c.fetch(bob, u16::MAX).unwrap().len(), MAX_FETCH as usize);
        let mut after = 0;
        let mut seen = Vec::new();
        loop {
            let page = c.fetch_after(bob, after, u16::MAX).unwrap();
            if page.is_empty() {
                break;
            }
            assert!(page.len() <= MAX_FETCH as usize);
            assert!(page.iter().all(|(s, _)| *s > after));
            assert!(page.windows(2).all(|w| w[0].0 < w[1].0));
            after = page.last().unwrap().0;
            seen.extend(page.into_iter().map(|(s, _)| s));
        }
        assert_eq!(seen, seqs);
        assert_eq!(relay.stored(&bob).len(), n, "reading removed nothing");
        assert!(c.fetch_after(bob, u64::MAX, 10).unwrap().is_empty());
        relay.stop();
    }

    #[test]
    fn fetch_after_skips_deleted_entries_and_sees_appended_ones() {
        let relay = start(RelayConfig::default());
        let mut c = conn(&relay);
        let bob = [2u8; 32];
        let s: Vec<u64> = (0..5u8).map(|i| c.send(bob, vec![i]).unwrap()).collect();
        let first = c.fetch_after(bob, 0, 2).unwrap();
        assert_eq!(first.iter().map(|x| x.0).collect::<Vec<_>>(), &s[..2]);
        // Between pages: the next entry is deleted, one is appended.
        c.delete(bob, vec![s[2]]).unwrap();
        let late = c.send(bob, vec![9]).unwrap();
        let rest = c.fetch_after(bob, first[1].0, 10).unwrap();
        assert_eq!(
            rest.iter().map(|x| x.0).collect::<Vec<_>>(),
            vec![s[3], s[4], late]
        );
        // A duplicate SEND still names the stored entry, not a new position.
        assert_eq!(c.send(bob, vec![0]).unwrap(), s[0]);
        assert!(c.fetch_after(bob, late, 10).unwrap().is_empty());
        relay.stop();
    }

    #[test]
    fn fetch_after_does_not_return_expired_entries() {
        let relay = start(RelayConfig {
            ttl: Duration::from_millis(100),
            ..RelayConfig::default()
        });
        let mut c = conn(&relay);
        let a = c.send([2; 32], vec![1]).unwrap();
        assert_eq!(c.fetch_after([2; 32], 0, 10).unwrap().len(), 1);
        std::thread::sleep(Duration::from_millis(150));
        let b = c.send([2; 32], vec![2]).unwrap();
        assert_eq!(c.fetch_after([2; 32], 0, 10).unwrap(), vec![(b, vec![2])]);
        assert!(b > a);
        relay.stop();
    }

    /// A page holds at most what fits in one frame: a mailbox of the largest
    /// envelopes is read in pages of at least `MIN_PAGE`, and both FETCH and
    /// FETCH_AFTER keep answering instead of failing on an oversized response.
    #[test]
    fn a_page_of_large_envelopes_fits_in_one_frame() {
        let relay = start(RelayConfig::default());
        let mut c = conn(&relay);
        let n = 3 * MIN_PAGE + 2;
        let seqs: Vec<u64> = (0..n)
            .map(|i| {
                let mut e = vec![0u8; MAX_ENVELOPE];
                e[..8].copy_from_slice(&(i as u64).to_be_bytes());
                c.send([2; 32], e).unwrap()
            })
            .collect();
        assert_eq!(c.fetch([2; 32], MAX_FETCH).unwrap().len(), MIN_PAGE);
        let (mut after, mut seen, mut pages) = (0, Vec::new(), 0);
        loop {
            let page = c.fetch_after([2; 32], after, MAX_FETCH).unwrap();
            if page.is_empty() {
                break;
            }
            assert!(page.len() >= MIN_PAGE.min(n - seen.len()));
            after = page.last().unwrap().0;
            seen.extend(page.into_iter().map(|(s, _)| s));
            pages += 1;
        }
        assert_eq!(seen, seqs);
        assert_eq!(pages, n.div_ceil(MIN_PAGE));
        relay.stop();
    }

    /// A mailbox holds 1 to `DEFAULT_MAX_MAILBOX` envelopes, the most a
    /// reader's scan covers in one round. Any other capacity is refused as
    /// invalid input before anything starts; nothing is clamped.
    #[test]
    fn a_mailbox_capacity_outside_the_supported_range_is_refused() {
        for ok in [DEFAULT_MAX_MAILBOX, 100, 1] {
            let relay = start(RelayConfig {
                max_mailbox: ok,
                ..RelayConfig::default()
            });
            assert!(conn(&relay).fetch([2; 32], 1).unwrap().is_empty(), "{ok}");
            relay.stop();
        }
        for bad in [0, DEFAULT_MAX_MAILBOX + 1, 100_000, usize::MAX] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let config = RelayConfig {
                max_mailbox: bad,
                ..RelayConfig::default()
            };
            let Err(e) = serve(listener, config) else {
                panic!("max_mailbox {bad} was accepted");
            };
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{bad}");
            assert!(e.to_string().contains(&bad.to_string()), "{e}");
            // Nothing was started: the listener is gone with the refusal.
            assert!(
                std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_err(),
                "{bad}: something is listening"
            );
        }
    }

    /// The largest supported mailbox fills as before: 4096 envelopes are
    /// stored, the next one is refused with FULL, and a repeat of a stored one
    /// still names it.
    #[test]
    fn a_mailbox_of_the_largest_supported_capacity_refuses_the_next_envelope() {
        let relay = start(RelayConfig::default());
        let mut c = conn(&relay);
        let first = c.send([2; 32], 0u32.to_be_bytes().to_vec()).unwrap();
        for i in 1..DEFAULT_MAX_MAILBOX as u32 {
            c.send([2; 32], i.to_be_bytes().to_vec()).unwrap();
        }
        assert!(matches!(
            c.send([2; 32], vec![0xff; 5]),
            Err(super::client::ClientError::Refused(ErrorCode::Full))
        ));
        assert_eq!(relay.stored(&[2; 32]).len(), DEFAULT_MAX_MAILBOX);
        assert_eq!(c.send([2; 32], 0u32.to_be_bytes().to_vec()).unwrap(), first);
        relay.stop();
    }

    /// A relay that predates FETCH_AFTER answers it as it answers any
    /// operation it does not know: BAD_REQUEST, and the client reports that.
    #[test]
    fn a_relay_without_fetch_after_refuses_it_explicitly() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let old = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let body = read_frame(&mut s).unwrap().unwrap();
            assert_eq!(body[0], 6);
            // What the relay before FETCH_AFTER does with op 6.
            write_frame(&mut s, &Response::Error(ErrorCode::BadRequest).encode()).unwrap();
        });
        let mut c = Connection::connect(&addr.to_string(), Duration::from_secs(5)).unwrap();
        assert!(matches!(
            c.fetch_after([2; 32], 0, 10),
            Err(super::client::ClientError::Refused(ErrorCode::BadRequest))
        ));
        old.join().unwrap();
    }

    /// Waits up to 2 s for the relay to track exactly `n` open connections.
    fn wait_for_connections(relay: &super::server::RelayHandle, n: usize) -> usize {
        let started = std::time::Instant::now();
        while relay.open_connections() != n && started.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(5));
        }
        relay.open_connections()
    }

    /// Every connection kept a clone of its socket, and with it a file
    /// descriptor, until the relay stopped: 600 short connections left 600
    /// descriptors open, and a relay at its descriptor limit stopped
    /// answering concurrent clients. A closed connection now releases it.
    #[test]
    fn a_closed_connection_releases_its_descriptor() {
        let relay = start(RelayConfig::default());
        for i in 0..300u32 {
            let mut c = conn(&relay);
            c.send([2; 32], i.to_be_bytes().to_vec()).unwrap();
        }
        assert_eq!(wait_for_connections(&relay, 0), 0, "every closed connection released");

        // Open connections are still tracked, so `stop` can close them.
        let mut held: Vec<_> = (0..3).map(|_| conn(&relay)).collect();
        for c in &mut held {
            c.get_bundle([1; 32]).unwrap();
        }
        assert_eq!(wait_for_connections(&relay, 3), 3);
        drop(held.pop());
        assert_eq!(wait_for_connections(&relay, 2), 2);
        relay.stop();
        for mut c in held {
            assert!(c.get_bundle([1; 32]).is_err(), "stop closed the open connections");
        }
    }

    #[test]
    fn the_canary_is_detected() {
        let relay = start(RelayConfig {
            canary: Some(b"SECRET".to_vec()),
            ..RelayConfig::default()
        });
        let mut c = conn(&relay);
        c.send([2; 32], b"xxSECRETxx".to_vec()).unwrap();
        c.send([2; 32], b"ciphertext".to_vec()).unwrap();
        assert_eq!(relay.canary_hits(), 1);
        relay.stop();
    }
}
