//! Untrusted store-and-forward relay for Arcium Messenger. Specification:
//! `docs/NET-MESSAGING.md`.

pub mod client;
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
