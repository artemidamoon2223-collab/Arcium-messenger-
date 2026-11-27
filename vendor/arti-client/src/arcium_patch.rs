//! Arcium Messenger patch: a protocol shutdown does not end the process.
//!
//! Not part of upstream arti-client 0.48.0. Why and how to remove it:
//! `vendor/README.md` in the Arcium Messenger repository.
//!
//! When a consensus newer than this software lists as required for clients a
//! protocol this arti does not implement ([`crate::protostatus`]), upstream
//! ends the whole process with `std::process::exit(1)` (TODO #1932). An app
//! that embeds arti must not close for that. Instead, the shutdown is recorded
//! here, and whoever owns the [`TorClient`](crate::TorClient) stops Tor by
//! dropping it: [`protocol_shutdown`] tells it when.
//!
//! The record is per process, not per client: the condition is about this
//! software's version, which every client in the process shares. It is never
//! cleared. The check of the cached consensus at bootstrap is unchanged: it
//! still fails the bootstrap, with an error of kind
//! [`ErrorKind::SoftwareDeprecated`](crate::ErrorKind::SoftwareDeprecated),
//! and records nothing here.

use std::future::Future;
use std::sync::{Mutex, MutexGuard, PoisonError};

use futures::channel::oneshot;
use tor_error::ErrorReport as _;
use tracing::error;

use crate::err::ErrorDetail;

/// Whether a protocol shutdown was recorded, and who waits for one.
struct Record {
    /// Set once, never cleared.
    happened: bool,
    /// Woken, and emptied, when `happened` is set. A waiter whose future was
    /// dropped is removed when the next one comes.
    waiters: Vec<oneshot::Sender<()>>,
}

/// This process's record.
static RECORD: Mutex<Record> = Mutex::new(Record {
    happened: false,
    waiters: Vec::new(),
});

/// The record, also after a panic in another thread that held it.
fn record() -> MutexGuard<'static, Record> {
    RECORD.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Whether this process has had a protocol shutdown: the Tor network required
/// a protocol this arti does not implement. Once true, it stays true; only a
/// newer version of the software helps.
pub fn protocol_shutdown_happened() -> bool {
    record().happened
}

/// A future that finishes once this process has had a protocol shutdown; at
/// once if it already has. A client's owner waits for it, then drops every
/// [`TorClient`](crate::TorClient) it holds: that is what stops Tor.
pub fn protocol_shutdown() -> impl Future<Output = ()> + Send + 'static {
    let waiting = {
        let mut record = record();
        if record.happened {
            None
        } else {
            record.waiters.retain(|waiter| !waiter.is_canceled());
            let (tx, rx) = oneshot::channel();
            record.waiters.push(tx);
            Some(rx)
        }
    };
    async move {
        if let Some(rx) = waiting {
            // The sender is never dropped unsent: it is kept until it sends.
            let _ = rx.await;
        }
    }
}

/// What a running client does on a protocol shutdown, in place of upstream's
/// `std::process::exit(1)`: log it, record it, and wake whoever waits for it.
pub(crate) async fn on_protocol_shutdown(fatal: ErrorDetail) {
    // protostatus already logged the missing protocols.
    error!(
        "Stopping Tor because of unsupported software version. Error was: {}",
        fatal.report(),
    );
    if let Some(hint) = crate::err::Error::from(fatal).hint() {
        error!("{}", hint);
    }
    let waiters = {
        let mut record = record();
        record.happened = true;
        std::mem::take(&mut record.waiters)
    };
    for waiter in waiters {
        let _ = waiter.send(());
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use futures::FutureExt as _;
    use tor_netdoc::doc::netstatus::ProtoStatuses;

    use super::*;

    /// One test, since the record is per process and never cleared. The
    /// shutdown comes from the same check as in a running client: a required
    /// protocol this software lacks. That the test finishes at all is the
    /// check that nothing ends the process.
    #[test]
    fn a_protocol_shutdown_is_recorded_and_wakes_its_waiters() {
        let rec: ProtoStatuses = serde_json::from_str(
            r#"{
                "client": { "recommended" : "Relay=1-5", "required" : "Relay=3" },
                "relay": { "recommended": "", "required" : ""}
            }"#,
        )
        .unwrap();
        let rec_date = humantime::parse_rfc3339("2025-03-08T10:16:00Z").unwrap();
        let fatal = crate::protostatus::evaluate_protocol_status(
            rec_date,
            &rec,
            &"Relay=1".parse().unwrap(),
        )
        .unwrap_err();

        assert!(!protocol_shutdown_happened());
        drop(protocol_shutdown());
        let mut early = Box::pin(protocol_shutdown());
        assert!(early.as_mut().now_or_never().is_none(), "finished before any shutdown");
        assert_eq!(record().waiters.len(), 1, "a dropped waiter was kept");

        on_protocol_shutdown(fatal).now_or_never().unwrap();

        assert!(protocol_shutdown_happened());
        assert!(early.now_or_never().is_some(), "a waiter from before was not woken");
        assert!(
            protocol_shutdown().now_or_never().is_some(),
            "a waiter from after did not finish at once"
        );
    }
}
