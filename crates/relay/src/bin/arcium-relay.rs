//! `arcium-relay --listen HOST:PORT [--db FILE] [--log] [--canary TEXT] [--ttl-secs N] [--max-mailbox N] [--max-total-bytes N]`
//!
//! `--max-mailbox` is 1 to 4096 (`DEFAULT_MAX_MAILBOX`, the default); any
//! other value is refused. `--db FILE` keeps mailboxes and bundles in that
//! SQLite file across restarts (created if missing); without it nothing is
//! persisted. `--max-total-bytes N` caps the envelope bytes of all mailboxes
//! together (default 1 GiB, at least 65536).
//!
//! Runs the untrusted store-and-forward relay until killed. Not for
//! production yet: no TLS and no authentication (docs/NET-MESSAGING.md,
//! section 1).

use std::net::TcpListener;
use std::time::Duration;

use relay::protocol::DEFAULT_MAX_MAILBOX;
use relay::server::{serve, RelayConfig};

fn main() {
    let mut listen = "127.0.0.1:7700".to_string();
    let mut config = RelayConfig::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| usage(&arg));
        match arg.as_str() {
            "--listen" => listen = value(),
            "--db" => config.db = Some(value().into()),
            "--log" => config.log = true,
            "--canary" => config.canary = Some(value().into_bytes()),
            "--ttl-secs" => {
                config.ttl =
                    Duration::from_secs(value().parse().unwrap_or_else(|_| usage("--ttl-secs")))
            }
            "--max-mailbox" => {
                config.max_mailbox = value().parse().unwrap_or_else(|_| usage("--max-mailbox"))
            }
            "--max-total-bytes" => {
                config.max_total_bytes =
                    value().parse().unwrap_or_else(|_| usage("--max-total-bytes"))
            }
            other => usage(other),
        }
    }
    let listener = TcpListener::bind(&listen).unwrap_or_else(|e| {
        eprintln!("arcium-relay: cannot listen on {listen}: {e}");
        std::process::exit(1);
    });
    let handle = serve(listener, config).unwrap_or_else(|e| {
        eprintln!("arcium-relay: {e}");
        std::process::exit(2);
    });
    eprintln!("arcium-relay: listening on {}", handle.addr());
    loop {
        std::thread::park();
    }
}

fn usage(bad: &str) -> ! {
    eprintln!(
        "arcium-relay: bad argument {bad}\n\
         usage: arcium-relay --listen HOST:PORT [--db FILE] [--log] [--canary TEXT] [--ttl-secs N] [--max-mailbox N] [--max-total-bytes N]\n\
         --db FILE        keep mailboxes and bundles in this SQLite file across restarts\n\
         --max-mailbox N  envelopes per mailbox, 1 to {DEFAULT_MAX_MAILBOX} (default {DEFAULT_MAX_MAILBOX})\n\
         --max-total-bytes N  envelope bytes in all mailboxes together (default 1 GiB)"
    );
    std::process::exit(2);
}
