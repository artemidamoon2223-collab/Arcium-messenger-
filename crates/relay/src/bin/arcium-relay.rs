//! `arcium-relay keygen --out FILE --address HOST:PORT`
//!
//! `arcium-relay --listen HOST:PORT [--keys FILE] [--db FILE] [--log] [--canary TEXT] [--ttl-secs N] [--max-mailbox N] [--max-total-bytes N] [--max-connections N] [--max-connections-per-address N]`
//!
//! `keygen` makes the relay's keys (an Ed25519 TLS key and an X25519 auth
//! key), writes both secrets to a new FILE readable by its owner only (mode
//! 0600; an existing file is never overwritten), and prints the connection
//! string clients use to reach the relay at HOST:PORT, its public address
//! (`relay::address`).
//!
//! `--keys FILE` serves `RELAY_PROTOCOL_V2` on `--listen` with the keys in
//! FILE: TLS 1.3 with the pinned key, and mailboxes only for their
//! authenticated owners. Without it, `RELAY_PROTOCOL_V1`: no TLS and no
//! authentication, for development builds and tests only (release builds of
//! the app accept only V2).
//!
//! `--max-mailbox` is 1 to 4096 (`DEFAULT_MAX_MAILBOX`, the default); any
//! other value is refused. `--db FILE` keeps mailboxes and bundles in that
//! SQLite file across restarts (created if missing); without it nothing is
//! persisted. `--max-connections N` (default 1024) and
//! `--max-connections-per-address N` (default 32) cap open connections; one
//! beyond either is closed at once. `--max-total-bytes N` caps the envelope bytes of all mailboxes
//! together (default 1 GiB, at least 65536).
//!
//! Runs the untrusted store-and-forward relay until killed. Not for
//! production yet (docs/NET-MESSAGING.md, section 1).

use std::net::TcpListener;
use std::path::PathBuf;
use std::time::Duration;

use relay::address::RelayAddress;
use relay::auth::RelayKeys;
use relay::protocol::DEFAULT_MAX_MAILBOX;
use relay::server::{serve, serve_v2, RelayConfig};

fn main() {
    let mut args = std::env::args().skip(1).peekable();
    if args.peek().map(String::as_str) == Some("keygen") {
        args.next();
        keygen(args);
    }
    let mut listen = "127.0.0.1:7700".to_string();
    let mut keys: Option<PathBuf> = None;
    let mut config = RelayConfig::default();
    while let Some(arg) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| usage(&arg));
        match arg.as_str() {
            "--listen" => listen = value(),
            "--keys" => keys = Some(value().into()),
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
            "--max-connections" => {
                config.max_connections =
                    value().parse().unwrap_or_else(|_| usage("--max-connections"))
            }
            "--max-connections-per-address" => {
                config.max_connections_per_address = value()
                    .parse()
                    .unwrap_or_else(|_| usage("--max-connections-per-address"))
            }
            other => usage(other),
        }
    }
    let keys = keys.map(|path| {
        RelayKeys::read(&path).unwrap_or_else(|e| {
            eprintln!("arcium-relay: cannot read keys from {}: {e}", path.display());
            std::process::exit(1);
        })
    });
    let listener = TcpListener::bind(&listen).unwrap_or_else(|e| {
        eprintln!("arcium-relay: cannot listen on {listen}: {e}");
        std::process::exit(1);
    });
    let handle = match &keys {
        Some(keys) => serve_v2(listener, config, keys),
        None => serve(listener, config),
    }
    .unwrap_or_else(|e| {
        eprintln!("arcium-relay: {e}");
        std::process::exit(2);
    });
    match &keys {
        // Public values only: what the connection string carries.
        Some(keys) => eprintln!(
            "arcium-relay: listening on {} (RELAY_PROTOCOL_V2, TLS 1.3), tls_pin={} auth_pk={}",
            handle.addr(),
            keys.tls_pin().map(|p| hex(&p)).unwrap_or_default(),
            hex(&keys.auth_public())
        ),
        None => eprintln!(
            "arcium-relay: listening on {} (RELAY_PROTOCOL_V1: no TLS, no authentication; development only)",
            handle.addr()
        ),
    }
    loop {
        std::thread::park();
    }
}

/// `keygen --out FILE --address HOST:PORT`: writes new keys, prints the
/// connection string, exits.
fn keygen(mut args: impl Iterator<Item = String>) -> ! {
    let (mut out, mut address) = (None, None);
    while let Some(arg) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| usage(&arg));
        match arg.as_str() {
            "--out" => out = Some(PathBuf::from(value())),
            "--address" => address = Some(value()),
            other => usage(other),
        }
    }
    let out = out.unwrap_or_else(|| usage("keygen needs --out FILE"));
    let address = address.unwrap_or_else(|| usage("keygen needs --address HOST:PORT"));
    // Checked before anything is written.
    let (host, port) = RelayAddress::parse_host_port(&address).unwrap_or_else(|e| {
        eprintln!("arcium-relay: --address {address}: {e}");
        std::process::exit(2);
    });
    let (keys, connection) = RelayKeys::generate()
        .and_then(|k| k.address(&host, port).map(|a| (k, a)))
        .unwrap_or_else(|e| {
            eprintln!("arcium-relay: cannot make keys: {e}");
            std::process::exit(1);
        });
    keys.write_new(&out).unwrap_or_else(|e| {
        eprintln!("arcium-relay: cannot write keys to {}: {e}", out.display());
        std::process::exit(1);
    });
    eprintln!("arcium-relay: wrote the relay's secret keys to {} (mode 0600)", out.display());
    println!("{connection}");
    std::process::exit(0);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn usage(bad: &str) -> ! {
    eprintln!(
        "arcium-relay: bad argument {bad}\n\
         usage: arcium-relay keygen --out FILE --address HOST:PORT\n\
         \x20      arcium-relay --listen HOST:PORT [--keys FILE] [--db FILE] [--log] [--canary TEXT] [--ttl-secs N] [--max-mailbox N] [--max-total-bytes N] [--max-connections N] [--max-connections-per-address N]\n\
         keygen           write new relay keys to FILE (mode 0600, never over a file) and print the connection string for HOST:PORT\n\
         --keys FILE      serve RELAY_PROTOCOL_V2 (TLS, authenticated mailboxes) with these keys; without it, V1 for development only\n\
         --db FILE        keep mailboxes and bundles in this SQLite file across restarts\n\
         --max-mailbox N  envelopes per mailbox, 1 to {DEFAULT_MAX_MAILBOX} (default {DEFAULT_MAX_MAILBOX})\n\
         --max-total-bytes N  envelope bytes in all mailboxes together (default 1 GiB)\n\
         --max-connections N, --max-connections-per-address N  open connections in all (default 1024) and per IP (default 32)"
    );
    std::process::exit(2);
}
