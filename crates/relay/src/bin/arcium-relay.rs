//! `arcium-relay --listen HOST:PORT [--log] [--canary TEXT] [--ttl-secs N] [--max-mailbox N]`
//!
//! Runs the untrusted store-and-forward relay until killed. For development
//! and tests only: no TLS, no authentication, nothing persisted.

use std::net::TcpListener;
use std::time::Duration;

use relay::server::{serve, RelayConfig};

fn main() {
    let mut listen = "127.0.0.1:7700".to_string();
    let mut config = RelayConfig::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| usage(&arg));
        match arg.as_str() {
            "--listen" => listen = value(),
            "--log" => config.log = true,
            "--canary" => config.canary = Some(value().into_bytes()),
            "--ttl-secs" => {
                config.ttl =
                    Duration::from_secs(value().parse().unwrap_or_else(|_| usage("--ttl-secs")))
            }
            "--max-mailbox" => {
                config.max_mailbox = value().parse().unwrap_or_else(|_| usage("--max-mailbox"))
            }
            other => usage(other),
        }
    }
    let listener = TcpListener::bind(&listen).unwrap_or_else(|e| {
        eprintln!("arcium-relay: cannot listen on {listen}: {e}");
        std::process::exit(1);
    });
    let handle = serve(listener, config).expect("relay");
    eprintln!("arcium-relay: listening on {}", handle.addr());
    loop {
        std::thread::park();
    }
}

fn usage(bad: &str) -> ! {
    eprintln!(
        "arcium-relay: bad argument {bad}\n\
         usage: arcium-relay --listen HOST:PORT [--log] [--canary TEXT] [--ttl-secs N] [--max-mailbox N]"
    );
    std::process::exit(2);
}
