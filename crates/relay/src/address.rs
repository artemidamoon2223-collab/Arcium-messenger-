//! The connection string of a `RELAY_PROTOCOL_V2` relay: everything a client
//! needs to reach it and to check that it reached the right one.
//!
//! ```text
//! arcium-relay-v2:<host>:<port>:<tls_pin>:<auth_pk>
//! ```
//!
//! - `host`: a lowercase DNS name, an IPv4 address in dotted decimal, or an
//!   IPv6 address in brackets (`[::1]`), each in its canonical form;
//! - `port`: decimal, 1 to 65535, no leading zero;
//! - `tls_pin`: SHA-256 of the DER `SubjectPublicKeyInfo` of the relay's
//!   Ed25519 TLS key, 64 lowercase hex digits;
//! - `auth_pk`: the relay's X25519 authentication public key, 64 lowercase
//!   hex digits.
//!
//! Parsing is strict: no whitespace, no other case, no missing or extra field.
//! A relay therefore has exactly one connection string per host and port, and
//! [`RelayAddress`]'s `Display` writes it.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::protocol::Key;

/// The prefix that names the format and its version.
pub const ADDRESS_PREFIX: &str = "arcium-relay-v2:";

/// A parsed, validated connection string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAddress {
    host: String,
    port: u16,
    tls_pin: [u8; 32],
    auth_pk: Key,
}

/// Why a connection string (or a host and port) was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid relay address: {0}")]
pub struct AddressError(pub &'static str);

impl RelayAddress {
    /// A connection string for `host` and `port`, both validated as when
    /// parsed.
    pub fn new(host: &str, port: u16, tls_pin: [u8; 32], auth_pk: Key) -> Result<Self, AddressError> {
        check_host(host)?;
        if port == 0 {
            return Err(AddressError("port 0"));
        }
        Ok(Self {
            host: host.to_string(),
            port,
            tls_pin,
            auth_pk,
        })
    }

    /// Parses a connection string; see the module documentation.
    pub fn parse(s: &str) -> Result<Self, AddressError> {
        let rest = s
            .strip_prefix(ADDRESS_PREFIX)
            .ok_or(AddressError("not an arcium-relay-v2 connection string"))?;
        // From the right: the last three fields never contain ':', and the
        // host contains it only inside brackets, which `check_host` enforces.
        let mut fields = rest.rsplitn(4, ':');
        let auth_pk = fields.next().ok_or(AddressError("missing auth key"))?;
        let tls_pin = fields.next().ok_or(AddressError("missing TLS pin"))?;
        let port = fields.next().ok_or(AddressError("missing port"))?;
        let host = fields.next().ok_or(AddressError("missing host"))?;
        let auth_pk = parse_hex32(auth_pk).ok_or(AddressError("auth key is not 64 lowercase hex digits"))?;
        let tls_pin = parse_hex32(tls_pin).ok_or(AddressError("TLS pin is not 64 lowercase hex digits"))?;
        Self::new(host, parse_port(port)?, tls_pin, auth_pk)
    }

    /// Parses `HOST:PORT` with the rules of the connection string.
    pub fn parse_host_port(s: &str) -> Result<(String, u16), AddressError> {
        let (host, port) = s.rsplit_once(':').ok_or(AddressError("expected HOST:PORT"))?;
        check_host(host)?;
        Ok((host.to_string(), parse_port(port)?))
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// SHA-256 of the relay's TLS `SubjectPublicKeyInfo`.
    pub fn tls_pin(&self) -> &[u8; 32] {
        &self.tls_pin
    }

    /// The relay's X25519 authentication public key.
    pub fn auth_pk(&self) -> &Key {
        &self.auth_pk
    }

    /// `host:port`, for resolving and connecting.
    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl FromStr for RelayAddress {
    type Err = AddressError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for RelayAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{ADDRESS_PREFIX}{}:{}:{}:{}",
            self.host,
            self.port,
            hex(&self.tls_pin),
            hex(&self.auth_pk)
        )
    }
}

fn parse_port(s: &str) -> Result<u16, AddressError> {
    let canonical = !s.is_empty() && s.len() <= 5 && s.bytes().all(|b| b.is_ascii_digit()) && !s.starts_with('0');
    if !canonical {
        return Err(AddressError("port is not a decimal number from 1 to 65535"));
    }
    s.parse().map_err(|_| AddressError("port is not a decimal number from 1 to 65535"))
}

/// A lowercase DNS name, a dotted-decimal IPv4 address, or a bracketed IPv6
/// address, each canonical: what parses must also print back unchanged.
fn check_host(host: &str) -> Result<(), AddressError> {
    if let Some(inner) = host.strip_prefix('[') {
        let inner = inner.strip_suffix(']').ok_or(AddressError("unclosed '[' in host"))?;
        let ip: Ipv6Addr = inner.parse().map_err(|_| AddressError("bad IPv6 address"))?;
        if ip.to_string() != inner {
            return Err(AddressError("IPv6 address not in canonical form"));
        }
        return Ok(());
    }
    if host.is_empty() || host.len() > 253 {
        return Err(AddressError("host must be 1 to 253 characters"));
    }
    // Digits and dots only: an IPv4 address, never a name ("010.1" and the
    // like mean different things to different resolvers).
    if host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        let ip: Ipv4Addr = host.parse().map_err(|_| AddressError("bad IPv4 address"))?;
        if ip.to_string() != host {
            return Err(AddressError("IPv4 address not in canonical form"));
        }
        return Ok(());
    }
    for label in host.split('.') {
        let ok = (1..=63).contains(&label.len())
            && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !ok {
            return Err(AddressError(
                "host is not a lowercase DNS name, an IPv4 address or a bracketed IPv6 address",
            ));
        }
    }
    Ok(())
}

/// Lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Exactly 64 lowercase hex digits.
pub(crate) fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.as_bytes();
    if s.len() != 64 {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    let (pairs, _) = s.as_chunks::<2>();
    for (byte, [hi, lo]) in out.iter_mut().zip(pairs) {
        *byte = digit(*hi)? << 4 | digit(*lo)?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIN: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const PK: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

    fn s(host_port: &str) -> String {
        format!("{ADDRESS_PREFIX}{host_port}:{PIN}:{PK}")
    }

    #[test]
    fn valid_connection_strings_parse_and_print_back_unchanged() {
        for host_port in [
            "relay.example.org:7700",
            "127.0.0.1:1",
            "10.0.2.2:65535",
            "[::1]:7700",
            "[2001:db8::1]:443",
            "localhost:7700",
            "a-b.c0:9",
        ] {
            let text = s(host_port);
            let a = RelayAddress::parse(&text).unwrap_or_else(|e| panic!("{host_port}: {e}"));
            assert_eq!(a.to_string(), text);
            assert_eq!(a.socket_addr(), host_port);
            assert_eq!(text.parse::<RelayAddress>().unwrap(), a);
        }
        let a = RelayAddress::parse(&s("[::1]:7700")).unwrap();
        assert_eq!(a.host(), "[::1]");
        assert_eq!(a.port(), 7700);
        assert_eq!(hex(a.tls_pin()), PIN);
        assert_eq!(hex(a.auth_pk()), PK);
    }

    #[test]
    fn invalid_connection_strings_are_refused() {
        let upper_pin = PIN.to_uppercase();
        let short = &PIN[..62];
        let long = format!("{PIN}00");
        let bad: Vec<String> = vec![
            String::new(),
            format!("arcium-relay-v1:h:1:{PIN}:{PK}"),
            format!("ARCIUM-RELAY-V2:h:1:{PIN}:{PK}"),
            format!(" {}", s("h:1")),
            format!("{} ", s("h:1")),
            format!("{}\n", s("h:1")),
            format!("{ADDRESS_PREFIX}h:1:{PIN}"),            // missing field
            format!("{ADDRESS_PREFIX}:1:{PIN}:{PK}"),         // empty host
            format!("{ADDRESS_PREFIX}h::{PIN}:{PK}"),         // empty port
            format!("{ADDRESS_PREFIX}h:1:{upper_pin}:{PK}"),  // uppercase hex
            format!("{ADDRESS_PREFIX}h:1:{short}:{PK}"),      // short pin
            format!("{ADDRESS_PREFIX}h:1:{long}:{PK}"),       // long pin
            format!("{ADDRESS_PREFIX}h:1:{PIN}:{PK}:x"),      // extra field
            format!("{ADDRESS_PREFIX}h:1:{PIN}:{}g", &PK[..63]), // not hex
            s("h:0"),
            s("h:07700"),
            s("h:65536"),
            s("h:+1"),
            s("h:-1"),
            s("h:1 "),
            s("Relay.example.org:1"),
            s("relay_x:1"),
            s("-relay:1"),
            s("relay-:1"),
            s("a..b:1"),
            s(".a:1"),
            s("a.:1"),
            s("::1:7700"),       // IPv6 without brackets
            s("[::1:7700"),      // unclosed bracket
            s("[0:0::1]:7700"),  // not canonical
            s("[::ffff:1.2.3.4]x:1"),
            s("[relay]:1"),
            s("010.0.0.1:1"),    // leading zero
            s("1.2.3:1"),        // not four octets
            s("256.0.0.1:1"),
            s(&format!("{}:1", "a".repeat(64))),
            s(&format!("{}:1", ["a"; 128].join("."))), // 255 characters
        ];
        for text in &bad {
            assert!(RelayAddress::parse(text).is_err(), "accepted {text:?}");
        }
    }

    #[test]
    fn host_and_port_are_validated_on_their_own_too() {
        assert_eq!(
            RelayAddress::parse_host_port("relay.example.org:7700").unwrap(),
            ("relay.example.org".to_string(), 7700)
        );
        assert_eq!(RelayAddress::parse_host_port("[::1]:1").unwrap(), ("[::1]".to_string(), 1));
        for bad in ["relay", "relay:", ":1", "relay:0", "::1:1", "Relay:1", "relay:1:2"] {
            assert!(RelayAddress::parse_host_port(bad).is_err(), "accepted {bad:?}");
        }
        assert!(RelayAddress::new("h", 0, [0; 32], [0; 32]).is_err());
        assert!(RelayAddress::new("h h", 1, [0; 32], [0; 32]).is_err());
    }

    #[test]
    fn hex_is_strict_lowercase_and_exactly_32_bytes() {
        assert_eq!(parse_hex32(PIN).map(|b| hex(&b)), Some(PIN.to_string()));
        for bad in ["", &PIN[..63], &PIN.to_uppercase(), &format!("{}x", &PIN[..63])] {
            assert!(parse_hex32(bad).is_none(), "{bad}");
        }
    }
}
