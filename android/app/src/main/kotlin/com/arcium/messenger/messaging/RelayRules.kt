package com.arcium.messenger.messaging

/** How the app talks to a relay (docs/NET-MESSAGING.md, sections 1 and 3). */
internal enum class RelayProtocol {
    /**
     * `RELAY_PROTOCOL_V2`: TLS 1.3 to the relay's pinned key, and only this
     * device can read or delete its mailbox.
     */
    V2,

    /** `RELAY_PROTOCOL_V1`: plain TCP, no authentication. Debug builds only. */
    DEV_V1,
}

/** A relay this build may use: the string the Rust core is given, and its protocol. */
internal data class RelayChoice(val address: String, val protocol: RelayProtocol)

/** The prefix of a V2 connection string (`crates/relay/src/address.rs`). */
internal const val V2_PREFIX = "arcium-relay-v2:"

/**
 * [value], trimmed, if this build may use it as its relay; null otherwise.
 *
 * Every build accepts a V2 connection string,
 * `arcium-relay-v2:<host>:<port>:<tls_pin>:<auth_pk>`, as `arcium-relay
 * keygen` prints it. Only a build with [devRelayAllowed] (a debug build)
 * also accepts `host:port` of a development relay. A string with the V2
 * prefix is never read as `host:port`.
 */
internal fun relayChoice(value: String, devRelayAllowed: Boolean): RelayChoice? {
    val trimmed = value.trim()
    if (trimmed.startsWith(V2_PREFIX)) {
        return if (isV2ConnectionString(trimmed)) RelayChoice(trimmed, RelayProtocol.V2) else null
    }
    if (!devRelayAllowed) return null
    return devHostPort(trimmed)?.let { RelayChoice(it, RelayProtocol.DEV_V1) }
}

/** The protocol of an address [relayChoice] returned. */
internal fun relayProtocolOf(address: String): RelayProtocol =
    if (address.startsWith(V2_PREFIX)) RelayProtocol.V2 else RelayProtocol.DEV_V1

/** What to enter, for the error shown when [relayChoice] refuses the input. */
internal fun relayInputHint(devRelayAllowed: Boolean): String =
    if (devRelayAllowed) {
        "enter a connection string (arcium-relay-v2:…) or a development relay's host:port, for example 10.0.2.2:7700"
    } else {
        "enter the relay's connection string (arcium-relay-v2:…)"
    }

/**
 * Whether [s] is a V2 connection string by the rules of
 * `RelayAddress::parse` (`crates/relay/src/address.rs`): exact, no
 * whitespace, lowercase hex. One difference: a bracketed IPv6 host is only
 * checked for its characters here, and the Rust parser also requires its
 * canonical form. Rust parses the string again on every connection and
 * refuses what it does not accept, so a string this check lets through and
 * Rust refuses fails every round with a network error naming the reason; it
 * is never tried as `host:port`.
 */
internal fun isV2ConnectionString(s: String): Boolean {
    if (!s.startsWith(V2_PREFIX)) return false
    val rest = s.substring(V2_PREFIX.length)
    // From the right: the last three fields never contain ':', and the host
    // contains it only inside brackets.
    val authAt = rest.lastIndexOf(':')
    if (authAt < 0) return false
    val pinAt = rest.lastIndexOf(':', authAt - 1)
    if (pinAt < 0) return false
    val portAt = rest.lastIndexOf(':', pinAt - 1)
    if (portAt < 0) return false
    return isHost(rest.substring(0, portAt)) &&
        isPort(rest.substring(portAt + 1, pinAt)) &&
        isHex64(rest.substring(pinAt + 1, authAt)) &&
        isHex64(rest.substring(authAt + 1))
}

private fun isHex64(s: String): Boolean = s.length == 64 && s.all { it in '0'..'9' || it in 'a'..'f' }

/** Decimal, 1 to 65535, no leading zero. */
private fun isPort(s: String): Boolean =
    s.length in 1..5 && s.all { it in '0'..'9' } && s[0] != '0' && s.toInt() <= 65535

/**
 * A lowercase DNS name, a dotted-decimal IPv4 address in canonical form, or a
 * bracketed IPv6 address (characters only; see [isV2ConnectionString]).
 */
private fun isHost(host: String): Boolean {
    if (host.startsWith("[")) {
        val inner = host.substring(1).removeSuffix("]")
        return host.endsWith("]") && inner.isNotEmpty() &&
            inner.all { it in '0'..'9' || it in 'a'..'f' || it == ':' || it == '.' }
    }
    if (host.isEmpty() || host.length > 253) return false
    // Digits and dots only: an IPv4 address, never a name.
    if (host.all { it in '0'..'9' || it == '.' }) {
        val octets = host.split('.')
        return octets.size == 4 && octets.all { o ->
            o.length in 1..3 && (o.length == 1 || o[0] != '0') && o.toInt() <= 255
        }
    }
    return host.split('.').all { label ->
        label.length in 1..63 &&
            label.all { it in 'a'..'z' || it in '0'..'9' || it == '-' } &&
            !label.startsWith('-') && !label.endsWith('-')
    }
}

/** `host:port` of a development relay, with a port from 1 to 65535; null if it is not one. */
private fun devHostPort(trimmed: String): String? {
    val colon = trimmed.lastIndexOf(':')
    if (colon <= 0) return null
    val host = trimmed.substring(0, colon)
    val port = trimmed.substring(colon + 1).toIntOrNull() ?: return null
    if (port !in 1..65535 || host.any { it.isWhitespace() || it == '/' }) return null
    return "$host:$port"
}
