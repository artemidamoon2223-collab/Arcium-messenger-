package com.arcium.messenger.messaging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Which relay a build may use, without Android or native code: every build
 * accepts a V2 connection string, only a debug build a development relay's
 * `host:port`. The V2 vectors are those of `crates/relay/src/address.rs`.
 */
class RelayRulesTest {

    private val pin = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    private val pk = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"

    private fun v2(hostPort: String) = "arcium-relay-v2:$hostPort:$pin:$pk"

    private val debug = true
    private val release = false

    @Test
    fun everyBuildAcceptsAV2ConnectionString() {
        for (hostPort in listOf(
            "relay.example.org:7700",
            "127.0.0.1:1",
            "10.0.2.2:65535",
            "[::1]:7700",
            "[2001:db8::1]:443",
            "localhost:7700",
            "a-b.c0:9",
        )) {
            for (build in listOf(debug, release)) {
                assertEquals(hostPort, RelayChoice(v2(hostPort), RelayProtocol.V2), relayChoice(v2(hostPort), build))
            }
        }
    }

    @Test
    fun surroundingWhitespaceIsTrimmed() {
        val s = v2("relay.example.org:7700")
        assertEquals(RelayChoice(s, RelayProtocol.V2), relayChoice("  $s\n", release))
        assertEquals(RelayChoice("10.0.2.2:7700", RelayProtocol.DEV_V1), relayChoice(" 10.0.2.2:7700 ", debug))
    }

    @Test
    fun aDebugBuildAcceptsADevelopmentRelay() {
        assertEquals(RelayChoice("10.0.2.2:7700", RelayProtocol.DEV_V1), relayChoice("10.0.2.2:7700", debug))
        assertEquals(RelayChoice("localhost:1", RelayProtocol.DEV_V1), relayChoice("localhost:1", debug))
        for (bad in listOf("", "relay", ":7700", "relay:0", "relay:65536", "relay:x", "re lay:1", "a/b:1")) {
            assertNull(bad, relayChoice(bad, debug))
        }
    }

    @Test
    fun aReleaseBuildRefusesEveryDevelopmentRelay() {
        for (dev in listOf("10.0.2.2:7700", "127.0.0.1:1", "localhost:7700", "relay.example.org:7700")) {
            assertEquals(dev, RelayProtocol.DEV_V1, relayChoice(dev, debug)?.protocol)
            assertNull(dev, relayChoice(dev, release))
        }
    }

    @Test
    fun malformedV2StringsAreRefusedAndNeverReadAsHostAndPort() {
        val upperPin = pin.uppercase()
        val short = pin.substring(0, 62)
        val bad = listOf(
            "arcium-relay-v2:",
            "arcium-relay-v2:h:1:$pin",
            "arcium-relay-v2::1:$pin:$pk",
            "arcium-relay-v2:h::$pin:$pk",
            "arcium-relay-v2:h:1:$upperPin:$pk",
            "arcium-relay-v2:h:1:$short:$pk",
            "arcium-relay-v2:h:1:${pin}00:$pk",
            "arcium-relay-v2:h:1:$pin:$pk:x",
            // Both would pass as host:port if the prefix did not rule that out.
            "arcium-relay-v2:h:1:$pin:$pk:7700",
            "arcium-relay-v2:7700",
            "arcium-relay-v2:h:1:$pin:${pk.substring(0, 63)}g",
            v2("h:0"),
            v2("h:07700"),
            v2("h:65536"),
            v2("h:+1"),
            v2("h:-1"),
            v2("Relay.example.org:1"),
            v2("relay_x:1"),
            v2("-relay:1"),
            v2("relay-:1"),
            v2("a..b:1"),
            v2(".a:1"),
            v2("a.:1"),
            v2("::1:7700"),
            v2("[::1:7700"),
            v2("[relay]:1"),
            v2("010.0.0.1:1"),
            v2("1.2.3:1"),
            v2("256.0.0.1:1"),
            v2("${"a".repeat(64)}:1"),
            v2("${List(128) { "a" }.joinToString(".")}:1"),
            v2("h h:1"),
        )
        for (s in bad) {
            assertFalse(s, isV2ConnectionString(s))
            assertNull(s, relayChoice(s, debug))
            assertNull(s, relayChoice(s, release))
        }
    }

    @Test
    fun otherPrefixesAreNotV2() {
        for (s in listOf("arcium-relay-v1:h:1:$pin:$pk", "ARCIUM-RELAY-V2:h:1:$pin:$pk")) {
            assertFalse(s, isV2ConnectionString(s))
            assertNull(s, relayChoice(s, release))
        }
    }

    @Test
    fun theProtocolFollowsThePrefix() {
        assertEquals(RelayProtocol.V2, relayProtocolOf(v2("relay.example.org:7700")))
        assertEquals(RelayProtocol.DEV_V1, relayProtocolOf("10.0.2.2:7700"))
    }

    @Test
    fun theHintNamesHostAndPortOnlyWhereTheyAreAccepted() {
        assertTrue(relayInputHint(debug).contains("host:port"))
        assertFalse(relayInputHint(release).contains("host:port"))
        assertTrue(relayInputHint(release).contains("arcium-relay-v2:"))
    }
}
