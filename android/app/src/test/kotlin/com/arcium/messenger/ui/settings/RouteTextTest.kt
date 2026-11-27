package com.arcium.messenger.ui.settings

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.arcium_core.TorState

/** What Settings says about the route to the relay and about Tor, without Android. */
class RouteTextTest {

    /** A relay reached directly is labelled as one that sees the IP address, whatever Tor's state. */
    @Test
    fun aDirectRelayIsLabelledAsSeeingTheAddress() {
        for (state in TorState.values()) {
            assertEquals(state.name, "Without Tor: the relay sees your IP address.", routeStatus(false, state))
        }
    }

    /** A relay reached through Tor says so, and then what Tor is doing. */
    @Test
    fun aRelayThroughTorSaysSoAndNamesTorsState() {
        for (state in TorState.values()) {
            val text = routeStatus(true, state)
            assertTrue(text, text.startsWith("Through Tor: the relay does not see your IP address. "))
            assertTrue(text, text.endsWith(torStatus(state)))
        }
    }

    /** Each state has its own text; the one that needs an update asks for it. */
    @Test
    fun everyTorStateHasItsOwnText() {
        val texts = TorState.values().map(::torStatus)
        assertEquals(texts.toString(), texts.size, texts.toSet().size)
        assertTrue(torStatus(TorState.NEEDS_UPDATE).startsWith("Tor needs an app update"))
        assertEquals("Tor is running.", torStatus(TorState.RUNNING))
    }
}
