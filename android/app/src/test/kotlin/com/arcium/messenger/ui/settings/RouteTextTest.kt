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

    /** A relay reached through Tor says so, and then what Tor is doing once that has been read. */
    @Test
    fun aRelayThroughTorSaysSoAndNamesTorsState() {
        assertEquals("Through Tor: the relay does not see your IP address.", routeStatus(true, null))
        assertEquals("Without Tor: the relay sees your IP address.", routeStatus(false, null))
        for (state in TorState.values()) {
            val text = routeStatus(true, state)
            assertTrue(text, text.startsWith("Through Tor: the relay does not see your IP address. "))
            assertTrue(text, text.endsWith(torStatus(state)))
        }
    }

    /** Each state has its own text, and it is this one. */
    @Test
    fun everyTorStateHasItsOwnText() {
        val texts = TorState.values().map(::torStatus)
        assertEquals(texts.toString(), texts.size, texts.toSet().size)
        assertEquals("Tor starts with the first connection to the relay.", torStatus(TorState.NOT_STARTED))
        assertEquals("Tor is starting; a start can take up to two minutes.", torStatus(TorState.STARTING))
        assertEquals("Tor is running.", torStatus(TorState.RUNNING))
        assertEquals(
            "Tor needs an app update: the Tor network requires a newer version of this app. " +
                "Until it is updated, nothing reaches this relay.",
            torStatus(TorState.NEEDS_UPDATE),
        )
        assertEquals(
            "Tor did not start. The app tries again at its next sync, at least a minute later.",
            torStatus(TorState.FAILED),
        )
    }
}
