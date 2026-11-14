package com.arcium.messenger.messaging

import org.junit.Assert.assertEquals
import org.junit.Test
import uniffi.arcium_core.SyncReport

/**
 * R-17: a round that reached the relay but failed on this device is shown as
 * a problem, not as a healthy link. The budget notice is not an error, and a
 * network error still means the relay was not reached.
 */
class RelayLinkTest {

    private fun report(vararg errors: String) = SyncReport(
        published = 0u,
        fetched = 0u,
        accepted = 0u,
        duplicates = 0u,
        sessionsAccepted = 0u,
        delivered = 0u,
        dropped = 0u,
        deferred = 0u,
        errors = errors.toList(),
    )

    private fun link(vararg errors: String, network: Boolean = true) =
        linkAfterRound(report(*errors), 7L) { network }

    @Test
    fun aCleanRoundIsOnlineWithoutAProblem() {
        assertEquals(RelayLink.Online(7L, null), link())
    }

    @Test
    fun theBudgetNoticeIsNotAProblem() {
        assertEquals(
            RelayLink.Online(7L, null),
            link("round budget exhausted: the rest follows in the next round"),
        )
    }

    @Test
    fun anErrorOnThisDeviceIsShownWhileOnline() {
        assertEquals(
            RelayLink.Online(7L, "storage error: key not found"),
            link("storage error: key not found"),
        )
        assertEquals(
            RelayLink.Online(7L, "handshake refused: one-time prekey unavailable"),
            link(
                "round budget exhausted: the rest follows in the next round",
                "handshake refused: one-time prekey unavailable",
                "storage error: key not found",
            ),
        )
    }

    @Test
    fun aNetworkErrorIsOfflineWhateverElseWasReported() {
        assertEquals(
            RelayLink.Offline("network: connection refused", networkAvailable = false),
            link("storage error: key not found", "network: connection refused", network = false),
        )
        assertEquals(
            RelayLink.Offline("network: timed out", networkAvailable = true),
            link("network: timed out"),
        )
    }
}
