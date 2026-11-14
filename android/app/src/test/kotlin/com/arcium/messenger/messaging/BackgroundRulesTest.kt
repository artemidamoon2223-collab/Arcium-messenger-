package com.arcium.messenger.messaging

import com.arcium.messenger.ffi.PlaintextText
import com.arcium.messenger.startup.StartupProblem
import com.arcium.messenger.startup.StartupState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.arcium_core.ChatEntry
import uniffi.arcium_core.ChatEntryState
import uniffi.arcium_core.ChatSessionState
import uniffi.arcium_core.Conversation

/**
 * Background receive's own rules, without Android or native code: when the
 * service may run, and when a round's conversation list means a new text
 * arrived that the user should be told about (without saying from whom).
 */
class BackgroundRulesTest {

    private val relay = "10.0.2.2:7700"
    private val blocked = StartupState.Blocked(StartupProblem.KeyMissingForExistingData)

    // ── backgroundState ─────────────────────────────────────────────────────

    @Test
    fun itRunsWhenOnReadyWithARelayAndNotifications() {
        assertEquals(BackgroundState.RUN, backgroundState(true, StartupState.Ready, relay, true))
    }

    @Test
    fun offWinsOverEverythingElse() {
        for (startup in listOf(StartupState.Ready, StartupState.Checking, blocked)) {
            for (address in listOf(relay, null)) {
                for (notifications in listOf(true, false)) {
                    assertEquals(BackgroundState.OFF, backgroundState(false, startup, address, notifications))
                }
            }
        }
    }

    @Test
    fun nothingRunsBeforeStartupIsReady() {
        assertEquals(BackgroundState.WAITING_FOR_STARTUP, backgroundState(true, StartupState.Checking, relay, true))
        assertEquals(BackgroundState.STARTUP_BLOCKED, backgroundState(true, blocked, relay, true))
        // Without a store, the relay and notifications do not matter yet.
        assertEquals(BackgroundState.STARTUP_BLOCKED, backgroundState(true, blocked, null, false))
    }

    @Test
    fun withoutARelayThereIsNothingToStayConnectedTo() {
        assertEquals(BackgroundState.NO_RELAY, backgroundState(true, StartupState.Ready, null, true))
        assertEquals(BackgroundState.NO_RELAY, backgroundState(true, StartupState.Ready, null, false))
    }

    @Test
    fun withoutNotificationsItDoesNotRunUnseen() {
        assertEquals(BackgroundState.NOTIFICATIONS_BLOCKED, backgroundState(true, StartupState.Ready, relay, false))
    }

    // ── newestEntries ───────────────────────────────────────────────────────

    private fun entry(seq: ULong, outgoing: Boolean) = ChatEntry(
        seq,
        outgoing,
        if (outgoing) ChatEntryState.DELIVERED else ChatEntryState.RECEIVED,
        1_700_000_000_000uL,
        if (outgoing) byteArrayOf(0x61) else byteArrayOf(),
        PlaintextText("text"),
    )

    private fun conversation(key: Byte, last: ChatEntry?, unread: UInt = 0u) = Conversation(
        ByteArray(32) { key }, "Bob", "fp", ChatSessionState.Established, false, false, "", unread, last,
    )

    private val keyA = "01".repeat(32)
    private val keyB = "02".repeat(32)

    @Test
    fun newestEntriesKeepTheNumberAndDirectionByContact() {
        val newest = newestEntries(
            listOf(
                conversation(1, entry(5uL, outgoing = false)),
                conversation(2, entry(9uL, outgoing = true)),
            ),
        )
        assertEquals(mapOf(keyA to NewestEntry(5uL, true), keyB to NewestEntry(9uL, false)), newest)
    }

    @Test
    fun aConversationWithoutEntriesIsLeftOut() {
        assertEquals(emptyMap<String, NewestEntry>(), newestEntries(listOf(conversation(1, null))))
    }

    // ── notifyAfterRound ────────────────────────────────────────────────────

    private val before = mapOf(keyA to NewestEntry(5uL, true), keyB to NewestEntry(9uL, false))

    @Test
    fun aNewTextFromAContactIsNotifiedWhileTheAppIsNotVisible() {
        val after = before + (keyA to NewestEntry(6uL, true))
        assertTrue(notifyAfterRound(before, after, visible = false))
        // Also several texts at once, after an own text.
        assertTrue(notifyAfterRound(before, before + (keyB to NewestEntry(12uL, true)), visible = false))
    }

    @Test
    fun nothingIsNotifiedWhileTheAppIsVisible() {
        assertFalse(notifyAfterRound(before, before + (keyA to NewestEntry(6uL, true)), visible = true))
    }

    @Test
    fun anUnchangedListIsNotNotified() {
        // The newest entry of A is incoming, but it was there before the round.
        assertFalse(notifyAfterRound(before, before, visible = false))
    }

    @Test
    fun aNewOwnTextIsNotNotified() {
        assertFalse(notifyAfterRound(before, before + (keyA to NewestEntry(6uL, false)), visible = false))
    }

    @Test
    fun aFirstTextFromAContactWithNoEntriesBeforeIsNotified() {
        val keyC = "03".repeat(32)
        assertTrue(notifyAfterRound(before, before + (keyC to NewestEntry(1uL, true)), visible = false))
    }

    @Test
    fun aTextInAHistoryThatRestartedIsNotified() {
        // Deleting a contact removes its history; added again, it restarts at 1.
        assertTrue(notifyAfterRound(before, before + (keyB to NewestEntry(1uL, true)), visible = false))
    }

    @Test
    fun aListThatCouldNotBeReadNotifiesNothing() {
        val after = before + (keyA to NewestEntry(6uL, true))
        assertFalse(notifyAfterRound(null, after, visible = false))
        assertFalse(notifyAfterRound(before, null, visible = false))
    }

    @Test
    fun theBackgroundPaceIsSlowerThanTheVisibleOne() {
        assertEquals(VISIBLE_IDLE_DELAY_MS, idleDelayMs(visible = true))
        assertEquals(BACKGROUND_IDLE_DELAY_MS, idleDelayMs(visible = false))
        assertTrue(BACKGROUND_IDLE_DELAY_MS >= 30_000L)
        assertTrue(VISIBLE_IDLE_DELAY_MS < BACKGROUND_IDLE_DELAY_MS)
    }
}
