package com.arcium.messenger.ui.chat

import com.arcium.messenger.ffi.PlaintextText
import org.junit.Assert.assertEquals
import org.junit.Test
import uniffi.arcium_core.ChatEntry
import uniffi.arcium_core.ChatEntryState

/**
 * Which actions a message bubble offers per state (R-15): "Cancel" only on
 * an own text not yet final, "Send again" only on one given up on.
 */
class CancelActionsTest {
    private fun entry(outgoing: Boolean, state: ChatEntryState) =
        ChatEntry(1uL, outgoing, state, 1uL, byteArrayOf(0x61), PlaintextText("hi"))

    @Test
    fun eachStateOffersTheRightActions() {
        val expected = mapOf(
            ChatEntryState.QUEUED to (true to false),
            ChatEntryState.PENDING to (true to false),
            ChatEntryState.TRANSMITTED to (true to false),
            ChatEntryState.DELIVERED to (false to false),
            ChatEntryState.NOT_DELIVERED to (false to true),
            ChatEntryState.CANCELLED to (false to true),
            ChatEntryState.RECEIVED to (false to false),
        )
        assertEquals(ChatEntryState.entries.toSet(), expected.keys)
        for ((state, actions) in expected) {
            val e = entry(outgoing = state != ChatEntryState.RECEIVED, state = state)
            assertEquals("cancel $state", actions.first, cancellable(e))
            assertEquals("send again $state", actions.second, resendable(e))
        }
    }

    @Test
    fun incomingEntriesOfferNothing() {
        for (state in ChatEntryState.entries) {
            val e = entry(outgoing = false, state = state)
            assertEquals(false, cancellable(e))
            assertEquals(false, resendable(e))
        }
    }

    @Test
    fun cancelledHasItsOwnLabel() {
        assertEquals("Cancelled", statusLabel(ChatEntryState.CANCELLED))
    }
}
