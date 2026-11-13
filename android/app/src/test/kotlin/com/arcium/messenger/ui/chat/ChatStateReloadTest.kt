package com.arcium.messenger.ui.chat

import com.arcium.messenger.ffi.PlaintextText
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import uniffi.arcium_core.ChatEntry
import uniffi.arcium_core.ChatEntryState
import uniffi.arcium_core.ChatSessionState
import uniffi.arcium_core.Conversation

/**
 * R-7 (d): a failed reload showed "Could not read the conversation", and the
 * error stayed after every later successful reload. A successful reload now
 * clears that read error, and only that one.
 */
class ChatStateReloadTest {

    private val entry = ChatEntry(1uL, true, ChatEntryState.PENDING, 1uL, byteArrayOf(0x61), PlaintextText("hi"))
    private val conversation = Conversation(
        ByteArray(32) { 1 }, "Bob", "fp", ChatSessionState.Established, false, false, "", 0u, entry,
    )

    @Test
    fun aSuccessfulReloadClearsTheReadError() {
        val failed = ChatState().afterFailedReload("database is locked")
        assertEquals("Could not read the conversation: database is locked", failed.error)
        val reloaded = failed.afterReload(conversation, listOf(entry))
        assertNull(reloaded.error)
        assertEquals(conversation, reloaded.conversation)
        assertEquals(listOf(entry), reloaded.entries)
    }

    @Test
    fun aSuccessfulReloadKeepsOtherErrors() {
        for (error in listOf("Not saved: busy. Send again to retry.", "Not resolved: no conflict")) {
            val reloaded = ChatState(error = error).afterReload(conversation, listOf(entry))
            assertEquals(error, reloaded.error)
        }
    }

    @Test
    fun aReloadChangesNothingElse() {
        val before = ChatState(input = "draft", sending = true)
        val after = before.afterReload(conversation, emptyList())
        assertEquals(before.copy(conversation = conversation), after)
    }
}
