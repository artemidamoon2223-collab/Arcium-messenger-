package com.arcium.messenger.ui.chat

import com.arcium.messenger.ffi.PlaintextText
import com.arcium.messenger.ffi.plaintextForms
import com.arcium.messenger.messaging.RelayLink
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.arcium_core.ChatEntry
import uniffi.arcium_core.ChatEntryState
import uniffi.arcium_core.ChatSessionState
import uniffi.arcium_core.Conversation

/**
 * `toString` and string templates of [ChatState], whose [ChatState.input] is
 * the user's unsent draft. The generated `toString` of a data class printed it
 * as is (H-15). The draft must appear in none of the forms a formatter could
 * produce, and must not change the rendering at all; the other fields and the
 * data-class behaviour the screen relies on must stay.
 */
class ChatStateStringificationTest {

    private val draft = "ARCIUM-DRAFT-CANARY-h15-7e1c"

    /** Non-ASCII text, a newline, a tab and an emoji: no other rendering leaks. */
    private val unicodeDraft = "Привет, ARCIUM-DRAFT-CANARY-h15-ü\nвторая строка\t🔒"

    private fun forms(text: String): List<String> =
        plaintextForms(text.toByteArray()) + text.lines().filter { it.isNotBlank() } +
            text.replace("\n", "\\n").replace("\t", "\\t")

    private fun assertHidden(text: String, rendered: String) {
        for (form in forms(text)) {
            assertFalse("draft form '$form' in: $rendered", rendered.contains(form))
        }
    }

    @Test
    fun toStringAndTemplatesHideTheDraft() {
        for (text in listOf(draft, unicodeDraft)) {
            val state = ChatState(input = text)
            for (rendered in listOf(state.toString(), "$state", listOf(state).toString())) {
                assertHidden(text, rendered)
                assertTrue(rendered, rendered.contains("input=<redacted>"))
            }
        }
    }

    /** Empty and non-empty drafts render the same, so the length does not show either. */
    @Test
    fun theRenderingDoesNotDependOnTheDraft() {
        val empty = ChatState().toString()
        assertTrue(empty, empty.contains("input=<redacted>"))
        assertEquals(empty, ChatState(input = draft).toString())
        assertEquals(empty, ChatState(input = unicodeDraft).toString())
    }

    @Test
    fun theOtherFieldsStillShow() {
        val rendered = ChatState(
            link = RelayLink.Online(5L),
            input = draft,
            sending = true,
            error = "Not saved: busy",
        ).toString()
        assertTrue(rendered, rendered.startsWith("ChatState("))
        val parts = listOf(
            "conversation=null", "entries=[]", "link=Online(atMs=5)", "sending=true", "error=Not saved: busy",
        )
        for (part in parts) {
            assertTrue("'$part' missing in: $rendered", rendered.contains(part))
        }
    }

    /** The message plaintext in nested records stays hidden (H-14) inside a state. */
    @Test
    fun nestedEntriesAndConversationStayRedacted() {
        val text = "ARCIUM-KOTLIN-PLAINTEXT-CANARY-h15-nested"
        val entry = ChatEntry(
            7uL, false, ChatEntryState.RECEIVED, 1_700_000_000_000uL, byteArrayOf(0x61), PlaintextText(text),
        )
        val conversation = Conversation(
            ByteArray(32) { 1 }, "Bob", "fp", ChatSessionState.Established, false, false, "", 1u, entry,
        )
        val state = ChatState(conversation = conversation, entries = listOf(entry), input = draft)
        for (rendered in listOf(state.toString(), "$state")) {
            assertHidden(text, rendered)
            assertHidden(draft, rendered)
            assertTrue(rendered, rendered.contains("seq=7") && rendered.contains("name=Bob"))
        }
    }

    /** The draft itself, copy, equality and destructuring behave as in a data class. */
    @Test
    fun dataClassBehaviourIsUnchanged() {
        val state = ChatState(input = draft)
        assertEquals(draft, state.input)
        assertEquals(unicodeDraft, state.copy(input = unicodeDraft).input)
        assertEquals("", state.copy(input = "").input)
        assertEquals(state, ChatState(input = draft))
        assertEquals(state.hashCode(), ChatState(input = draft).hashCode())
        assertNotEquals(state, state.copy(input = "$draft "))
        assertNotEquals(state, state.copy(sending = true))
        val (conversation, entries, link, input, sending, error) = state
        assertEquals(
            listOf(null, emptyList<ChatEntry>(), RelayLink.NotConfigured, draft, false, null),
            listOf(conversation, entries, link, input, sending, error),
        )
    }
}
