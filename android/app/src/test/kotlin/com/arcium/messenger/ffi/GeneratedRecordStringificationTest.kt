package com.arcium.messenger.ffi

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.arcium_core.ChatEntry
import uniffi.arcium_core.ChatEntryState
import uniffi.arcium_core.ChatSessionState
import uniffi.arcium_core.Conversation
import uniffi.arcium_core.IncomingMessage
import uniffi.arcium_core.ReceiveResult
import uniffi.arcium_core.ReceivedText

/**
 * `toString` and string templates of the UniFFI-generated records that carry
 * message plaintext, built here from the generated classes themselves (no
 * native code runs). Before the plaintext fields used [PlaintextText] and
 * [PlaintextBytes], a data class printed a `String` field as is and a
 * `ByteArray` field as its decimal bytes. The canary must appear in none of
 * the forms a formatter could produce; ids and state must still appear.
 * `PlaintextStringificationInstrumentationTest` repeats this on values a real
 * receive returns, on a device.
 */
class GeneratedRecordStringificationTest {

    private val text = "ARCIUM-KOTLIN-PLAINTEXT-CANARY-5b2d"
    private val bytes = text.toByteArray()

    private fun assertHidden(rendered: String) {
        for (form in plaintextForms(bytes)) {
            assertFalse("plaintext form '$form' in: $rendered", rendered.contains(form))
        }
    }

    private fun entry() = ChatEntry(
        7uL, false, ChatEntryState.RECEIVED, 1_700_000_000_000uL, byteArrayOf(0x61), PlaintextText(text),
    )

    private fun incoming() = IncomingMessage(ByteArray(32) { 0x11 }, PlaintextBytes(bytes))

    @Test
    fun chatEntryAndConversationHideTheTextAndKeepTheMetadata() {
        val entry = entry()
        for (rendered in listOf(entry.toString(), "$entry", listOf(entry).toString())) {
            assertHidden(rendered)
            assertTrue(rendered, rendered.contains("seq=7") && rendered.contains("state=RECEIVED"))
        }
        val conversation = Conversation(
            ByteArray(32) { 1 }, "Bob", "fp", ChatSessionState.Established, false, false, "", 1u, entry,
        )
        assertHidden(conversation.toString())
        assertTrue(conversation.toString().contains("name=Bob"))
    }

    @Test
    fun incomingMessageAndReceiveResultsHideTheBytes() {
        val message = incoming()
        val results = listOf(
            message,
            ReceiveResult.Accepted(message),
            ReceiveResult.Duplicate(ByteArray(32) { 3 }, message),
            listOf(message),
        )
        for (value in results) {
            assertHidden(value.toString())
            assertHidden("$value")
            assertTrue(value.toString(), value.toString().contains("messageId="))
        }
    }

    @Test
    fun receivedTextHidesTheBytes() {
        val received = ReceivedText(ByteArray(32) { 4 }, PlaintextBytes(bytes))
        assertHidden(received.toString())
        assertHidden(listOf(received).toString())
        assertTrue(received.toString().contains("messageId="))
    }

    /** The wrappers change formatting only: the plaintext and equality stay. */
    @Test
    fun theWrappersStillCarryThePlaintext() {
        assertEquals(text, entry().text.value)
        assertArrayEquals(bytes, incoming().plaintext.bytes)
        assertEquals(PlaintextText(text), PlaintextText(text))
        assertEquals(PlaintextBytes(bytes), PlaintextBytes(bytes))
        assertEquals("<redacted>", PlaintextBytes(bytes).toString())
    }
}

/** Every rendering of [bytes] a formatter could produce. */
internal fun plaintextForms(bytes: ByteArray): List<String> = listOf(
    String(bytes),
    bytes.joinToString(", "),
    bytes.contentToString(),
    bytes.joinToString("") { "%02x".format(it) },
    bytes.joinToString("") { "%02X".format(it) },
)
