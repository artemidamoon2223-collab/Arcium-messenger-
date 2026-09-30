package com.arcium.messenger.ffi

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.arcium_core.ArciumCore
import uniffi.arcium_core.ChatEntryState
import uniffi.arcium_core.Identity
import uniffi.arcium_core.NetworkMessenger
import uniffi.arcium_core.ReceiveResult
import uniffi.arcium_core.SendResult
import uniffi.arcium_core.localSessionHandle

/**
 * The generated records that carry message plaintext, as a real exchange
 * returns them through Rust → UniFFI → Kotlin on Android, formatted with
 * `toString` and string templates: the text must not appear in any form a
 * formatter could produce (see `GeneratedRecordStringificationTest`).
 *
 * No relay: Alice's committed wire bytes are handed to Bob here, and the chat
 * entries come from the local stores. Nothing is mocked; every value below was
 * produced by the native library.
 */
@RunWith(AndroidJUnit4::class)
class PlaintextStringificationInstrumentationTest {

    private val text = "ARCIUM-KOTLIN-PLAINTEXT-CANARY-9e41"

    private class Device(dir: File, name: String, keyByte: Byte) {
        val core = ArciumCore(File(dir, "$name.db").absolutePath, ByteArray(32) { keyByte })
        val net: NetworkMessenger
        val pk: ByteArray

        init {
            core.saveIdentity(Identity.generate())
            core.establishPrekeys()
            net = NetworkMessenger(core, "127.0.0.1:1", 0uL, 1000uL)
            pk = core.contactCard().copyOfRange(1, 33)
        }
    }

    private fun assertHidden(value: Any) {
        for (rendered in listOf(value.toString(), "$value")) {
            for (form in forms(text.toByteArray())) {
                assertFalse("plaintext form '$form' in: $rendered", rendered.contains(form))
            }
        }
    }

    private fun forms(bytes: ByteArray) = listOf(
        String(bytes),
        bytes.joinToString(", "),
        bytes.contentToString(),
        bytes.joinToString("") { "%02x".format(it) },
        bytes.joinToString("") { "%02X".format(it) },
    )

    @Test
    fun whatARealReceiveReturnsDoesNotPrintTheText() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val dir = File(context.cacheDir, "arcium-stringification/${UUID.randomUUID()}")
        check(dir.mkdirs())
        val alice = Device(dir, "alice", 0x31)
        val bob = Device(dir, "bob", 0x32)
        alice.net.addNamedContact(bob.core.contactCard(), "Bob")
        bob.net.addNamedContact(alice.core.contactCard(), "Alice")

        // A session under each side's handle for the other, as the network
        // layer keys it; Alice's text is committed through send_text.
        val toBob = localSessionHandle(bob.pk)
        val toAlice = localSessionHandle(alice.pk)
        val handshake = alice.core.establishSessionInitiator(toBob, bob.core.exportPrekeyBundle())
        bob.core.establishSessionResponder(toAlice, handshake)
        alice.net.sendText(bob.pk, "t-1".toByteArray(), text.toByteArray())
        val wire = alice.core.pendingOutgoing(toBob).single().wire

        val accepted = bob.core.receiveMessage(toAlice, wire)
        assertTrue(accepted is ReceiveResult.Accepted)
        assertHidden(accepted)
        val duplicate = bob.core.receiveMessage(toAlice, wire)
        assertTrue(duplicate is ReceiveResult.Duplicate && duplicate.undelivered != null)
        assertHidden(duplicate)
        assertHidden(bob.core.pendingIncoming(toAlice))

        val received = bob.net.receivedTexts(alice.pk)
        assertArrayEquals(text.toByteArray(), received.single().text.bytes)
        assertHidden(received)

        // Into Bob's history (this marks it read), and an entry Alice queues.
        val history = bob.net.chatEntries(alice.pk)
        assertEquals(text, history.single().text.value)
        assertEquals(ChatEntryState.RECEIVED, history.single().state)
        assertHidden(history)
        assertHidden(bob.net.conversation(alice.pk))
        val queued = alice.net.chatSend(bob.pk, "c-1".toByteArray(), text)
        assertEquals(text, queued.text.value)
        assertHidden(queued)
        assertHidden(alice.net.conversations())

        // Control: the outgoing message is ciphertext, and its wire bytes are
        // printed as they always were.
        val sent = alice.core.sendMessage(toBob, "control".toByteArray(), "x".toByteArray())
        assertTrue(sent is SendResult.Sent && sent.toString().contains("wire=["))
    }
}
