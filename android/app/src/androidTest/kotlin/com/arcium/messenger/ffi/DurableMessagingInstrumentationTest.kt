package com.arcium.messenger.ffi

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.arcium.messenger.data.MessageRepository
import com.arcium.messenger.debug.CrashVictimProvider
import java.io.File
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.arcium_core.CoreException
import uniffi.arcium_core.ReceiveResult
import uniffi.arcium_core.SendResult

/**
 * S2-B2 on an Android runtime: sessions and messages survive the store being
 * reopened and the process that held it being killed.
 *
 * Process death is real. `CrashVictimProvider` (debug builds only) runs in a
 * separate app process, `:victim`, performs one messaging operation through
 * the same JNA → `libarcium_core.so` path the app uses, records what the
 * operation returned, and kills itself with SIGKILL before acknowledging or
 * closing anything. This test process then opens the same database — the
 * state a restarted app would see — and checks it.
 *
 * What this does not show: behaviour under power loss, or on a physical
 * device's storage. The emulator's disk is not a phone's flash.
 */
@RunWith(AndroidJUnit4::class)
class DurableMessagingInstrumentationTest {

    private companion object {
        const val PUBLIC_KEY_BYTES = 32
        const val IDENTITY_OFFSET = 4
        const val ALICE_KEY: Byte = 0x71
        const val BOB_KEY: Byte = 0x72
    }

    private val context: Context =
        InstrumentationRegistry.getInstrumentation().targetContext

    /** One test's databases and victim input/output files. */
    private class Workspace(val dir: File) {
        val aliceDb = File(dir, "alice.db").absolutePath
        val bobDb = File(dir, "bob.db").absolutePath
    }

    private fun workspace(): Workspace {
        val dir = File(context.filesDir, "arcium-durable-test/${UUID.randomUUID()}")
        check(dir.mkdirs()) { "could not create $dir" }
        return Workspace(dir)
    }

    private fun open(db: String, key: Byte) =
        ArciumCoreWrapper().apply { openEncryptedDb(db, ByteArray(32) { key }) }

    private fun identityAt(bytes: ByteArray) =
        bytes.copyOfRange(IDENTITY_OFFSET, IDENTITY_OFFSET + PUBLIC_KEY_BYTES)

    /** Identities and local handles of an Alice ↔ Bob session. */
    private class Pair(
        val aliceIdentity: ByteArray,
        val bobIdentity: ByteArray,
        val aliceHandle: ULong, // Alice's handle for Bob
        val bobHandle: ULong,   // Bob's handle for Alice
    )

    /** Creates both identities and the session, then closes both stores. */
    private fun establish(w: Workspace): Pair {
        val alice = open(w.aliceDb, ALICE_KEY)
        val bob = open(w.bobDb, BOB_KEY)
        alice.generateAndSaveIdentity()
        bob.generateAndSaveIdentity()
        val bobRepo = MessageRepository(bob)
        bobRepo.publishOwnPrekeys()
        val bundle = bobRepo.ownPrekeyBundle()
        val bobIdentity = identityAt(bundle)
        val handshake = MessageRepository(alice).startSessionAsInitiator(bobIdentity, bundle)
        val aliceIdentity = identityAt(handshake)
        bobRepo.acceptSessionAsResponder(aliceIdentity, handshake)
        val pair = Pair(
            aliceIdentity,
            bobIdentity,
            alice.localSessionHandle(bobIdentity),
            bob.localSessionHandle(aliceIdentity),
        )
        alice.closeEncryptedDb()
        bob.closeEncryptedDb()
        return pair
    }

    private fun accepted(r: ReceiveResult): ByteArray = when (r) {
        is ReceiveResult.Accepted -> r.message.plaintext
        is ReceiveResult.Duplicate -> throw AssertionError("expected a new message, got a duplicate")
    }

    private fun bytes(s: String) = s.toByteArray()

    /** A first send of a new logical message; its committed outgoing message. */
    private fun sendNew(
        core: ArciumCoreWrapper,
        session: ULong,
        plaintext: ByteArray,
        clientId: ByteArray = UUID.randomUUID().toString().toByteArray(),
    ) =
        when (val r = core.sendMessage(session, clientId, plaintext)) {
            is SendResult.Sent -> r.message
            else -> throw AssertionError("expected a new message, got $r")
        }

    private fun runVictim(w: Workspace, scenario: String, db: String, key: Byte, session: ULong) =
        runInVictimProcess(context, w.dir, scenario, db, key, session)

    // ── Reopening ─────────────────────────────────────────────────────────────

    @Test
    fun sessionsAndMessagesSurviveReopeningTheStores() {
        val w = workspace()
        val p = establish(w)
        repeat(3) { round ->
            val alice = open(w.aliceDb, ALICE_KEY)
            val bob = open(w.bobDb, BOB_KEY)
            assertTrue(alice.hasSession(p.aliceHandle))
            assertTrue(bob.hasSession(p.bobHandle))
            val m = sendNew(alice, p.aliceHandle, bytes("to bob $round"))
            assertArrayEquals(bytes("to bob $round"), accepted(bob.receiveMessage(p.bobHandle, m.wire)))
            val r = sendNew(bob, p.bobHandle, bytes("to alice $round"))
            alice.closeEncryptedDb()
            val reopened = open(w.aliceDb, ALICE_KEY)
            assertArrayEquals(bytes("to alice $round"), accepted(reopened.receiveMessage(p.aliceHandle, r.wire)))
            reopened.closeEncryptedDb()
            bob.closeEncryptedDb()
        }
    }

    /**
     * Two wrappers on one store — what reopening without closing produces.
     * Neither caches the session, so alternating between them does not fork it.
     */
    @Test
    fun twoHandlesOnOneStoreDoNotForkTheSession() {
        val w = workspace()
        val p = establish(w)
        val a1 = open(w.aliceDb, ALICE_KEY)
        val a2 = open(w.aliceDb, ALICE_KEY)
        val bob = open(w.bobDb, BOB_KEY)
        for (i in 0 until 6) {
            val sender = if (i % 2 == 0) a1 else a2
            val m = sendNew(sender, p.aliceHandle, bytes("m$i"))
            assertArrayEquals(bytes("m$i"), accepted(bob.receiveMessage(p.bobHandle, m.wire)))
        }
        assertEquals(6, a1.pendingOutgoing(p.aliceHandle).size)
    }

    // ── Process death ─────────────────────────────────────────────────────────

    /**
     * Killed after the message was committed and handed out, before any
     * acknowledgement. After restart the outbox holds the byte-identical
     * message, the peer accepts it once, and both directions keep working.
     */
    @Test
    fun killedAfterSendingTheMessageIsResentByteForByte() {
        val w = workspace()
        val p = establish(w)
        File(w.dir, "clientId").writeBytes(bytes("logical-send-1"))
        File(w.dir, "plaintext").writeBytes(bytes("sent before the crash"))
        runVictim(w, CrashVictimProvider.SCENARIO_SEND, w.aliceDb, ALICE_KEY, p.aliceHandle)
        val published = File(w.dir, "published").readBytes()

        val alice = open(w.aliceDb, ALICE_KEY)
        val bob = open(w.bobDb, BOB_KEY)
        val pending = alice.pendingOutgoing(p.aliceHandle)
        assertEquals(1, pending.size)
        assertArrayEquals("byte-identical across the crash", published, pending[0].wire)
        // The restarted app, unsure whether its send took effect, sends the
        // same logical message again: it gets the stored bytes, not a new
        // ciphertext.
        val repeated = alice.sendMessage(p.aliceHandle, bytes("logical-send-1"), bytes("sent before the crash"))
        assertTrue("a repeated logical send must not encrypt again", repeated is SendResult.AlreadyPending)
        assertArrayEquals(published, (repeated as SendResult.AlreadyPending).message.wire)
        assertEquals(1, alice.pendingOutgoing(p.aliceHandle).size)

        assertArrayEquals(bytes("sent before the crash"), accepted(bob.receiveMessage(p.bobHandle, published)))
        val again = bob.receiveMessage(p.bobHandle, pending[0].wire)
        assertTrue("a retransmission is a duplicate", again is ReceiveResult.Duplicate)
        assertTrue(alice.acknowledgeOutgoing(p.aliceHandle, pending[0].messageId))
        assertTrue(alice.pendingOutgoing(p.aliceHandle).isEmpty())

        val reply = sendNew(bob, p.bobHandle, bytes("reply after restart"))
        assertArrayEquals(bytes("reply after restart"), accepted(alice.receiveMessage(p.aliceHandle, reply.wire)))
        val more = sendNew(alice, p.aliceHandle, bytes("and onwards"))
        assertArrayEquals(bytes("and onwards"), accepted(bob.receiveMessage(p.bobHandle, more.wire)))
    }

    /**
     * Killed after the message was committed and its plaintext returned,
     * before the app showed or acknowledged it. After restart it is still
     * pending, a redelivery is a duplicate, and acknowledgement is idempotent.
     */
    @Test
    fun killedBeforeShowingTheMessageItIsStillPending() {
        val w = workspace()
        val p = establish(w)
        val alice = open(w.aliceDb, ALICE_KEY)
        val wire = sendNew(alice, p.aliceHandle, bytes("received before the crash")).wire
        File(w.dir, "wire").writeBytes(wire)
        runVictim(w, CrashVictimProvider.SCENARIO_RECEIVE, w.bobDb, BOB_KEY, p.bobHandle)

        val bob = open(w.bobDb, BOB_KEY)
        val pending = bob.pendingIncoming(p.bobHandle)
        assertEquals(1, pending.size)
        assertArrayEquals(bytes("received before the crash"), pending[0].plaintext)
        val dup = bob.receiveMessage(p.bobHandle, wire)
        assertTrue(dup is ReceiveResult.Duplicate && dup.undelivered != null)

        assertTrue(bob.acknowledgeIncoming(p.bobHandle, pending[0].messageId))
        assertFalse(bob.acknowledgeIncoming(p.bobHandle, pending[0].messageId))
        assertTrue(bob.pendingIncoming(p.bobHandle).isEmpty())
        val after = bob.receiveMessage(p.bobHandle, wire)
        assertTrue(after is ReceiveResult.Duplicate && after.undelivered == null)

        val reply = sendNew(bob, p.bobHandle, bytes("reply after restart"))
        assertArrayEquals(bytes("reply after restart"), accepted(alice.receiveMessage(p.aliceHandle, reply.wire)))
    }

    /**
     * Killed right after answering a handshake. After restart the responder
     * session exists and works, and the consumed one-time prekey is not
     * available to the same handshake again.
     */
    @Test
    fun killedAfterAnsweringAHandshakeTheSessionIsRestored() {
        val w = workspace()
        val alice = open(w.aliceDb, ALICE_KEY)
        val bob = open(w.bobDb, BOB_KEY)
        alice.generateAndSaveIdentity()
        bob.generateAndSaveIdentity()
        val bobRepo = MessageRepository(bob)
        bobRepo.publishOwnPrekeys()
        val bundle = bobRepo.ownPrekeyBundle()
        val bobIdentity = identityAt(bundle)
        val handshake = MessageRepository(alice).startSessionAsInitiator(bobIdentity, bundle)
        val aliceIdentity = identityAt(handshake)
        val bobHandle = bob.localSessionHandle(aliceIdentity)
        val aliceHandle = alice.localSessionHandle(bobIdentity)
        bob.closeEncryptedDb()
        File(w.dir, "handshake").writeBytes(handshake)

        runVictim(w, CrashVictimProvider.SCENARIO_RESPOND, w.bobDb, BOB_KEY, bobHandle)

        val restarted = open(w.bobDb, BOB_KEY)
        assertTrue(restarted.hasSession(bobHandle))
        assertNull("a responder stores no handshake to resend", restarted.initiatorHandshake(bobHandle))
        assertThrows(CoreException.OneTimePrekeyUnavailable::class.java) {
            restarted.establishSessionResponder(bobHandle + 1uL, handshake)
        }
        val m = sendNew(alice, aliceHandle, bytes("first after restart"))
        assertArrayEquals(bytes("first after restart"), accepted(restarted.receiveMessage(bobHandle, m.wire)))
        val r = sendNew(restarted, bobHandle, bytes("responder replies"))
        assertArrayEquals(bytes("responder replies"), accepted(alice.receiveMessage(aliceHandle, r.wire)))
    }

    /**
     * The responder refuses the initiator's handshake because its prekeys
     * rotated first. The initiator abandons what it sent, removes the stranded
     * session in a process that is then killed, and after the restart
     * establishes a working one with the peer's fresh bundle. The abandoned
     * logical message is not encrypted again, and once both sides have
     * talked neither session can be removed.
     */
    @Test
    fun aRefusedHandshakeIsReplacedAfterRemovingTheSession() {
        val w = workspace()
        val alice = open(w.aliceDb, ALICE_KEY)
        val bob = open(w.bobDb, BOB_KEY)
        alice.generateAndSaveIdentity()
        bob.generateAndSaveIdentity()
        val bobRepo = MessageRepository(bob)
        val aliceRepo = MessageRepository(alice)
        bobRepo.publishOwnPrekeys()
        val bundle = bobRepo.ownPrekeyBundle()
        val bobIdentity = identityAt(bundle)
        val handshake = aliceRepo.startSessionAsInitiator(bobIdentity, bundle)
        val aliceIdentity = identityAt(handshake)
        val aliceHandle = alice.localSessionHandle(bobIdentity)
        val orphan = sendNew(alice, aliceHandle, bytes("never read"), bytes("orphan"))
        bobRepo.publishOwnPrekeys() // rotation before the handshake arrives
        assertThrows(CoreException.StaleSignedPrekey::class.java) {
            bobRepo.acceptSessionAsResponder(aliceIdentity, handshake)
        }
        val fresh = bobRepo.ownPrekeyBundle()
        assertThrows(CoreException.SessionAlreadyExists::class.java) {
            aliceRepo.startSessionAsInitiator(bobIdentity, fresh)
        }
        assertThrows(CoreException.PendingOutgoing::class.java) {
            aliceRepo.removeSessionWith(bobIdentity)
        }
        assertTrue(aliceRepo.abandonUndelivered(bobIdentity, orphan.messageId))
        alice.closeEncryptedDb()

        runVictim(w, CrashVictimProvider.SCENARIO_REMOVE, w.aliceDb, ALICE_KEY, aliceHandle)

        val restarted = open(w.aliceDb, ALICE_KEY)
        assertFalse(restarted.hasSession(aliceHandle))
        val restartedRepo = MessageRepository(restarted)
        val handshake2 = restartedRepo.startSessionAsInitiator(bobIdentity, fresh)
        bobRepo.acceptSessionAsResponder(aliceIdentity, handshake2)
        val repeated = restarted.sendMessage(aliceHandle, bytes("orphan"), bytes("never read"))
        assertTrue("an abandoned logical message must not be encrypted again", repeated is SendResult.Abandoned)
        val m = sendNew(restarted, aliceHandle, bytes("after replacement"))
        val bobHandle = bob.localSessionHandle(aliceIdentity)
        assertArrayEquals(bytes("after replacement"), accepted(bob.receiveMessage(bobHandle, m.wire)))
        val r = sendNew(bob, bobHandle, bytes("reply"))
        assertArrayEquals(bytes("reply"), accepted(restarted.receiveMessage(aliceHandle, r.wire)))
        assertThrows(CoreException.SessionEstablished::class.java) {
            restartedRepo.removeSessionWith(bobIdentity)
        }
        assertThrows(CoreException.SessionEstablished::class.java) {
            bobRepo.removeSessionWith(aliceIdentity)
        }
    }
}
