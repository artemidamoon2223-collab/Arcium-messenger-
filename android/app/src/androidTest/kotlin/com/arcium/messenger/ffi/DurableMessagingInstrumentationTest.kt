package com.arcium.messenger.ffi

import android.app.ActivityManager
import android.content.Context
import android.os.Bundle
import android.os.RemoteException
import android.os.SystemClock
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
        const val VICTIM_TIMEOUT_MS = 30_000L
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

    /**
     * Runs [scenario] in the `:victim` process and waits for that process to
     * be gone. Fails if the victim reported an error.
     */
    private fun runVictim(w: Workspace, scenario: String, db: String, key: Byte, session: ULong) {
        val extras = Bundle().apply {
            putString(CrashVictimProvider.KEY_DIR, w.dir.absolutePath)
            putString(CrashVictimProvider.KEY_DB, db)
            putByte(CrashVictimProvider.KEY_MASTER_BYTE, key)
            putLong(CrashVictimProvider.KEY_SESSION, session.toLong())
        }
        val client = checkNotNull(
            context.contentResolver.acquireUnstableContentProviderClient(CrashVictimProvider.AUTHORITY),
        ) { "victim provider not found — is this a debug build?" }
        try {
            client.call(CrashVictimProvider.METHOD_RUN, scenario, extras)
            throw AssertionError("the victim returned instead of dying")
        } catch (expected: RemoteException) {
            // The victim process died during the call, as intended
            // (DeadObjectException). Checked below: it finished its operation
            // and is gone.
        } finally {
            client.close()
        }
        val victim = context.packageName + CrashVictimProvider.PROCESS_SUFFIX
        val am = context.getSystemService(ActivityManager::class.java)
        val deadline = SystemClock.elapsedRealtime() + VICTIM_TIMEOUT_MS
        while (am.runningAppProcesses.orEmpty().any { it.processName == victim }) {
            check(SystemClock.elapsedRealtime() < deadline) { "victim process still alive" }
            SystemClock.sleep(50)
        }
        val error = File(w.dir, "error")
        check(!error.exists()) { "victim failed: ${error.readText()}" }
        check(File(w.dir, "done").exists()) { "victim died before finishing its operation" }
    }

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
            val m = alice.sendMessage(p.aliceHandle, bytes("to bob $round"))
            assertArrayEquals(bytes("to bob $round"), accepted(bob.receiveMessage(p.bobHandle, m.wire)))
            val r = bob.sendMessage(p.bobHandle, bytes("to alice $round"))
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
            val m = sender.sendMessage(p.aliceHandle, bytes("m$i"))
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
        File(w.dir, "plaintext").writeBytes(bytes("sent before the crash"))
        runVictim(w, CrashVictimProvider.SCENARIO_SEND, w.aliceDb, ALICE_KEY, p.aliceHandle)
        val published = File(w.dir, "published").readBytes()

        val alice = open(w.aliceDb, ALICE_KEY)
        val bob = open(w.bobDb, BOB_KEY)
        val pending = alice.pendingOutgoing(p.aliceHandle)
        assertEquals(1, pending.size)
        assertArrayEquals("byte-identical across the crash", published, pending[0].wire)

        assertArrayEquals(bytes("sent before the crash"), accepted(bob.receiveMessage(p.bobHandle, published)))
        val again = bob.receiveMessage(p.bobHandle, pending[0].wire)
        assertTrue("a retransmission is a duplicate", again is ReceiveResult.Duplicate)
        assertTrue(alice.acknowledgeOutgoing(p.aliceHandle, pending[0].messageId))
        assertTrue(alice.pendingOutgoing(p.aliceHandle).isEmpty())

        val reply = bob.sendMessage(p.bobHandle, bytes("reply after restart"))
        assertArrayEquals(bytes("reply after restart"), accepted(alice.receiveMessage(p.aliceHandle, reply.wire)))
        val more = alice.sendMessage(p.aliceHandle, bytes("and onwards"))
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
        val wire = alice.sendMessage(p.aliceHandle, bytes("received before the crash")).wire
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

        val reply = bob.sendMessage(p.bobHandle, bytes("reply after restart"))
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
        val m = alice.sendMessage(aliceHandle, bytes("first after restart"))
        assertArrayEquals(bytes("first after restart"), accepted(restarted.receiveMessage(bobHandle, m.wire)))
        val r = restarted.sendMessage(bobHandle, bytes("responder replies"))
        assertArrayEquals(bytes("responder replies"), accepted(alice.receiveMessage(aliceHandle, r.wire)))
    }
}
