package com.arcium.messenger.ffi

import android.content.Context
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.arcium.messenger.debug.CrashVictimProvider
import java.io.File
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.arcium_core.CoreException
import uniffi.arcium_core.NetworkMessenger
import uniffi.arcium_core.SyncReport
import uniffi.arcium_core.contactCardFingerprint

/**
 * End-to-end encrypted messaging between this app on the emulator and an
 * independent peer on the CI host, through a real relay over the network
 * (docs/NET-MESSAGING.md). Mixed environment: one Android emulator and one
 * Linux host process — not two phones.
 *
 * The workflow starts `arcium-relay` and the peer (`net_peer_bot` in the
 * `mobile-ffi` tests) on the host and passes two instrumentation arguments:
 * `relay` (the relay as reachable from the emulator, 10.0.2.2:PORT) and
 * `peerCard` (the peer's contact card in hex — the out-of-band channel). The
 * peer answers every text `T` with `echo:T`, and goes away for N ms on
 * `cmd:offline:N`. Missing arguments fail the tests; they are never skipped.
 *
 * Every text carries [CANARY]; the relay alerts if it ever stores those
 * bytes, and the workflow fails on that alert.
 */
@RunWith(AndroidJUnit4::class)
class NetworkMessagingInstrumentationTest {

    private companion object {
        const val KEY: Byte = 0x61
        const val CANARY = "CANARY-PLAINTEXT-7f3a"
        const val WAIT_MS = 60_000L
    }

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val args = InstrumentationRegistry.getArguments()

    private val relay: String
        get() = checkNotNull(args.getString("relay")) {
            "instrumentation argument 'relay' is missing: run through android-instrumentation.yml, " +
                "which starts the host relay and peer"
        }

    private val peerCard: ByteArray
        get() = hex(
            checkNotNull(args.getString("peerCard")) { "instrumentation argument 'peerCard' is missing" },
        )

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    /** A fresh device: its own directory, database and identity. */
    private class Device(val dir: File, val db: String, val core: ArciumCoreWrapper)

    private fun device(): Device {
        val dir = File(context.filesDir, "arcium-net-test/${UUID.randomUUID()}")
        check(dir.mkdirs()) { "could not create $dir" }
        val db = File(dir, "app.db").absolutePath
        val core = ArciumCoreWrapper().apply {
            openEncryptedDb(db, ByteArray(32) { KEY })
            generateAndSaveIdentity()
        }
        return Device(dir, db, core)
    }

    private fun messenger(core: ArciumCoreWrapper, address: String = relay): NetworkMessenger =
        core.networkMessenger(address, retransmitAfterMs = 1_000u, timeoutMs = 5_000u)

    private fun text(s: String) = "$s $CANARY".toByteArray()

    /** Syncs until [done] holds, failing on sync errors or after [WAIT_MS]. */
    private fun syncUntil(net: NetworkMessenger, what: String, done: (SyncReport) -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + WAIT_MS
        while (true) {
            val r = net.sync()
            assertTrue("sync failed while waiting for $what: ${r.errors}", r.errors.isEmpty())
            if (done(r)) return
            check(SystemClock.elapsedRealtime() < deadline) { "timed out waiting for $what" }
            SystemClock.sleep(250)
        }
    }

    /** Pins the host peer, publishes our prekeys and starts a session; waits
     * for the peer's receipt of the session's OPEN message. */
    private fun connect(core: ArciumCoreWrapper, net: NetworkMessenger): ByteArray {
        val peer = core.addContact(peerCard)
        net.publishPrekeys()
        net.startSession(peer)
        syncUntil(net, "the peer to accept the session") { it.delivered > 0u }
        return peer
    }

    /** Waits for the peer's echo of [sent], marks it read and returns it. */
    private fun awaitEcho(net: NetworkMessenger, peer: ByteArray, sent: ByteArray): ByteArray {
        val expected = "echo:".toByteArray() + sent
        var echo: ByteArray? = null
        syncUntil(net, "the echo of '${String(sent)}'") {
            echo = net.receivedTexts(peer).firstOrNull { t -> t.text.contentEquals(expected) }?.also { t ->
                net.markRead(peer, t.messageId)
            }?.text
            echo != null
        }
        return echo!!
    }

    @Test
    fun aMessageReachesTheHostPeerAndItsReplyComesBack() {
        val d = device()
        val net = messenger(d.core)
        val peer = connect(d.core, net)
        assertTrue(contactCardFingerprint(peerCard).isNotEmpty())

        val hello = text("hello from android")
        net.sendText(peer, "hello".toByteArray(), hello)
        awaitEcho(net, peer, hello)
        syncUntil(net, "the peer's receipt") { net.undelivered(peer).isEmpty() }

        // A second round on the same session, both directions.
        val again = text("second")
        net.sendText(peer, "second".toByteArray(), again)
        awaitEcho(net, peer, again)

        // A different card for the pinned identity is refused.
        val forged = peerCard.copyOf().also { it[40] = (it[40].toInt() xor 1).toByte() }
        assertThrows(CoreException.ContactIdentityChanged::class.java) { d.core.addContact(forged) }
        d.core.closeEncryptedDb()
    }

    @Test
    fun textsSentWhileThePeerIsOfflineAreDeliveredWhenItReturns() {
        val d = device()
        val net = messenger(d.core)
        val peer = connect(d.core, net)
        net.sendText(peer, "offline".toByteArray(), "cmd:offline:10000".toByteArray())
        syncUntil(net, "the offline command's receipt") { net.undelivered(peer).isEmpty() }

        val queued = (1..3).map { text("queued $it") }
        queued.forEachIndexed { i, t -> net.sendText(peer, "q$i".toByteArray(), t) }
        repeat(4) {
            net.sync()
            SystemClock.sleep(250)
        }
        assertEquals("the relay accepting them is not delivery", 3, net.undelivered(peer).size)

        queued.forEach { awaitEcho(net, peer, it) }
        syncUntil(net, "every receipt") { net.undelivered(peer).isEmpty() }
        d.core.closeEncryptedDb()
    }

    @Test
    fun anUnreachableRelayLosesNothing() {
        val d = device()
        val net = messenger(d.core)
        val peer = connect(d.core, net)
        val body = text("while the network is down")
        net.sendText(peer, "down".toByteArray(), body)

        // Nothing listens on port 9 of the host: the connection is refused.
        val cut = messenger(d.core, relay.substringBefore(':') + ":9").sync()
        assertFalse("the failure is reported", cut.errors.isEmpty())
        assertEquals(1, net.undelivered(peer).size)

        awaitEcho(net, peer, body)
        syncUntil(net, "the receipt") { net.undelivered(peer).isEmpty() }
        d.core.closeEncryptedDb()
    }

    /**
     * The app process is killed after committing a text and before any
     * network I/O. After the restart the stored bytes are sent, delivered and
     * answered, and the session keeps working in both directions.
     */
    @Test
    fun aTextCommittedBeforeTheProcessWasKilledIsSentAfterRestart() {
        val d = device()
        val peer = connect(d.core, messenger(d.core))
        d.core.closeEncryptedDb()
        val body = text("committed before the kill")
        File(d.dir, "peer").writeBytes(peer)
        File(d.dir, "clientId").writeBytes("killed".toByteArray())
        File(d.dir, "plaintext").writeBytes(body)
        runInVictimProcess(context, d.dir, CrashVictimProvider.SCENARIO_NET_SEND, d.db, KEY, 0u)

        val core = ArciumCoreWrapper().apply { openEncryptedDb(d.db, ByteArray(32) { KEY }) }
        val net = messenger(core)
        assertEquals("the text survived the kill", 1, net.undelivered(peer).size)
        awaitEcho(net, peer, body)
        syncUntil(net, "the receipt") { net.undelivered(peer).isEmpty() }

        val after = text("after restart")
        net.sendText(peer, "after".toByteArray(), after)
        awaitEcho(net, peer, after)
        core.closeEncryptedDb()
    }
}
