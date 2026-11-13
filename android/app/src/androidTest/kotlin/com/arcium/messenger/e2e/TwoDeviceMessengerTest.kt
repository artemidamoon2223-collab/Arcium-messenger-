package com.arcium.messenger.e2e

import android.os.Bundle
import android.os.ParcelFileDescriptor
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.ComposeTimeoutException
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isRoot
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.arcium.messenger.ArciumApp
import com.arcium.messenger.MainActivity
import com.arcium.messenger.messaging.ContactCardText
import com.arcium.messenger.messaging.MessengerService
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.Socket
import java.security.SecureRandom
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.arcium_core.ChatEntryState
import uniffi.arcium_core.ChatSessionState
import uniffi.arcium_core.SyncReport
import uniffi.arcium_core.contactCardFingerprint

/**
 * Two people messaging through the real app on two independent Android
 * emulators, each with its own identity, encrypted database and process.
 *
 * Each test is one step of one user; `android/e2e/two_devices.py` runs them
 * with `am instrument` on the right emulator, in order or side by side, and
 * passes what a user would have: the relay address, and the contact's card,
 * fingerprint and name as shown on the contact's own screen (the out-of-band
 * channel). Steps drive the screens; the Rust store is read from this same
 * app process to count what the screens show, and the steps named below go
 * further.
 *
 * Every text carries [CANARY]; the relay alerts if it ever stores those
 * bytes, and the workflow fails on that alert. Missing arguments fail a step;
 * nothing is skipped.
 *
 * Some steps also act as the untrusted relay or call the messenger directly,
 * to reach a boundary the screens cannot: [aKeyMismatchOnTheRelayIsRefusedAndShown]
 * publishes a bundle, [aliceSendsWhileBobIsOffline] reads what the relay holds
 * for Bob, [bobIgnoresReplayedEnvelopes] sends old envelopes to Bob again,
 * [everyTextIsInTheHistoryOnceAfterRepeatedSyncs] runs sync rounds itself and
 * reads both mailboxes, and [theFinalChecksRejectViolatedFixtures] uses a
 * mailbox of its own. The two that sync do so on the app's own sync thread
 * ([exclusive]), so no round of the app's loop runs between their rounds and
 * their checks.
 */
@RunWith(AndroidJUnit4::class)
class TwoDeviceMessengerTest {

    @get:Rule
    val rule = createAndroidComposeRule<MainActivity>()

    private companion object {
        const val CANARY = "CANARY-PLAINTEXT-7f3a"
        const val WAIT_MS = 180_000L
        const val UI_MS = 20_000L
        const val DATA_CODE = 42

        /** Every text of the Alice–Bob conversation, and whether Alice wrote it. */
        val CONVERSATION = listOf(
            "hello bob" to true, "hi alice" to false, "queued 1" to true, "queued 2" to true,
            "queued 3" to true, "after restart" to false, "welcome back" to true, "before the kill" to true,
            "during the outage" to true, "before publishing" to true, "while bob restarts" to true,
        )

        /** A sync round that sent, fetched and changed nothing. */
        val IDLE = SyncReport(
            published = 0u, fetched = 0u, accepted = 0u, duplicates = 0u, sessionsAccepted = 0u,
            delivered = 0u, dropped = 0u, deferred = 0u, errors = emptyList(),
        )
    }

    private val args = InstrumentationRegistry.getArguments()

    private fun arg(name: String): String =
        checkNotNull(args.getString(name)) { "instrumentation argument '$name' is missing" }

    private val peerName get() = arg("peerName")
    private val peerCard get() = checkNotNull(ContactCardText.decode(arg("peerCard")))
    private val peerKey get() = peerCard.copyOfRange(1, 33)
    private val myName get() = if (peerName == "Bob") "Alice" else "Bob"

    /** This device's mailbox on the relay: the X25519 key in its own card. */
    private val myKey get() = ArciumApp.core.contactCard().copyOfRange(1, 33)

    private fun text(s: String) = "$s $CANARY"

    /** Every step starts in a new app process; its pid goes to the driver's log. */
    @Before
    fun reportProcess() = report()

    // ── Steps ───────────────────────────────────────────────────────────────

    /** A new user creates an identity, sets the relay and reads their card. */
    @Test
    fun onboard() {
        tap("createIdentity")
        waitFor("openAddContact")
        tap("openSettings")
        rule.onNodeWithTag("relayInput").performTextClearance()
        rule.onNodeWithTag("relayInput").performTextInput(arg("relay"))
        tap("saveRelay")
        assertEquals("Using ${arg("relay")}", textOf("savedRelay"))
        tap("settingsBack")
        // A round reached the relay: the prekey bundle is published.
        waitForText("Connected to the development relay", WAIT_MS)
        tap("openAddContact")
        waitFor("myCard")
        val card = textOf("myCard")
        val fingerprint = textOf("myFingerprint")
        assertEquals(fingerprint, contactCardFingerprint(checkNotNull(ContactCardText.decode(card))))
        report("card" to card, "fingerprint" to fingerprint)
    }

    /**
     * Adds the contact from the card they sent, after comparing fingerprints
     * with the one on their screen; then shows that a different card for the
     * same identity is refused and changes nothing.
     */
    @Test
    fun addContact() {
        tap("openAddContact")
        waitFor("cardInput")
        rule.onNodeWithTag("cardInput").performTextInput("not a card")
        waitForText("Not an Arcium contact card", UI_MS)
        rule.onNodeWithTag("cardInput").performTextClearance()
        rule.onNodeWithTag("cardInput").performTextInput(arg("peerCard"))
        waitFor("theirFingerprint")
        assertEquals("the fingerprint this device computed", arg("peerFingerprint"), textOf("theirFingerprint"))
        tap("fingerprintsMatch")
        rule.onNodeWithTag("contactName").performTextInput(peerName)
        tap("addContact")
        waitFor("messageInput")

        // An impostor's card: the contact's X25519 key, another signing key.
        rule.activityRule.scenario.onActivity { it.onBackPressedDispatcher.onBackPressed() }
        waitFor("openAddContact")
        tap("openAddContact")
        val forged = peerCard.copyOf().also { it[40] = (it[40].toInt() xor 1).toByte() }
        rule.onNodeWithTag("cardInput").performTextInput(ContactCardText.encode(forged))
        waitFor("theirFingerprint")
        assertNotEquals(arg("peerFingerprint"), textOf("theirFingerprint"))
        tap("fingerprintsMatch")
        rule.onNodeWithTag("contactName").performTextInput(peerName)
        tap("addContact")
        waitForText("a different card is already verified", UI_MS)
        val conversation = messenger { it.conversation(peerKey) }
        assertEquals(arg("peerFingerprint"), conversation.fingerprint)
        assertEquals(1, messenger { it.conversations() }.size)
    }

    /** Alice writes first; the session starts from that text. */
    @Test
    fun aliceSendsHello() {
        openChat()
        send(text("hello bob"))
        waitForStatus(text("hello bob"), "Delivered")
        waitForMessage(text("hi alice"))
        assertEquals(ChatSessionState.Established, messenger { it.conversation(peerKey) }.session)
        assertEquals(1, stored(text("hello bob"), outgoing = true).size)
        assertEquals(1, stored(text("hi alice"), outgoing = false).size)
    }

    /** Bob reads Alice's text and answers; tapping send twice sends once. */
    @Test
    fun bobRepliesToHello() {
        openChat()
        waitForMessage(text("hello bob"))
        rule.onNodeWithTag("messageInput").performTextInput(text("hi alice"))
        rule.onNodeWithTag("send").performClick()
        rule.onNodeWithTag("send").performClick()
        waitForStatus(text("hi alice"), "Delivered")
        assertEquals(1, stored(text("hi alice"), outgoing = true).size)
        assertEquals(1, stored(text("hello bob"), outgoing = false).size)
    }

    /** Bob's device has no network: the app says so, then catches up. */
    @Test
    fun bobIsOfflineThenCatchesUp() {
        openChat()
        waitForText("No network", WAIT_MS)
        report("ready" to "offline")
        for (i in 1..3) waitForMessage(text("queued $i"))
        for (i in 1..3) assertEquals(1, stored(text("queued $i"), outgoing = false).size)
        val order = messenger { it.chatEntries(peerKey) }.map { it.text.value }.filter { it.startsWith("queued") }
        assertEquals((1..3).map { text("queued $it") }, order)
    }

    /** While Bob is offline: the relay takes Alice's texts; nothing is shown as delivered. */
    @Test
    fun aliceSendsWhileBobIsOffline() {
        openChat()
        for (i in 1..3) send(text("queued $i"))
        for (i in 1..3) waitForStatus(text("queued $i"), "Sent to relay")
        val until = System.currentTimeMillis() + 15_000
        while (System.currentTimeMillis() < until) {
            for (i in 1..3) assertEquals("Sent to relay", statusOf(text("queued $i")))
            Thread.sleep(1_000)
        }
        // What the relay holds for Bob now, before he fetches it: replayed to
        // him in bobIgnoresReplayedEnvelopes, long after he accepted it.
        val held = RelayClient(arg("relay")).fetchAfter(peerKey, 0)
        assertEquals("the relay holds Alice's three texts for Bob, and nothing else", 3, held.size)
        report(
            "replayTo" to hex(peerKey),
            "replay" to held.joinToString(",") { hex(it.second) },
            "replayHeldMaxSeq" to held.maxOf { it.first }.toString(),
        )
    }

    /** Alice's new process: the pending texts were kept, once each, and are now delivered. */
    @Test
    fun aliceSeesTheQueuedTextsDelivered() {
        openChat()
        for (i in 1..3) waitForStatus(text("queued $i"), "Delivered")
        for (i in 1..3) assertEquals(1, stored(text("queued $i"), outgoing = true).size)
        assertEquals(ChatSessionState.Established, messenger { it.conversation(peerKey) }.session)
    }

    /** Bob after a restart: the whole conversation is there and goes on in the same session. */
    @Test
    fun bobContinuesAfterRestart() {
        openChat()
        val history = messenger { it.chatEntries(peerKey) }
        val expected = listOf(
            text("hello bob") to ChatEntryState.RECEIVED,
            text("hi alice") to ChatEntryState.DELIVERED,
            text("queued 1") to ChatEntryState.RECEIVED,
            text("queued 2") to ChatEntryState.RECEIVED,
            text("queued 3") to ChatEntryState.RECEIVED,
        )
        assertEquals(expected, history.map { it.text.value to it.state })
        for ((t, _) in expected) waitForMessage(t)
        assertEquals(ChatSessionState.Established, messenger { it.conversation(peerKey) }.session)
        send(text("after restart"))
        waitForStatus(text("after restart"), "Delivered")
        waitForMessage(text("welcome back"))
        assertEquals(1, stored(text("after restart"), outgoing = true).size)
        assertEquals(1, stored(text("welcome back"), outgoing = false).size)
    }

    @Test
    fun aliceAnswersAfterBobsRestart() {
        openChat()
        waitForMessage(text("after restart"))
        send(text("welcome back"))
        waitForStatus(text("welcome back"), "Delivered")
        assertEquals(1, stored(text("after restart"), outgoing = false).size)
        assertEquals(1, stored(text("welcome back"), outgoing = true).size)
    }

    /**
     * Alice's text is encrypted, committed and on the relay when her process
     * receives SIGKILL (the signal `kill -9` sends): no shutdown path runs.
     * The driver checks the process is gone. Reaching the end of this step
     * means the signal did not kill it.
     */
    @Test
    fun aliceIsKilledWithATextInFlight() {
        openChat()
        send(text("before the kill"))
        waitForStatus(text("before the kill"), "Sent to relay")
        report("killing" to "SIGKILL")
        android.os.Process.sendSignal(android.os.Process.myPid(), android.os.Process.SIGNAL_KILL)
        Thread.sleep(30_000)
        throw AssertionError("SIGKILL did not end this process")
    }

    /** Alice's new process still has the text, once, and Bob's receipt marks it delivered. */
    @Test
    fun aliceSeesTheTextFromBeforeTheKillDelivered() {
        openChat()
        assertEquals(1, stored(text("before the kill"), outgoing = true).size)
        waitForStatus(text("before the kill"), "Delivered")
        assertEquals(ChatSessionState.Established, messenger { it.conversation(peerKey) }.session)
    }

    @Test
    fun bobReceivesTheTextFromBeforeTheKill() {
        openChat()
        waitForMessage(text("before the kill"))
        assertEquals(1, stored(text("before the kill"), outgoing = false).size)
    }

    /**
     * Alice loses the network while sending: the text is kept and shown as
     * not sent; when the network returns it goes out and is delivered, once.
     */
    @Test
    fun aliceSendsDuringAnOutage() {
        openChat()
        shell("cmd connectivity airplane-mode enable")
        try {
            waitForText("No network", WAIT_MS)
            send(text("during the outage"))
            waitForStatus(text("during the outage"), "Not sent yet")
            Thread.sleep(5_000)
            assertEquals("Not sent yet", statusOf(text("during the outage")))
        } finally {
            shell("cmd connectivity airplane-mode disable")
        }
        waitForStatus(text("during the outage"), "Delivered")
        assertEquals(1, stored(text("during the outage"), outgoing = true).size)
    }

    @Test
    fun bobReceivesAfterAlicesOutage() {
        openChat()
        waitForMessage(text("during the outage"))
        assertEquals(1, stored(text("during the outage"), outgoing = false).size)
    }

    /**
     * A contact whose keys on the relay are not the ones the user verified:
     * the relay is unauthenticated, so this test publishes Bob's bundle under
     * the new contact's key itself. Nothing is encrypted for it, and the
     * chat says why.
     */
    @Test
    fun aKeyMismatchOnTheRelayIsRefusedAndShown() {
        val random = SecureRandom()
        val card = ByteArray(65).also { random.nextBytes(it); it[0] = 1 }
        val relay = arg("relay")
        val bobBundle = checkNotNull(RelayClient(relay).getBundle(peerKey)) { "Bob has no bundle" }
        RelayClient(relay).putBundle(card.copyOfRange(1, 33), bobBundle)

        tap("openAddContact")
        rule.onNodeWithTag("cardInput").performTextInput(ContactCardText.encode(card))
        waitFor("theirFingerprint")
        tap("fingerprintsMatch")
        rule.onNodeWithTag("contactName").performTextInput("Mallory")
        tap("addContact")
        waitFor("messageInput")
        send(text("for mallory"))
        waitForText("do not match the card you verified", WAIT_MS)
        assertEquals("Queued", statusOf(text("for mallory")))
        val c = messenger { it.conversation(card.copyOfRange(1, 33)) }
        assertTrue(c.identityMismatch)
        assertEquals(ChatSessionState.None, c.session)
    }

    /**
     * Alice has no network (the driver switched it off): her text is recorded
     * and shown as not sent when her process receives SIGKILL. With no
     * network nothing of it can have reached the relay; the relay itself is
     * not read here.
     */
    @Test
    fun aliceIsKilledBeforePublishing() {
        openChat()
        waitForText("No network", WAIT_MS)
        send(text("before publishing"))
        waitForStatus(text("before publishing"), "Not sent yet")
        report("killing" to "SIGKILL")
        android.os.Process.sendSignal(android.os.Process.myPid(), android.os.Process.SIGNAL_KILL)
        Thread.sleep(30_000)
        throw AssertionError("SIGKILL did not end this process")
    }

    /** Alice's new process, network back: the text was kept, once, and is delivered once. */
    @Test
    fun aliceDeliversTheTextFromBeforePublishing() {
        openChat()
        assertEquals(1, stored(text("before publishing"), outgoing = true).size)
        waitForStatus(text("before publishing"), "Delivered")
        assertEquals(1, stored(text("before publishing"), outgoing = true).size)
    }

    @Test
    fun bobReceivesTheTextFromBeforePublishing() {
        openChat()
        waitForMessage(text("before publishing"))
        assertEquals(1, stored(text("before publishing"), outgoing = false).size)
    }

    /** Bob is offline again (the driver switched his network off): Alice's text waits on the relay. */
    @Test
    fun aliceWritesWhileBobRestartsOffline() {
        openChat()
        send(text("while bob restarts"))
        waitForStatus(text("while bob restarts"), "Sent to relay")
        assertEquals(1, stored(text("while bob restarts"), outgoing = true).size)
    }

    /** Bob's app opens with no network and has not got the text; then this process ends. */
    @Test
    fun bobOpensTheChatOffline() {
        openChat()
        waitForText("No network", WAIT_MS)
        assertEquals(0, stored(text("while bob restarts"), outgoing = false).size)
    }

    /** Bob's next process, network back: the text arrives, once. */
    @Test
    fun bobCatchesUpAfterRestartingOffline() {
        openChat()
        waitForMessage(text("while bob restarts"))
        assertEquals(1, stored(text("while bob restarts"), outgoing = false).size)
    }

    /**
     * The relay is untrusted and may deliver an envelope again after it was
     * fetched and deleted. On the app's sync thread, with Bob's mailbox
     * synced empty first, this step sends Bob, a second time, the envelopes
     * the relay held for him while he was offline (all accepted long ago),
     * then runs one sync round itself. That round must fetch exactly those
     * envelopes, find each a duplicate (none newly accepted, none discarded)
     * and delete them from the relay; and nothing in his history may change.
     * A duplicate text gets a new receipt, but at most one per message per
     * minute (docs/NET-MESSAGING.md), so the round sends at most one each.
     */
    @Test
    fun bobIgnoresReplayedEnvelopes() {
        openChat()
        val me = unhex(arg("replayTo"))
        val envelopes = arg("replay").split(",").map(::unhex)
        val heldMax = arg("replayHeldMaxSeq").toLong()
        val relay = RelayClient(arg("relay"))
        val (seqs, round) = exclusive {
            settle()
            val before = history()
            val seqs = envelopes.map { relay.send(me, it) }
            // Identical bytes still stored would get their old number back: new
            // numbers show the relay stored them again, after Bob deleted them.
            assertTrue("the relay stored the replay anew: $seqs after $heldMax", seqs.all { it > heldMax })
            val n = seqs.size.toUInt()
            val round = messenger { it.syncConversations() }
            assertEquals(
                "the replay round: each envelope fetched and a duplicate, nothing else: $round",
                IDLE.copy(fetched = n, duplicates = n),
                round.copy(published = 0u),
            )
            // Not exactly n: an earlier duplicate of the same text in this
            // minute (a new process of Alice's sends pending texts again)
            // already used that minute's receipt.
            assertTrue("the replay round sent more than a receipt per envelope: $round", round.published <= n)
            assertTrue("the replay is still on the relay", relay.fetchAfter(me, 0).none { it.first in seqs })
            assertEquals(before, history())
            for (i in 1..3) assertEquals(1, stored(text("queued $i"), outgoing = false).size)
            seqs to round
        }
        report("replayed" to seqs.joinToString(","), "replayRound" to round.brief())
    }

    /**
     * Run last, one device at a time (see the driver). On the app's sync
     * thread: sync until a round fetches nothing; then three rounds of the
     * app's messenger, and one of a new messenger with no retransmission
     * clock (it sends at once whatever any session still has pending: texts,
     * receipts, handshakes), must each send, fetch and change nothing; no
     * text to the contact waits for a receipt; the relay holds nothing for
     * this device; and the history with the contact is the whole
     * conversation, every text once, in its final state, and nothing else.
     * With `checkPeerMailbox`, the relay must also hold nothing for the
     * contact: nothing this device sent is left untaken. Not covered: a text
     * to a contact without a session (Alice's to "Mallory" stays queued),
     * and other contacts' histories.
     */
    @Test
    fun everyTextIsInTheHistoryOnceAfterRepeatedSyncs() {
        openChat()
        val expected = conversation(iAmAlice = peerName == "Bob")
        for ((t, outgoing, _) in expected) if (outgoing) waitForStatus(t, "Delivered") else waitForMessage(t)
        val relay = RelayClient(arg("relay"))
        val (rounds, fresh) = exclusive {
            settle()
            val rounds = List(3) { messenger { it.syncConversations() } }
            rounds.forEachIndexed { i, r -> checkQuiet("round ${i + 1}", r) }
            val probe = ArciumApp.core.networkMessenger(arg("relay"), retransmitAfterMs = 0u)
            val fresh = try {
                probe.syncConversations()
            } finally {
                probe.close()
            }
            checkQuiet("the round of a messenger that sends everything pending at once", fresh)
            checkNothingUndelivered(messenger { it.undelivered(peerKey) })
            checkMailboxEmpty(relay, myKey, myName)
            checkHistory(expected, history())
            if (args.getString("checkPeerMailbox") == "1") checkMailboxEmpty(relay, peerKey, peerName)
            rounds to fresh
        }
        report("rounds" to rounds.joinToString(" | ") { it.brief() }, "fresh" to fresh.brief())
    }

    /**
     * Negative controls for the checks of the final step: each is applied to
     * a fixture that breaks what it guards and must fail, and to the matching
     * correct fixture, which must pass. The mailbox fixture is the condition
     * of run 82: one envelope left on the relay for a device after the last
     * pass. It is a new random mailbox that nothing else uses. The driver
     * runs this step first, so no app process runs after the final step.
     */
    @Test
    fun theFinalChecksRejectViolatedFixtures() {
        checkQuiet("the idle report", IDLE)
        val busy = listOf(
            IDLE.copy(published = 1u), IDLE.copy(fetched = 1u), IDLE.copy(accepted = 1u),
            IDLE.copy(duplicates = 1u), IDLE.copy(deferred = 1u), IDLE.copy(errors = listOf("network: refused")),
        )
        for (r in busy) rejects("was not idle") { checkQuiet("a fixture", r) }

        val expected = conversation(iAmAlice = true)
        checkHistory(expected, expected.reversed())
        val sent = expected.indexOfFirst { it.second }
        val broken = listOf(
            expected + expected[sent],
            expected.drop(1),
            expected.mapIndexed { i, e -> if (i == sent) e.copy(third = ChatEntryState.TRANSMITTED) else e },
        )
        for (h in broken) rejects("is not the conversation") { checkHistory(expected, h) }

        checkNothingUndelivered(emptyList())
        rejects("still wait for a receipt") { checkNothingUndelivered(listOf(ByteArray(32))) }

        val relay = RelayClient(arg("relay"))
        val mailbox = ByteArray(32).also { SecureRandom().nextBytes(it) }
        checkMailboxEmpty(relay, mailbox, "the fixture")
        val seq = relay.send(mailbox, ByteArray(158).also { SecureRandom().nextBytes(it) })
        rejects("left on the relay for the fixture: [seq=$seq len=158]") {
            checkMailboxEmpty(relay, mailbox, "the fixture")
        }
        report("controls" to "${busy.size + broken.size + 2} violated fixtures rejected, 4 correct ones passed")
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private fun history() =
        messenger { it.chatEntries(peerKey) }.map { Triple(it.text.value, it.outgoing, it.state) }

    /** Every text of [CONVERSATION] as this device's history must end: (text, outgoing, state). */
    private fun conversation(iAmAlice: Boolean) = CONVERSATION.map { (t, fromAlice) ->
        val outgoing = fromAlice == iAmAlice
        Triple(text(t), outgoing, if (outgoing) ChatEntryState.DELIVERED else ChatEntryState.RECEIVED)
    }

    /**
     * Runs [block] on the app's own sync thread (`MessengerService.syncDispatcher`,
     * one task at a time, read here by reflection): a round of the app's loop
     * already running finishes first, and none starts until [block] returns.
     * [block] must not suspend, or the thread would be free again. It excludes
     * only what runs on that dispatcher: today the app syncs nowhere else
     * (`MessengerService.round`); a sync path added elsewhere would not be.
     */
    private fun <T> exclusive(block: () -> T): T {
        val field = MessengerService::class.java.getDeclaredField("syncDispatcher").apply { isAccessible = true }
        return runBlocking(field.get(ArciumApp.messenger) as CoroutineDispatcher) { block() }
    }

    /** Syncs until a round fetches nothing: every envelope on the relay for this device was processed. */
    private fun settle() {
        val deadline = System.currentTimeMillis() + WAIT_MS
        while (true) {
            val r = messenger { it.syncConversations() }
            assertTrue("settling: ${r.errors}", r.errors.isEmpty())
            if (r.fetched == 0u) return
            check(System.currentTimeMillis() < deadline) { "the mailbox never ran empty: $r" }
        }
    }

    private fun checkQuiet(what: String, r: SyncReport) = assertEquals("$what was not idle", IDLE, r)

    private fun checkNothingUndelivered(ids: List<ByteArray>) =
        assertTrue("texts to $peerName still wait for a receipt: ${ids.map(::hex)}", ids.isEmpty())

    private fun checkMailboxEmpty(relay: RelayClient, owner: ByteArray, whose: String) {
        val left = relay.fetchAfter(owner, 0).map { "seq=${it.first} len=${it.second.size}" }
        assertTrue("left on the relay for $whose: $left", left.isEmpty())
    }

    /** Every expected entry once and nothing else; order is not compared. */
    private fun checkHistory(
        expected: List<Triple<String, Boolean, ChatEntryState>>,
        actual: List<Triple<String, Boolean, ChatEntryState>>,
    ) {
        val order = compareBy<Triple<String, Boolean, ChatEntryState>>({ it.first }, { it.second }, { it.third })
        assertEquals("the history is not the conversation", expected.sortedWith(order), actual.sortedWith(order))
    }

    /** Fails unless [check] fails with a message containing [fragment]. */
    private fun rejects(fragment: String, check: () -> Unit) {
        val e = assertThrows(AssertionError::class.java) { check() }
        assertTrue("the failure says '$fragment': ${e.message}", e.message.orEmpty().contains(fragment))
    }

    private fun SyncReport.brief() =
        "published=$published fetched=$fetched accepted=$accepted duplicates=$duplicates " +
            "delivered=$delivered dropped=$dropped deferred=$deferred errors=$errors"

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

    private fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    private fun <T> messenger(block: (uniffi.arcium_core.NetworkMessenger) -> T): T =
        block(ArciumApp.messenger.messenger())

    private fun stored(text: String, outgoing: Boolean) =
        messenger { it.chatEntries(peerKey) }.filter { it.text.value == text && it.outgoing == outgoing }

    private fun report(vararg pairs: Pair<String, String>) {
        val data = Bundle()
        pairs.forEach { (k, v) -> data.putString(k, v) }
        data.putString("pid", android.os.Process.myPid().toString())
        InstrumentationRegistry.getInstrumentation().sendStatus(DATA_CODE, data)
    }

    private fun shell(command: String) {
        val fd = InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(command)
        ParcelFileDescriptor.AutoCloseInputStream(fd).use { it.readBytes() }
    }

    private fun tap(tag: String) {
        waitFor(tag)
        // Inside a scrolling screen the node may be below the fold.
        try {
            rule.onNodeWithTag(tag).performScrollTo()
        } catch (e: AssertionError) {
            // Not in a scrollable container: already where it is shown.
        }
        rule.onNodeWithTag(tag).performClick()
    }

    private fun waitFor(tag: String, timeoutMs: Long = UI_MS) {
        waitUntil("'$tag' on screen", timeoutMs) {
            rule.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()
        }
    }

    /** [rule.waitUntil], failing with what the screen shows instead of a bare timeout. */
    private fun waitUntil(what: String, timeoutMs: Long, condition: () -> Boolean) {
        try {
            rule.waitUntil(timeoutMs, condition)
        } catch (e: ComposeTimeoutException) {
            val shown = rule.onAllNodes(isRoot()).fetchSemanticsNodes().flatMap { root ->
                generateSequence(listOf(root)) { level -> level.flatMap { it.children }.ifEmpty { null } }
                    .flatten()
                    .mapNotNull { n -> n.config.getOrNull(SemanticsProperties.Text)?.joinToString(" ") { it.text } }
            }
            throw AssertionError(
                "timed out after $timeoutMs ms waiting for $what; screen shows: $shown; ${composerState()}",
                e,
            )
        }
    }

    /**
     * What the message composer holds, for a timeout message: the typed text
     * is not among the texts a screen dump lists, and neither is whether the
     * send button can be pressed.
     */
    private fun composerState(): String {
        val input = rule.onAllNodesWithTag("messageInput").fetchSemanticsNodes().firstOrNull()
            ?.config?.getOrNull(SemanticsProperties.EditableText)?.text
        return "message input: ${input?.let { "'$it'" } ?: "not on screen"}; " +
            "send button: ${enabled("send")?.let { if (it) "enabled" else "disabled" } ?: "not on screen"}"
    }

    /** Whether the node with [tag] can be pressed; null if it is not on screen. */
    private fun enabled(tag: String): Boolean? =
        rule.onAllNodesWithTag(tag).fetchSemanticsNodes().firstOrNull()
            ?.let { SemanticsProperties.Disabled !in it.config }

    private fun textOf(tag: String): String =
        rule.onNodeWithTag(tag).fetchSemanticsNode().config.run {
            (getOrNull(SemanticsProperties.EditableText)?.text
                ?: getOrNull(SemanticsProperties.Text)?.joinToString(" ") { it.text }).orEmpty()
        }

    /** Waits until some text on screen contains [fragment]. */
    private fun waitForText(fragment: String, timeoutMs: Long) {
        waitUntil("text '$fragment'", timeoutMs) {
            rule.onAllNodes(hasText(fragment, substring = true), useUnmergedTree = true)
                .fetchSemanticsNodes().isNotEmpty()
        }
    }

    private fun openChat() {
        waitFor("contact:$peerName", WAIT_MS)
        rule.onNodeWithTag("contact:$peerName").performClick()
        waitFor("messageInput")
    }

    private fun send(message: String) {
        rule.onNodeWithTag("messageInput").performTextInput(message)
        // The button can be pressed only once the typed text has reached the
        // screen's state, so wait for that. Then invoke its click action
        // rather than click by coordinates: typing brings up the keyboard,
        // which moves the button while such a click is on its way. A press
        // that does nothing leaves the text in the field and no bubble, and
        // the step times out; that is what run 43334490691 showed in
        // `bobContinuesAfterRestart`. Which of the two made that press do
        // nothing was not established: the timeout message now says.
        waitUntil("the send button to be enabled", UI_MS) { enabled("send") == true }
        rule.onNodeWithTag("send").performSemanticsAction(SemanticsActions.OnClick)
        waitForMessage(message)
    }

    /** Brings the bubble with [message] into view; false if the chat has none. */
    private fun scrollTo(message: String): Boolean {
        if (rule.onAllNodesWithTag("msg").fetchSemanticsNodes().isEmpty()) return false
        return try {
            rule.onNodeWithTag("chatList").performScrollToNode(hasTestTag("msg") and hasText(message, substring = true))
            true
        } catch (e: AssertionError) {
            false
        }
    }

    /** The state label of the bubble with [message], or null if none is shown. */
    private fun statusOf(message: String): String? {
        if (!scrollTo(message)) return null
        return rule.onAllNodesWithTag("msg").fetchSemanticsNodes()
            .firstOrNull { n -> n.config.getOrNull(SemanticsProperties.Text).orEmpty().any { it.text == message } }
            ?.config?.getOrNull(SemanticsProperties.StateDescription)
    }

    private fun waitForMessage(message: String) {
        waitUntil("message '$message'", WAIT_MS) { statusOf(message) != null }
    }

    private fun waitForStatus(message: String, status: String) {
        waitUntil("'$message' to be '$status'", WAIT_MS) { statusOf(message) == status }
    }

    /** The relay requests this test needs (`RELAY_PROTOCOL_V1`). */
    private class RelayClient(address: String) {
        private val host = address.substringBeforeLast(':')
        private val port = address.substringAfterLast(':').toInt()

        fun getBundle(owner: ByteArray): ByteArray? {
            val response = request(byteArrayOf(2) + owner)
            return if (response[0].toInt() == 0) response.copyOfRange(1, response.size) else null
        }

        fun putBundle(owner: ByteArray, bundle: ByteArray) {
            check(request(byteArrayOf(1) + owner + bundle).contentEquals(byteArrayOf(0))) { "PUT_BUNDLE refused" }
        }

        /** SEND: the sequence number the relay stored [envelope] under. */
        fun send(recipient: ByteArray, envelope: ByteArray): Long {
            val response = request(byteArrayOf(3) + recipient + envelope)
            check(response.size == 9 && response[0].toInt() == 0) { "SEND refused: status ${response[0]}" }
            return DataInputStream(response.inputStream(1, 8)).readLong()
        }

        /** FETCH_AFTER: up to 256 (sequence number, envelope) pairs after [after]. */
        fun fetchAfter(recipient: ByteArray, after: Long): List<Pair<Long, ByteArray>> {
            val body = java.io.ByteArrayOutputStream().also { b ->
                DataOutputStream(b).run { write(6); write(recipient); writeLong(after); writeShort(256) }
            }.toByteArray()
            val response = request(body)
            check(response[0].toInt() == 0) { "FETCH_AFTER refused: status ${response[0]}" }
            val input = DataInputStream(response.inputStream(1, response.size - 1))
            return List(input.readUnsignedShort()) {
                val seq = input.readLong()
                seq to ByteArray(input.readInt()).also { input.readFully(it) }
            }
        }

        private fun request(body: ByteArray): ByteArray = Socket(host, port).use { socket ->
            socket.soTimeout = 10_000
            val out = DataOutputStream(socket.getOutputStream())
            out.writeInt(body.size)
            out.write(body)
            out.flush()
            val input = DataInputStream(socket.getInputStream())
            ByteArray(input.readInt()).also { input.readFully(it) }
        }
    }
}
