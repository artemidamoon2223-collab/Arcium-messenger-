package com.arcium.messenger.e2e

import android.os.Bundle
import android.os.ParcelFileDescriptor
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
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.arcium.messenger.ArciumApp
import com.arcium.messenger.MainActivity
import com.arcium.messenger.messaging.ContactCardText
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.Socket
import java.security.SecureRandom
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.arcium_core.ChatEntryState
import uniffi.arcium_core.ChatSessionState
import uniffi.arcium_core.contactCardFingerprint

/**
 * Two people messaging through the real app on two independent Android
 * emulators, each with its own identity, encrypted database and process.
 *
 * Each test is one step of one user; `android/e2e/two_devices.py` runs them
 * with `am instrument` on the right emulator, in order or side by side, and
 * passes what a user would have: the relay address, and the contact's card,
 * fingerprint and name as shown on the contact's own screen (the out-of-band
 * channel). Steps drive the screens only — the Rust store is read afterwards,
 * from this same app process, just to count what the screens show.
 *
 * Every text carries [CANARY]; the relay alerts if it ever stores those
 * bytes, and the workflow fails on that alert. Missing arguments fail a step;
 * nothing is skipped.
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
    }

    private val args = InstrumentationRegistry.getArguments()

    private fun arg(name: String): String =
        checkNotNull(args.getString(name)) { "instrumentation argument '$name' is missing" }

    private val peerName get() = arg("peerName")
    private val peerCard get() = checkNotNull(ContactCardText.decode(arg("peerCard")))
    private val peerKey get() = peerCard.copyOfRange(1, 33)

    private fun text(s: String) = "$s $CANARY"

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
        val order = messenger { it.chatEntries(peerKey) }.map { it.text }.filter { it.startsWith("queued") }
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
            for (i in 1..3) assertNotEquals("Delivered", statusOf(text("queued $i")))
            Thread.sleep(1_000)
        }
    }

    /** Alice's new process: the pending texts were kept and are now delivered. */
    @Test
    fun aliceSeesTheQueuedTextsDelivered() {
        openChat()
        for (i in 1..3) waitForStatus(text("queued $i"), "Delivered")
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
        assertEquals(expected, history.map { it.text to it.state })
        for ((t, _) in expected) waitForMessage(t)
        assertEquals(ChatSessionState.Established, messenger { it.conversation(peerKey) }.session)
        send(text("after restart"))
        waitForStatus(text("after restart"), "Delivered")
        waitForMessage(text("welcome back"))
    }

    @Test
    fun aliceAnswersAfterBobsRestart() {
        openChat()
        waitForMessage(text("after restart"))
        send(text("welcome back"))
        waitForStatus(text("welcome back"), "Delivered")
    }

    /**
     * Alice loses the network while sending: the text is kept and shown as
     * not sent; when the network returns it goes out and is delivered.
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
    }

    @Test
    fun bobReceivesAfterAlicesOutage() {
        openChat()
        waitForMessage(text("during the outage"))
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

    // ── Helpers ─────────────────────────────────────────────────────────────

    private fun <T> messenger(block: (uniffi.arcium_core.NetworkMessenger) -> T): T =
        block(ArciumApp.messenger.messenger())

    private fun stored(text: String, outgoing: Boolean) =
        messenger { it.chatEntries(peerKey) }.filter { it.text == text && it.outgoing == outgoing }

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
            throw AssertionError("timed out after $timeoutMs ms waiting for $what; screen shows: $shown", e)
        }
    }

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
        tap("send")
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

    /** The two relay requests this test needs (`RELAY_PROTOCOL_V1`). */
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
