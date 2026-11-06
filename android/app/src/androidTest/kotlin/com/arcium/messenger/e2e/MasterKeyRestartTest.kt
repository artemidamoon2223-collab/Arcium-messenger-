package com.arcium.messenger.e2e

import android.os.Bundle
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.ComposeTimeoutException
import androidx.compose.ui.test.isRoot
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.arcium.messenger.ArciumApp
import com.arcium.messenger.MainActivity
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * D-007 through the real app: each test is one cold start of the app process
 * (`ArciumApp.onCreate`, then `MainActivity`), run by
 * `android/e2e/master_key_restart.py` with `am instrument`. Between steps the
 * driver force-stops the app and, from the host, deletes or corrupts
 * `files/master_key.blob` with `run-as`, and hashes the store and the blob.
 *
 * Uses only API that exists both before and after the D-007 fix, so the same
 * steps run on the unfixed code and record what it does there. Each step
 * reports what it saw (status code [DATA_CODE]) before asserting, so a failing
 * step still leaves its observation in the driver's log.
 */
@RunWith(AndroidJUnit4::class)
class MasterKeyRestartTest {

    @get:Rule
    val rule = createAndroidComposeRule<MainActivity>()

    private companion object {
        const val DATA_CODE = 42
        const val UI_MS = 20_000L
        const val ONBOARDING = "createIdentity"
        const val CONTACTS = "openAddContact"
        const val BLOCKED = "startupBlocked"
        const val RETRY = "startupRetry"
    }

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val blob get() = File(context.filesDir, "master_key.blob")

    /** First launch on cleared app data: onboarding creates the identity. */
    @Test
    fun firstLaunchCreatesAnIdentity() {
        val shown = waitForAny(ONBOARDING, BLOCKED, CONTACTS)
        report("screen" to shown)
        assertEquals(ONBOARDING, shown)
        rule.onNodeWithTag(ONBOARDING).performClick()
        waitForAny(CONTACTS)
        report("identity" to identityHex(), "blobExists" to blob.exists().toString())
    }

    /** A restart with the key intact opens the same identity, without onboarding. */
    @Test
    fun anIntactRestartOpensTheSameIdentity() {
        val shown = waitForAny(ONBOARDING, BLOCKED, CONTACTS)
        val identity = if (shown == CONTACTS) identityHex() else "none"
        report("screen" to shown, "identity" to identity)
        assertEquals(CONTACTS, shown)
        assertEquals(arg("expectedIdentity"), identity)
    }

    /** The blob was deleted by the driver; the store remains. */
    @Test
    fun aMissingKeyBlocksStartupAcrossRetries() = blockedAcrossRetries(expectBlob = false)

    /** The blob was overwritten with garbage by the driver; the store remains. */
    @Test
    fun aCorruptedKeyBlocksStartupAcrossRetries() = blockedAcrossRetries(expectBlob = true)

    private fun blockedAcrossRetries(expectBlob: Boolean) {
        val shown = waitForAny(ONBOARDING, BLOCKED, CONTACTS)
        report(
            "screen" to shown,
            "blobExists" to blob.exists().toString(),
            "messengerStarted" to messengerStarted().toString(),
        )
        assertEquals("start-up must stop at the error screen", BLOCKED, shown)
        repeat(3) { round ->
            rule.onNodeWithTag(RETRY).performClick()
            rule.waitForIdle()
            Thread.sleep(1_000)
            val again = waitForAny(ONBOARDING, BLOCKED, CONTACTS)
            report("retry" to "${round + 1}", "screen" to again, "blobExists" to blob.exists().toString())
            assertEquals("retry ${round + 1} must stay blocked", BLOCKED, again)
        }
        assertEquals("no onboarding may be shown", 0, count(ONBOARDING))
        assertFalse("messaging must not start", messengerStarted())
        assertEquals("the blob must be left as it was", expectBlob, blob.exists())
        assertFalse("no temporary blob may be written", File(context.filesDir, "master_key.blob.tmp").exists())
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private fun arg(name: String): String =
        checkNotNull(InstrumentationRegistry.getArguments().getString(name)) { "instrumentation argument '$name' is missing" }

    /** Whether the process-wide messenger exists (it is set only by a successful start-up). */
    private fun messengerStarted(): Boolean = runCatching { ArciumApp.messenger }.isSuccess

    private fun identityHex(): String =
        checkNotNull(ArciumApp.core.loadIdentityPublicKey()) { "no identity stored" }
            .joinToString("") { "%02x".format(it) }

    private fun count(tag: String) = rule.onAllNodesWithTag(tag).fetchSemanticsNodes().size

    /** Waits until one of [tags] is on screen and returns it. */
    private fun waitForAny(vararg tags: String): String {
        try {
            rule.waitUntil(UI_MS) { tags.any { count(it) > 0 } }
        } catch (e: ComposeTimeoutException) {
            val shown = rule.onAllNodes(isRoot()).fetchSemanticsNodes().flatMap { root ->
                generateSequence(listOf(root)) { level -> level.flatMap { it.children }.ifEmpty { null } }
                    .flatten()
                    .mapNotNull { n -> n.config.getOrNull(SemanticsProperties.Text)?.joinToString(" ") { it.text } }
            }
            throw AssertionError("none of ${tags.toList()} on screen after $UI_MS ms; screen shows: $shown", e)
        }
        return tags.first { count(it) > 0 }
    }

    private fun report(vararg pairs: Pair<String, String>) {
        val data = Bundle()
        pairs.forEach { (k, v) -> data.putString(k, v) }
        data.putString("pid", android.os.Process.myPid().toString())
        InstrumentationRegistry.getInstrumentation().sendStatus(DATA_CODE, data)
    }
}
