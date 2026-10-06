package com.arcium.messenger.ui

import androidx.compose.material3.Text
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.arcium.messenger.data.IdentityRepository
import com.arcium.messenger.ui.navigation.IdentityGate
import com.arcium.messenger.ui.navigation.IdentityGateViewModel
import com.arcium.messenger.ui.navigation.Routes
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.arcium_core.CoreException

/**
 * The identity gate on a device, with the identity read replaced by a
 * function: a failed read shows an error and a retry, never onboarding, and
 * the retry only reads again. The app's screens are replaced by a marker of
 * the start destination the gate chose.
 */
@RunWith(AndroidJUnit4::class)
class IdentityGateInstrumentationTest {

    @get:Rule
    val rule = createComposeRule()

    // Reads run on Dispatchers.IO; the test thread reads the counts.
    private val creates = AtomicInteger()

    private fun gate(load: () -> ByteArray?) =
        IdentityGateViewModel(IdentityRepository(load) { creates.incrementAndGet(); ByteArray(32) })

    private fun show(gate: IdentityGateViewModel) = rule.setContent {
        IdentityGate(gate) { start -> Text(start, Modifier.testTag("start:$start")) }
    }

    private fun waitFor(tag: String) =
        rule.waitUntil(10_000) { rule.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() }

    private fun count(tag: String) = rule.onAllNodesWithTag(tag).fetchSemanticsNodes().size

    @Test
    fun aFailedReadShowsARetryAndNeverOnboarding() {
        val reads = AtomicInteger()
        show(gate { reads.incrementAndGet(); throw CoreException.Storage("database is locked") })
        repeat(3) {
            waitFor("identityRetry")
            assertEquals(0, count("start:${Routes.ONBOARDING}"))
            rule.onNodeWithTag("identityRetry").performClick()
        }
        waitFor("identityLoadFailed")
        rule.waitUntil(10_000) { reads.get() == 4 }
        assertEquals(0, count("start:${Routes.ONBOARDING}"))
        assertEquals(0, creates.get())
    }

    @Test
    fun aRetryRecoversFromATransientFailure() {
        val reads = AtomicInteger()
        show(
            gate {
                if (reads.incrementAndGet() == 1) throw CoreException.Storage("database is locked")
                ByteArray(32)
            },
        )
        waitFor("identityRetry")
        rule.onNodeWithTag("identityRetry").performClick()
        waitFor("start:${Routes.CONTACTS}")
        assertEquals(0, count("start:${Routes.ONBOARDING}"))
        assertEquals(0, creates.get())
    }

    @Test
    fun onlyAStoreWithNoIdentityStartsOnboarding() {
        show(gate { null })
        waitFor("start:${Routes.ONBOARDING}")
        assertEquals(0, creates.get())
    }
}
