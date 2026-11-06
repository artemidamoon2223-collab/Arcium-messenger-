package com.arcium.messenger.ui

import androidx.compose.material3.Text
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.arcium.messenger.startup.AppStartup
import com.arcium.messenger.startup.StartupProblem
import com.arcium.messenger.startup.StartupState
import com.arcium.messenger.ui.startup.StartupGate
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The start-up gate on a device, with the start-up check replaced by a
 * function. The app's navigation is replaced by a marker that counts its own
 * compositions: while start-up is blocked it must never be composed, so no
 * ViewModel, onboarding or messaging can start.
 */
@RunWith(AndroidJUnit4::class)
class StartupGateInstrumentationTest {

    @get:Rule
    val rule = createComposeRule()

    private val composedContent = AtomicInteger()
    private val missing = StartupState.Blocked(StartupProblem.KeyMissingForExistingData)

    private fun show(startup: AppStartup) = rule.setContent {
        StartupGate(startup) {
            SideEffect { composedContent.incrementAndGet() }
            Text("app", Modifier.testTag("appContent"))
        }
    }

    private fun waitFor(tag: String) =
        rule.waitUntil(10_000) { rule.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() }

    private fun count(tag: String) = rule.onAllNodesWithTag(tag).fetchSemanticsNodes().size

    @Test
    fun aBlockedStartupShowsTheErrorAndRetriesStayBlocked() {
        val checks = AtomicInteger()
        val startup = AppStartup { checks.incrementAndGet(); missing }
        startup.start()
        show(startup)
        repeat(3) { round ->
            waitFor("startupRetry")
            assertEquals(1, count("startupBlocked"))
            rule.onNodeWithTag("startupRetry").performClick()
            rule.waitUntil(10_000) { checks.get() == round + 2 }
        }
        waitFor("startupBlocked")
        rule.waitForIdle()
        assertEquals(0, count("appContent"))
        assertEquals(0, composedContent.get())
        assertEquals(4, checks.get())
    }

    @Test
    fun aReadyStartupShowsTheApp() {
        val startup = AppStartup { StartupState.Ready }
        startup.start()
        show(startup)
        waitFor("appContent")
        assertEquals(0, count("startupBlocked"))
    }

    @Test
    fun aRetryThatSucceedsShowsTheAppOnce() {
        val checks = AtomicInteger()
        val startup = AppStartup { if (checks.incrementAndGet() == 1) missing else StartupState.Ready }
        startup.start()
        show(startup)
        waitFor("startupRetry")
        assertEquals(0, composedContent.get())
        rule.onNodeWithTag("startupRetry").performClick()
        waitFor("appContent")
        assertEquals(0, count("startupBlocked"))
        assertEquals(2, checks.get())
    }
}
