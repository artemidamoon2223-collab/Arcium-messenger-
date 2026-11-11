package com.arcium.messenger.startup

import java.util.concurrent.CountDownLatch
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The start-up gate's own rules, with the check replaced by a function (no
 * native code, no Keystore): a blocked start-up stays blocked across retries,
 * a successful one runs its check exactly once, and checks never overlap.
 */
class AppStartupTest {

    private val missing = StartupState.Blocked(StartupProblem.KeyMissingForExistingData)

    @Test
    fun aBlockedStartupStaysBlockedOnEveryRetry() {
        val checks = AtomicInteger()
        val startup = AppStartup { checks.incrementAndGet(); missing }
        assertEquals(missing, startup.start())
        repeat(5) { assertEquals(missing, startup.retry()) }
        assertEquals(missing, startup.state.value)
        assertEquals(6, checks.get())
    }

    @Test
    fun aSuccessfulStartupRunsItsCheckOnce() {
        val checks = AtomicInteger()
        val startup = AppStartup { checks.incrementAndGet(); StartupState.Ready }
        assertSame(StartupState.Ready, startup.start())
        repeat(5) { assertSame(StartupState.Ready, startup.retry()) }
        assertEquals(1, checks.get())
    }

    @Test
    fun aRetryCanSucceedAfterABlockedStart() {
        val checks = AtomicInteger()
        val startup = AppStartup { if (checks.incrementAndGet() < 3) missing else StartupState.Ready }
        assertEquals(missing, startup.start())
        assertEquals(missing, startup.retry())
        assertSame(StartupState.Ready, startup.retry())
        assertSame(StartupState.Ready, startup.retry())
        assertEquals(3, checks.get())
    }

    @Test
    fun aThrowingCheckBlocksInsteadOfPropagating() {
        val startup = AppStartup { throw IllegalStateException("boom") }
        val state = startup.start()
        assertTrue("$state", state is StartupState.Blocked)
        assertTrue(startup.state.value is StartupState.Blocked)
    }

    @Test
    fun aCheckThatReportsNoOutcomeBlocks() {
        val startup = AppStartup { StartupState.Checking }
        assertTrue(startup.start() is StartupState.Blocked)
    }

    @Test
    fun overlappingRetriesNeverRunTwoChecksAtOnceAndInitializeOnce() {
        val running = AtomicInteger()
        val maxRunning = AtomicInteger()
        val initialized = AtomicInteger()
        val checks = AtomicInteger()
        // Blocked for the first four checks, then Ready: later callers must
        // see Ready without initializing again.
        val startup = AppStartup {
            val now = running.incrementAndGet()
            maxRunning.accumulateAndGet(now) { a, b -> maxOf(a, b) }
            Thread.sleep(5)
            running.decrementAndGet()
            if (checks.incrementAndGet() <= 4) {
                missing
            } else {
                initialized.incrementAndGet()
                StartupState.Ready
            }
        }
        val threads = 16
        val barrier = CyclicBarrier(threads)
        val done = CountDownLatch(threads)
        repeat(threads) {
            Thread {
                barrier.await()
                startup.retry()
                done.countDown()
            }.start()
        }
        assertTrue(done.await(30, TimeUnit.SECONDS))
        assertEquals(1, maxRunning.get())
        assertEquals(1, initialized.get())
        assertEquals(5, checks.get())
        assertSame(StartupState.Ready, startup.state.value)
    }
}
