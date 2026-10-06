package com.arcium.messenger.data

import com.arcium.messenger.ui.navigation.Routes
import com.arcium.messenger.ui.navigation.startDestinationFor
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.arcium_core.CoreException

/**
 * F-9 on the Kotlin side, with the native calls replaced by functions (no
 * native code runs): a failed identity read is never "no identity", never
 * routes to onboarding, and never creates; an identity already stored is
 * loaded, not replaced. `IdentityInstrumentationTest` repeats the native part
 * on a device.
 */
class IdentityRepositoryTest {

    private val stored = ByteArray(32) { 0x11 }
    private val fresh = ByteArray(32) { 0x22 }

    private val noCreate: () -> ByteArray = { throw AssertionError("a read must never create an identity") }

    @Test
    fun onlyAMissingIdentityIsAbsent() {
        assertSame(IdentityState.Present, IdentityRepository({ stored }, noCreate).load())
        assertSame(IdentityState.Absent, IdentityRepository({ null }, noCreate).load())
    }

    @Test
    fun aFailedReadIsFailedNotAbsent() {
        for (error in listOf(CoreException.Storage("database is locked"), CoreException.IdentityUnreadable("x"))) {
            val state = IdentityRepository({ throw error }, noCreate).load()
            assertTrue("$error gave $state", state is IdentityState.Failed)
        }
    }

    @Test
    fun aFailedReadNeverStartsOnboarding() {
        assertNull(startDestinationFor(IdentityState.Failed("database is locked")))
        assertNull(startDestinationFor(IdentityState.Loading))
        assertEquals(Routes.ONBOARDING, startDestinationFor(IdentityState.Absent))
        assertEquals(Routes.CONTACTS, startDestinationFor(IdentityState.Present))
    }

    @Test
    fun aRetryReadsAgainAndRecoversFromATransientFailure() {
        var reads = 0
        val repo = IdentityRepository(
            loadKey = { if (++reads == 1) throw CoreException.Storage("database is locked") else stored },
            createKey = noCreate,
        )
        assertTrue(repo.load() is IdentityState.Failed)
        assertSame(IdentityState.Present, repo.load())
        assertEquals(2, reads)
    }

    @Test
    fun creatingInAnEmptyStoreReturnsTheNewKey() {
        assertArrayEquals(fresh, IdentityRepository({ null }, { fresh }).createOrLoadExisting())
    }

    @Test
    fun anIdentityAlreadyStoredIsLoadedNotReplaced() {
        var creates = 0
        val repo = IdentityRepository(
            loadKey = { stored },
            createKey = { creates++; throw CoreException.IdentityAlreadyExists() },
        )
        assertArrayEquals(stored, repo.createOrLoadExisting())
        assertEquals(1, creates)
    }

    @Test
    fun anIdentityAlreadyStoredThatCannotBeLoadedDoesNotProceed() {
        val repo = IdentityRepository(
            loadKey = { throw CoreException.IdentityUnreadable("x") },
            createKey = { throw CoreException.IdentityAlreadyExists() },
        )
        assertThrows(CoreException.IdentityUnreadable::class.java) { repo.createOrLoadExisting() }
    }

    @Test
    fun aCreationThatFailsOtherwisePropagates() {
        val repo = IdentityRepository(
            loadKey = { throw AssertionError("not reached") },
            createKey = { throw CoreException.IdentityUnreadable("x") },
        )
        assertThrows(CoreException.IdentityUnreadable::class.java) { repo.createOrLoadExisting() }
    }
}
