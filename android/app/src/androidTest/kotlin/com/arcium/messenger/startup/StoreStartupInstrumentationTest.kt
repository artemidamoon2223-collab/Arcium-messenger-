package com.arcium.messenger.startup

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.arcium.messenger.data.IdentityRepository
import com.arcium.messenger.data.IdentityState
import com.arcium.messenger.security.MasterKeyProvider
import java.io.File
import java.security.KeyStore
import java.util.UUID
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The start-up path the app runs (`StoreStartup.open` behind `AppStartup`),
 * end to end on a device: real Keystore, real master-key blob, real encrypted
 * store through the native library, in a private directory with its own
 * Keystore alias.
 */
@RunWith(AndroidJUnit4::class)
class StoreStartupInstrumentationTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val alias = "arcium_master_key_wrap_test_${UUID.randomUUID()}"
    private val dir = File(context.filesDir, "store-startup-test/${UUID.randomUUID()}").also { check(it.mkdirs()) }
    private val blob = File(dir, MasterKeyProvider.BLOB_FILE_NAME)
    private val store = File(dir, StoreStartup.STORE_FILE_NAME)

    @After
    fun deleteTestAlias() {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias)
    }

    private fun opened(): StoreStartup.Result.Opened {
        val r = StoreStartup.open(dir, alias)
        assertTrue("$r", r is StoreStartup.Result.Opened)
        return r as StoreStartup.Result.Opened
    }

    /** A first run that leaves a store holding an identity; returns its key. */
    private fun firstRunWithIdentity(): ByteArray {
        val core = opened().core
        assertSame(IdentityState.Absent, IdentityRepository(core).load())
        val pk = core.generateAndSaveIdentity()
        core.closeEncryptedDb()
        assertTrue(blob.isFile && store.isFile)
        return pk
    }

    @Test
    fun aCleanFirstRunAndAnIntactRelaunchBothOpenTheSameIdentity() {
        val pk = firstRunWithIdentity()
        val relaunched = opened().core
        assertArrayEquals(pk, relaunched.loadIdentityPublicKey())
        assertSame(IdentityState.Present, IdentityRepository(relaunched).load())
        relaunched.closeEncryptedDb()
    }

    @Test
    fun aMissingBlobBlocksEveryRetryAndLeavesTheStoreAndIdentityIntact() {
        val pk = firstRunWithIdentity()
        val savedBlob = blob.readBytes()
        check(blob.delete())
        val storeBefore = store.readBytes()

        val checks = mutableListOf<StoreStartup.Result>()
        val startup = AppStartup {
            when (val r = StoreStartup.open(dir, alias)) {
                is StoreStartup.Result.Opened -> { r.core.closeEncryptedDb(); StartupState.Ready }
                is StoreStartup.Result.Failed -> StartupState.Blocked(r.problem).also { checks += r }
            }
        }
        val expected = StartupState.Blocked(StartupProblem.KeyMissingForExistingData)
        assertEquals(expected, startup.start())
        repeat(3) { assertEquals(expected, startup.retry()) }
        assertEquals(4, checks.size)
        assertFalse("no replacement blob may be written", blob.exists())
        assertArrayEquals("the store must be unchanged", storeBefore, store.readBytes())

        // Nothing was lost: with the original blob back, the original identity opens.
        blob.writeBytes(savedBlob)
        assertSame(StartupState.Ready, startup.retry())
        val core = opened().core
        assertArrayEquals(pk, core.loadIdentityPublicKey())
        core.closeEncryptedDb()
    }

    @Test
    fun aCorruptedBlobBlocksWithoutCrashingAndChangesNothing() {
        firstRunWithIdentity()
        val corrupted = ByteArray(blob.length().toInt()) { 0x5a }
        blob.writeBytes(corrupted)
        val storeBefore = store.readBytes()
        repeat(2) {
            val r = StoreStartup.open(dir, alias)
            assertTrue("$r", r is StoreStartup.Result.Failed && r.problem is StartupProblem.KeyUnavailable)
            assertArrayEquals(corrupted, blob.readBytes())
            assertArrayEquals(storeBefore, store.readBytes())
        }
    }
}
