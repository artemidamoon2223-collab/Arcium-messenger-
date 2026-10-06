package com.arcium.messenger.ffi

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.arcium.messenger.data.IdentityRepository
import com.arcium.messenger.data.IdentityState
import java.io.File
import java.io.RandomAccessFile
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.arcium_core.CoreException

/**
 * F-9 through the native library on Android: identity reads and creation
 * through Rust → UniFFI → Kotlin, on real stores with synthetic keys.
 *
 * A read failure is injected by overwriting the database file's header while
 * the store is idle — SQLite then reports "file is not a database" — and
 * undone by writing the original header back.
 */
@RunWith(AndroidJUnit4::class)
class IdentityInstrumentationTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private fun newDb(): String {
        val dir = File(context.filesDir, "arcium-identity-test/${UUID.randomUUID()}")
        check(dir.mkdirs())
        return File(dir, "store.db").absolutePath
    }

    private fun open(db: String) = ArciumCoreWrapper().apply { openEncryptedDb(db, ByteArray(32) { 0x3c }) }

    @Test
    fun anEmptyStoreHasNoIdentity() {
        val core = open(newDb())
        assertNull(core.loadIdentityPublicKey())
        assertSame(IdentityState.Absent, IdentityRepository(core).load())
        core.closeEncryptedDb()
    }

    @Test
    fun aStoredIdentityIsNeverReplacedAndIsLoadedInstead() {
        val core = open(newDb())
        val pk = core.generateAndSaveIdentity()
        assertThrows(CoreException.IdentityAlreadyExists::class.java) { core.generateAndSaveIdentity() }
        assertArrayEquals(pk, core.loadIdentityPublicKey())
        // What onboarding does on a second tap: the stored identity, unchanged.
        assertArrayEquals(pk, IdentityRepository(core).createOrLoadExisting())
        assertArrayEquals(pk, core.loadIdentityPublicKey())
        core.closeEncryptedDb()
    }

    @Test
    fun aStoreThatCannotBeReadIsAnErrorAndRecoversUnchanged() {
        val db = newDb()
        val core = open(db)
        val pk = core.generateAndSaveIdentity()
        val header = ByteArray(100)
        RandomAccessFile(db, "rw").use { f ->
            f.readFully(header)
            f.seek(0)
            f.write(ByteArray(100))
            f.fd.sync()
        }

        assertThrows(CoreException.Storage::class.java) { core.loadIdentityPublicKey() }
        val state = IdentityRepository(core).load()
        assertTrue("$state", state is IdentityState.Failed)
        // Onboarding's create neither succeeds nor reports an existing identity.
        assertThrows(CoreException.Storage::class.java) { IdentityRepository(core).createOrLoadExisting() }

        RandomAccessFile(db, "rw").use { f ->
            f.write(header)
            f.fd.sync()
        }
        // A retry reads the same identity: nothing was created or replaced.
        assertSame(IdentityState.Present, IdentityRepository(core).load())
        assertArrayEquals(pk, core.loadIdentityPublicKey())
        core.closeEncryptedDb()
    }
}
