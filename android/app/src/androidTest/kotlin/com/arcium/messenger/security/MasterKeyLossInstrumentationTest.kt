package com.arcium.messenger.security

import android.content.Context
import android.content.ContextWrapper
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.arcium.messenger.data.IdentityRepository
import com.arcium.messenger.ffi.ArciumCoreWrapper
import com.arcium.messenger.ui.navigation.startDestinationFor
import java.io.File
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

/**
 * D-007 (F-9 residual): an existing store whose master-key blob is missing
 * must never get a replacement key, and so never reach onboarding or a second
 * identity.
 *
 * The scenario runs in a private directory standing in for `filesDir`, with
 * the same file names the app uses (`master_key.blob`, `arcium.db`). The
 * app's own files are not touched.
 *
 * Written against the startup API that exists before the fix
 * (`MasterKeyProvider.getOrCreateMasterKey`), so on the unfixed code it runs
 * and fails, and its message records what startup did instead.
 */
@RunWith(AndroidJUnit4::class)
class MasterKeyLossInstrumentationTest {

    private val target = InstrumentationRegistry.getInstrumentation().targetContext

    /** A context whose `filesDir` is a fresh private directory. */
    private fun isolatedContext(): Pair<Context, File> {
        val dir = File(target.filesDir, "master-key-loss-test/${UUID.randomUUID()}")
        check(dir.mkdirs())
        return object : ContextWrapper(target) {
            override fun getFilesDir(): File = dir
        } to dir
    }

    @Test
    fun aMissingBlobWithAnExistingStoreNeverYieldsANewKeyOrIdentity() {
        val (context, dir) = isolatedContext()
        val blob = File(dir, "master_key.blob")
        val db = File(dir, "arcium.db")

        // First run: key created, store opened, identity created.
        val firstKey = MasterKeyProvider.getOrCreateMasterKey(context)
        val first = ArciumCoreWrapper().apply { openEncryptedDb(db.absolutePath, firstKey) }
        firstKey.fill(0)
        val identity = first.generateAndSaveIdentity()
        first.closeEncryptedDb()
        check(blob.isFile && db.isFile)

        // The blob is lost; the store stays.
        check(blob.delete())
        val dbBefore = db.readBytes()

        val replacement = try {
            MasterKeyProvider.getOrCreateMasterKey(context)
        } catch (expected: Exception) {
            null
        }
        if (replacement != null) {
            // What the app would do next (ArciumApp.onCreate, IdentityGate,
            // onboarding), recorded for the failure message.
            val core = ArciumCoreWrapper().apply { openEncryptedDb(db.absolutePath, replacement) }
            replacement.fill(0)
            val state = IdentityRepository(core).load()
            val start = startDestinationFor(state)
            val created = IdentityRepository(core).createOrLoadExisting()
            core.closeEncryptedDb()
            fail(
                "startup created a replacement master key for an existing store: " +
                    "blobRecreated=${blob.exists()}, identityState=$state, startDestination=$start, " +
                    "onboardingCreatedSecondIdentity=${!created.contentEquals(identity)}",
            )
        }

        assertFalse("no replacement blob may be written", blob.exists())
        assertArrayEquals("the existing store must be unchanged", dbBefore, db.readBytes())
    }
}
