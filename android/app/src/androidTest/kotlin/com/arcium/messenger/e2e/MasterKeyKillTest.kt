package com.arcium.messenger.e2e

import android.os.Bundle
import android.os.Process
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.arcium.messenger.ffi.ArciumCoreWrapper
import com.arcium.messenger.security.MasterKeyProvider
import com.arcium.messenger.security.MasterKeyResult
import com.arcium.messenger.startup.StoreStartup
import java.io.File
import java.security.KeyStore
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The process dies while a first run creates the master key, before any store
 * exists; the runs after it must end with one key that opens one store.
 *
 * Each test is one app process, run by `android/e2e/master_key_restart.py`
 * with `am instrument`. The instrumentation argument `point` names where the
 * first process kills itself (SIGKILL):
 *
 *  - `written`: the temporary file is written, not synced and not renamed;
 *  - `renamed`: the blob has its name, its directory is not synced;
 *  - `returned`: the key was returned, the store is not created.
 *
 * A killed process loses nothing the kernel already holds, so this shows what
 * the next runs do with the files a process left when it died at one of these
 * three points. It does not show what reaches the disk when power is lost.
 *
 * Every point has its own directory under `filesDir` and its own Keystore
 * alias; the app's own key and store are not touched.
 */
@RunWith(AndroidJUnit4::class)
class MasterKeyKillTest {

    private companion object {
        const val DATA_CODE = 42
        const val MARKER = "killed-at"
    }

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val point = arg("point")
    private val dir = File(context.filesDir, "master-key-kill-test/$point")
    private val alias = "arcium_master_key_wrap_kill_test_$point"
    private val blob = File(dir, MasterKeyProvider.BLOB_FILE_NAME)
    private val tmp = File(dir, "${MasterKeyProvider.BLOB_FILE_NAME}.tmp")
    private val store = File(dir, StoreStartup.STORE_FILE_NAME)

    /** Starts from nothing and dies at [point]. A run that reaches the end of this method failed. */
    @Test
    fun theProcessDiesWhileCreatingTheKey() {
        dir.deleteRecursively()
        check(dir.mkdirs())
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias)

        val r = MasterKeyProvider.load(dir, store, alias) { path ->
            if (point == "written" && path == tmp) die()
            if (point == "renamed" && path == dir) die()
            MasterKeyProvider.syncToDisk(path)
        }
        if (point == "returned" && r is MasterKeyResult.Available) die()
        fail("the process outlived its kill point '$point': $r")
    }

    /** The first run after the death: it must end with a key and a store that key opens. */
    @Test
    fun theNextRunCreatesTheStoreWithTheKeyOnDisk() {
        assertEquals("the kill point that was reached", point, File(dir, MARKER).readText())
        assertFalse("no store may exist yet", store.exists())
        val left = if (blob.exists()) blob.readBytes() else null
        assertEquals("a blob has its name from 'renamed' on", point != "written", left != null)

        val synced = mutableListOf<String>()
        val r = MasterKeyProvider.load(dir, store, alias) { path ->
            synced += when (path) {
                tmp -> "tmp"
                blob -> "blob"
                dir -> "dir"
                else -> path.path
            }
            MasterKeyProvider.syncToDisk(path)
        }
        report("result" to r.javaClass.simpleName, "synced" to synced.joinToString(","))
        assertTrue("$r", r is MasterKeyResult.Available)
        val key = (r as MasterKeyResult.Available).key
        if (left == null) {
            // Nothing had the blob's name: a new key, written and synced as on any first run.
            assertEquals(listOf("tmp", "dir"), synced)
        } else {
            // The blob that was left is kept, and is put on disk before its key is used.
            assertEquals(listOf("blob", "dir"), synced)
            assertArrayEquals("the blob must not be replaced", left, blob.readBytes())
        }
        assertFalse("no temporary blob may be left", tmp.exists())

        val core = ArciumCoreWrapper()
        try {
            core.openEncryptedDb(store.absolutePath, key)
        } finally {
            key.fill(0)
        }
        val identity = core.generateAndSaveIdentity()
        core.closeEncryptedDb()
        report("identity" to hex(identity))
    }

    /** A later run, through the app's own start-up path: the same store and identity. */
    @Test
    fun aLaterRunOpensTheSameIdentity() {
        val r = StoreStartup.open(dir, alias)
        report("result" to r.javaClass.simpleName)
        assertTrue("$r", r is StoreStartup.Result.Opened)
        val core = (r as StoreStartup.Result.Opened).core
        val identity = core.loadIdentityPublicKey()
        core.closeEncryptedDb()
        report("identity" to (identity?.let(::hex) ?: "none"))
        assertEquals(arg("expectedIdentity"), identity?.let(::hex))
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /** Leaves a marker naming the point, then kills this process. */
    private fun die(): Nothing {
        File(dir, MARKER).writeText(point)
        Process.killProcess(Process.myPid())
        Thread.sleep(60_000)
        throw AssertionError("the process survived SIGKILL")
    }

    private fun arg(name: String): String =
        checkNotNull(InstrumentationRegistry.getArguments().getString(name)) { "instrumentation argument '$name' is missing" }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    private fun report(vararg pairs: Pair<String, String>) {
        val data = Bundle()
        pairs.forEach { (k, v) -> data.putString(k, v) }
        data.putString("pid", Process.myPid().toString())
        InstrumentationRegistry.getInstrumentation().sendStatus(DATA_CODE, data)
    }
}
