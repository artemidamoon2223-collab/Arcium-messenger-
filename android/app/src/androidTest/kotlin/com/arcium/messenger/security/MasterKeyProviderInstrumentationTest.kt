package com.arcium.messenger.security

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.io.IOException
import java.security.KeyStore
import java.util.UUID
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

/**
 * `MasterKeyProvider.load` on a device, with the real Android Keystore: a key
 * is created only when neither the blob nor the store exists, and every other
 * case is reported without creating, replacing or deleting anything.
 *
 * Each test uses its own directory and its own Keystore alias, so the app's
 * own key and files are never touched.
 */
@RunWith(AndroidJUnit4::class)
class MasterKeyProviderInstrumentationTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val alias = "arcium_master_key_wrap_test_${UUID.randomUUID()}"
    private val dir = File(context.filesDir, "master-key-provider-test/${UUID.randomUUID()}").also { check(it.mkdirs()) }
    private val blob = File(dir, MasterKeyProvider.BLOB_FILE_NAME)
    private val tmp = File(dir, "${MasterKeyProvider.BLOB_FILE_NAME}.tmp")
    private val store = File(dir, "arcium.db")

    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    @After
    fun deleteTestAlias() {
        keyStore().deleteEntry(alias)
    }

    private fun load() = MasterKeyProvider.load(dir, store, alias)

    private fun available(): ByteArray = key(load())

    private fun key(r: MasterKeyResult): ByteArray {
        assertTrue("$r", r is MasterKeyResult.Available)
        return (r as MasterKeyResult.Available).key
    }

    /** One call of the sync operation: what it was asked to sync, and which blob files existed then. */
    private data class Sync(val what: String, val tmpExists: Boolean, val blobExists: Boolean)

    private val syncs = mutableListOf<Sync>()

    /** The temporary file's bytes at the moment it was synced. */
    private var syncedTmp: ByteArray? = null

    /**
     * A sync operation that records each call and then really syncs, except
     * that call number [failAt] (counted from 1) throws instead.
     */
    private fun recording(failAt: Int = 0): (File) -> Unit = { path ->
        val what = when (path) {
            tmp -> "tmp"
            blob -> "blob"
            dir -> "dir"
            else -> path.path
        }
        syncs += Sync(what, tmpExists = tmp.exists(), blobExists = blob.exists())
        if (path == tmp) syncedTmp = tmp.readBytes()
        if (syncs.size == failAt) throw IOException("injected sync failure")
        MasterKeyProvider.syncToDisk(path)
    }

    @Test
    fun aFirstRunCreatesAKeyAndLaterRunsLoadTheSameKey() {
        assertFalse(keyStore().containsAlias(alias))
        val first = available()
        assertEquals(32, first.size)
        assertTrue(blob.isFile)
        assertFalse(tmp.exists())
        assertTrue(keyStore().containsAlias(alias))
        // An intact blob, with or without a store, gives the same key back.
        assertArrayEquals(first, available())
        store.writeBytes(byteArrayOf(1, 2, 3))
        assertArrayEquals(first, available())
    }

    @Test
    fun aStoreWithoutABlobIsReportedAndNothingIsCreated() {
        store.writeBytes(ByteArray(4096) { it.toByte() })
        val before = store.readBytes()
        repeat(3) {
            assertSame(MasterKeyResult.MissingForExistingStore, load())
            assertFalse("no blob may be written", blob.exists())
            assertFalse("no temporary blob may be written", tmp.exists())
            assertFalse("no wrapping key may be created", keyStore().containsAlias(alias))
            assertArrayEquals(before, store.readBytes())
        }
    }

    @Test
    fun anEmptyStoreFileOrAJournalAloneAlsoCountsAsAStore() {
        store.writeBytes(ByteArray(0))
        assertSame(MasterKeyResult.MissingForExistingStore, load())
        check(store.delete())
        File(store.path + "-journal").writeBytes(byteArrayOf(9))
        assertSame(MasterKeyResult.MissingForExistingStore, load())
        assertFalse(blob.exists())
        assertFalse(keyStore().containsAlias(alias))
    }

    @Test
    fun aMalformedBlobIsUnavailableAndKeptUnchanged() {
        available()
        store.writeBytes(byteArrayOf(7, 7, 7))
        val storeBefore = store.readBytes()
        for (bad in listOf(ByteArray(0), byteArrayOf(1), ByteArray(64) { 0x55 }, byteArrayOf(2) + ByteArray(60))) {
            blob.writeBytes(bad)
            val r = load()
            assertTrue("$r", r is MasterKeyResult.Unavailable)
            assertArrayEquals(bad, blob.readBytes())
            assertArrayEquals(storeBefore, store.readBytes())
        }
    }

    @Test
    fun aTamperedBlobIsUnavailableAndKeptUnchanged() {
        available()
        val tampered = blob.readBytes().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        blob.writeBytes(tampered)
        val r = load()
        assertTrue("$r", r is MasterKeyResult.Unavailable)
        assertArrayEquals(tampered, blob.readBytes())
    }

    @Test
    fun aMissingWrappingKeyIsUnavailableAndIsNotRecreated() {
        available()
        val blobBefore = blob.readBytes()
        keyStore().deleteEntry(alias)
        repeat(3) {
            val r = load()
            assertTrue("$r", r is MasterKeyResult.Unavailable)
            assertFalse("the wrapping key must not be recreated", keyStore().containsAlias(alias))
            assertArrayEquals(blobBefore, blob.readBytes())
        }
    }

    // ── A new key is on disk before it is returned ──────────────────────────

    @Test
    fun aNewBlobIsSyncedBeforeItGetsItsNameAndItsDirectoryAfter() {
        val first = key(MasterKeyProvider.load(dir, store, alias, recording()))
        assertEquals(
            listOf(
                Sync("tmp", tmpExists = true, blobExists = false),
                Sync("dir", tmpExists = false, blobExists = true),
            ),
            syncs,
        )
        assertArrayEquals("the bytes that were synced are the blob", syncedTmp, blob.readBytes())
        assertArrayEquals(first, available())
    }

    @Test
    fun aTemporaryFileThatCannotBeSyncedNeverGetsTheBlobsName() {
        val r = MasterKeyProvider.load(dir, store, alias, recording(failAt = 1))
        assertTrue("$r", r is MasterKeyResult.Unavailable)
        assertEquals(1, syncs.size)
        assertFalse("an unsynced file must not become the blob", blob.exists())
        assertFalse(store.exists())
        // Nothing was lost: the next run creates a key and keeps it.
        val next = available()
        assertArrayEquals(next, available())
    }

    @Test
    fun aDirectoryThatCannotBeSyncedReturnsNoKeyAndTheNextRunSyncsTheSameBlob() {
        val r = MasterKeyProvider.load(dir, store, alias, recording(failAt = 2))
        assertTrue("$r", r is MasterKeyResult.Unavailable)
        assertEquals(2, syncs.size)
        assertFalse(store.exists())
        // The blob has its name, but no key was returned, so no store was made
        // with it. The next run keeps that blob and syncs it before using it.
        val left = blob.readBytes()
        syncs.clear()
        key(MasterKeyProvider.load(dir, store, alias, recording()))
        assertEquals(
            listOf(
                Sync("blob", tmpExists = false, blobExists = true),
                Sync("dir", tmpExists = false, blobExists = true),
            ),
            syncs,
        )
        assertArrayEquals("the blob must not be replaced", left, blob.readBytes())
    }

    @Test
    fun aBlobWithoutAStoreIsReturnedOnlyOnceItCouldBeSynced() {
        val first = available()
        val before = blob.readBytes()
        for (failAt in 1..2) {
            syncs.clear()
            val r = MasterKeyProvider.load(dir, store, alias, recording(failAt))
            assertTrue("sync $failAt failed, yet: $r", r is MasterKeyResult.Unavailable)
            assertEquals(failAt, syncs.size)
            assertArrayEquals(before, blob.readBytes())
        }
        assertArrayEquals(first, available())
    }

    @Test
    fun aBlobWithAStoreIsReturnedWithoutASync() {
        val first = available()
        // A store file, or its journal alone, is a store. It must open even
        // where a sync would fail.
        for (present in listOf(store, File(store.path + "-journal"))) {
            present.writeBytes(byteArrayOf(1, 2, 3))
            assertArrayEquals(first, key(MasterKeyProvider.load(dir, store, alias, recording(failAt = 1))))
            assertEquals(emptyList<Sync>(), syncs)
            check(present.delete())
        }
    }

    @Test
    fun anErrorThrownInsideASyncReachesTheCaller() {
        class Stop : Error()
        // On a first run, and then for a blob without a store.
        repeat(2) {
            try {
                MasterKeyProvider.load(dir, store, alias) { throw Stop() }
                fail("the error must not become a result")
            } catch (expected: Stop) {
            }
            available()
        }
    }

    // ── The load the app uses, with the real sync ───────────────────────────

    @Test
    fun theAppsOwnLoadReturnsNoKeyUntilItsDirectoryCanBeSynced() {
        // Without its read bit a directory still takes new files and renames,
        // but cannot be opened, which a sync of it needs. So only the real
        // sync, called by the load the app uses, can fail here.
        check(dir.setReadable(false))
        try {
            assertEquals(
                MasterKeyResult.Unavailable("a new master key could not be stored (ErrnoException)"),
                load(),
            )
            assertTrue("the blob was renamed before the directory sync failed", blob.isFile)
            assertEquals(
                MasterKeyResult.Unavailable("the wrapped master key could not be forced to disk (ErrnoException)"),
                load(),
            )
        } finally {
            check(dir.setReadable(true))
        }
        val left = blob.readBytes()
        available()
        assertArrayEquals("the blob must not be replaced", left, blob.readBytes())
    }

    @Test
    fun theRealSyncAcceptsAFileAndADirectoryAndRefusesAMissingPath() {
        blob.writeBytes(byteArrayOf(1))
        MasterKeyProvider.syncToDisk(blob)
        MasterKeyProvider.syncToDisk(dir)
        val missing = runCatching { MasterKeyProvider.syncToDisk(File(dir, "absent")) }
        assertTrue("a missing path must be an error", missing.isFailure)
    }

    @Test
    fun theRealSyncPassesWhatItOpenedToFsync() {
        // A named pipe can be opened but not synced: fsync answers EINVAL for
        // it. That error can only come from fsync on the opened descriptor.
        val pipe = File(dir, "pipe")
        Os.mkfifo(pipe.path, OsConstants.S_IRUSR or OsConstants.S_IWUSR)
        // Held open for reading and writing, so that opening the pipe for
        // reading does not wait for a writer.
        val held = Os.open(pipe.path, OsConstants.O_RDWR, 0)
        try {
            MasterKeyProvider.syncToDisk(pipe)
            fail("the sync of a pipe must fail")
        } catch (e: ErrnoException) {
            assertEquals(OsConstants.EINVAL, e.errno)
        } finally {
            Os.close(held)
        }
    }
}
