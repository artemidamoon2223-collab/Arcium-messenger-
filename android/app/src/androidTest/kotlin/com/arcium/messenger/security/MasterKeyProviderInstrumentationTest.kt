package com.arcium.messenger.security

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
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

    private fun available(): ByteArray {
        val r = load()
        assertTrue("$r", r is MasterKeyResult.Available)
        return (r as MasterKeyResult.Available).key
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
}
