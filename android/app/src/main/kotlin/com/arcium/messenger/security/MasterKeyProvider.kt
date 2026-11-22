package com.arcium.messenger.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** What [MasterKeyProvider.load] found. */
sealed interface MasterKeyResult {
    /**
     * The 32-byte master key. The caller owns the array: zero it once it has
     * been handed on.
     */
    class Available(val key: ByteArray) : MasterKeyResult

    /**
     * The store exists but its wrapped master key does not. Nothing was
     * created: a new key would not open the existing store, and the app would
     * then treat it as empty.
     */
    data object MissingForExistingStore : MasterKeyResult

    /**
     * No usable master key; [reason] names the cause and carries no key
     * material. Either a wrapped master key exists but cannot be used (the blob
     * is malformed or does not decrypt, or the Keystore wrapping key is missing
     * or refuses to work), and then nothing was created, replaced or deleted.
     * Or a key for a store that does not exist yet could not be created or
     * could not be forced to disk, and then that key was not handed out.
     */
    data class Unavailable(val reason: String) : MasterKeyResult
}

/** Thrown by [MasterKeyProvider.getOrCreateMasterKey] for anything but [MasterKeyResult.Available]. */
class MasterKeyUnavailableException(val result: MasterKeyResult) :
    IllegalStateException("master key unavailable: $result")

/**
 * Provides the 32-byte master key for the Rust encrypted store.
 *
 * Scheme: a random 32-byte master key is generated once with [SecureRandom]
 * and stored on disk ONLY in wrapped (encrypted) form. The wrapping key is an
 * AES-256-GCM key that lives inside AndroidKeyStore and is not exportable.
 * Blob layout at files/master_key.blob: [1-byte version][12-byte GCM IV][ciphertext+tag].
 *
 * A key is created only on a first run: no blob AND no store. A store
 * without a blob, an unreadable blob, or a missing or failing wrapping key is
 * reported, never repaired: replacing the key would orphan the existing
 * encrypted database (records are found under a master-key-derived name, so
 * the store would read as empty and onboarding would create a new identity).
 *
 * The key for a store that does not exist yet is returned only after its blob
 * and the blob's directory entry were forced to disk (`fsync`). The store is
 * created with that key right after and syncs its own writes, so without this
 * order a power loss could keep the store and lose the only key that opens it.
 */
object MasterKeyProvider {

    const val KEYSTORE_ALIAS = "arcium_master_key_wrap"
    const val BLOB_FILE_NAME = "master_key.blob"
    private const val BLOB_VERSION: Byte = 1
    private const val GCM_IV_BYTES = 12
    private const val GCM_TAG_BITS = 128
    private const val MASTER_KEY_BYTES = 32

    /**
     * The master key for the store at [store], whose wrapped copy lives in
     * [dir]. Creates one only when neither the blob nor the store exists.
     * Never throws for a missing, unreadable or unusable key: those are
     * [MasterKeyResult.MissingForExistingStore] and [MasterKeyResult.Unavailable].
     *
     * Order matters: the store check comes before any Keystore access, so the
     * missing-blob case creates no wrapping key, no blob and no temporary file.
     *
     * [alias] is the Keystore alias of the wrapping key; tests pass their own.
     */
    fun load(dir: File, store: File, alias: String = KEYSTORE_ALIAS): MasterKeyResult =
        load(dir, store, alias, ::syncToDisk)

    /**
     * [load] with the operation that forces one file or directory to disk.
     * The app always uses [syncToDisk]; tests pass their own to see when it is
     * called, to make it fail, or to stop the process inside it.
     */
    internal fun load(dir: File, store: File, alias: String, sync: (File) -> Unit): MasterKeyResult {
        val blobFile = File(dir, BLOB_FILE_NAME)
        if (!blobFile.exists()) {
            if (storeExists(store)) return MasterKeyResult.MissingForExistingStore
            return create(dir, blobFile, alias, sync)
        }
        val found: SecretKey? = try {
            existingWrapKey(alias)
        } catch (e: Exception) {
            return MasterKeyResult.Unavailable("the Keystore could not be read (${e.javaClass.simpleName})")
        }
        val wrapKey = found
            ?: return MasterKeyResult.Unavailable("the wrapping key is missing from the Keystore")
        val masterKey = try {
            unwrap(blobFile.readBytes(), wrapKey)
        } catch (e: Exception) {
            return MasterKeyResult.Unavailable("the wrapped master key could not be read (${e.javaClass.simpleName})")
        }
        // A blob without a store: the process that wrote the blob may have
        // died before the blob was on disk, and the caller creates the store
        // next, so the blob goes to disk first. A blob with a store is not
        // synced: that store was created after this step, or by a version
        // without it, and a sync that fails must not keep an existing store
        // closed.
        if (!storeExists(store)) {
            try {
                sync(blobFile)
                sync(dir)
            } catch (t: Throwable) {
                masterKey.fill(0)
                if (t !is Exception) throw t
                return MasterKeyResult.Unavailable(
                    "the wrapped master key could not be forced to disk (${t.javaClass.simpleName})"
                )
            }
        }
        return MasterKeyResult.Available(masterKey)
    }

    /**
     * Returns once the file or directory at [path] is on stable storage, as
     * far as `fsync` promises that. For a directory this covers its entries:
     * a file created in it, or renamed into it, keeps its name.
     */
    internal fun syncToDisk(path: File) {
        val fd = Os.open(path.path, OsConstants.O_RDONLY, 0)
        try {
            Os.fsync(fd)
        } finally {
            Os.close(fd)
        }
    }

    /**
     * [load] for the app's own files: the blob in `filesDir`, the store at
     * `filesDir/[storeName]`. Returns the key, or throws
     * [MasterKeyUnavailableException] without creating or replacing anything.
     */
    fun getOrCreateMasterKey(context: Context, storeName: String = "arcium.db"): ByteArray =
        when (val r = load(context.filesDir, File(context.filesDir, storeName))) {
            is MasterKeyResult.Available -> r.key
            else -> throw MasterKeyUnavailableException(r)
        }

    /**
     * A store is present if its file or its rollback journal exists, empty or
     * not: any of them may hold data written under the lost key.
     */
    private fun storeExists(store: File): Boolean =
        store.exists() || File(store.path + "-journal").exists()

    private fun create(dir: File, blobFile: File, alias: String, sync: (File) -> Unit): MasterKeyResult {
        // The array is allocated outside the cleanup boundary because the JVM
        // zero-initializes it; the boundary starts at the first point where it
        // can hold secret bytes, which is nextBytes() below.
        val masterKey = ByteArray(MASTER_KEY_BYTES)
        try {
            val wrapKey = getOrCreateWrapKey(alias)
            SecureRandom().nextBytes(masterKey)
            // Write via temp file + rename so a crash mid-write cannot leave a
            // truncated blob that would permanently lock the database out.
            // The file is synced before it gets the blob's name, so that
            // after a power loss the name does not lead to a file without its
            // contents; the directory is synced after, so that the name is on
            // disk before the key is returned.
            val tmp = File(dir, "$BLOB_FILE_NAME.tmp")
            tmp.writeBytes(wrap(masterKey, wrapKey))
            sync(tmp)
            check(tmp.renameTo(blobFile)) { "failed to persist wrapped master key" }
            sync(dir)
        } catch (t: Throwable) {
            // Best-effort scrub on every failure, errors included: the caller
            // never receives the key on this path. Deliberately not a finally
            // block — on the success path the array is handed to the caller live.
            masterKey.fill(0)
            if (t !is Exception) throw t
            return MasterKeyResult.Unavailable("a new master key could not be stored (${t.javaClass.simpleName})")
        }
        return MasterKeyResult.Available(masterKey)
    }

    /** The existing wrapping key, or null. Never creates one. */
    private fun existingWrapKey(alias: String): SecretKey? {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return keyStore.getKey(alias, null) as? SecretKey
    }

    private fun getOrCreateWrapKey(alias: String): SecretKey {
        existingWrapKey(alias)?.let { return it }
        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
        )
        generator.init(
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    private fun wrap(masterKey: ByteArray, wrapKey: SecretKey): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, wrapKey)
        check(cipher.iv.size == GCM_IV_BYTES) { "unexpected GCM IV length ${cipher.iv.size}" }
        return byteArrayOf(BLOB_VERSION) + cipher.iv + cipher.doFinal(masterKey)
    }

    private fun unwrap(blob: ByteArray, wrapKey: SecretKey): ByteArray {
        check(blob.size > 1 + GCM_IV_BYTES && blob[0] == BLOB_VERSION) {
            "unrecognized master key blob (version=${blob.getOrNull(0)}, size=${blob.size})"
        }
        val iv = blob.copyOfRange(1, 1 + GCM_IV_BYTES)
        val ciphertext = blob.copyOfRange(1 + GCM_IV_BYTES, blob.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, wrapKey, GCMParameterSpec(GCM_TAG_BITS, iv))
        val masterKey = cipher.doFinal(ciphertext)
        try {
            check(masterKey.size == MASTER_KEY_BYTES) { "unwrapped key has wrong length ${masterKey.size}" }
        } catch (t: Throwable) {
            // Same reasoning as the creation path: the decrypted bytes never
            // reach the caller when this check fails, so scrub them first.
            masterKey.fill(0)
            throw t
        }
        return masterKey
    }
}
