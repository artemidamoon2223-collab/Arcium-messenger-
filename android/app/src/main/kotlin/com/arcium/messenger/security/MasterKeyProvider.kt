package com.arcium.messenger.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Provides the 32-byte master key for the Rust encrypted store.
 *
 * Scheme: a random 32-byte master key is generated once with [SecureRandom]
 * and stored on disk ONLY in wrapped (encrypted) form. The wrapping key is an
 * AES-256-GCM key that lives inside AndroidKeyStore and is not exportable.
 * Blob layout at files/master_key.blob: [1-byte version][12-byte GCM IV][ciphertext+tag].
 *
 * All failures (Keystore, IO, decryption) propagate to the caller — a master
 * key that cannot be created or unwrapped must never be silently replaced,
 * because replacing it would orphan the existing encrypted database.
 */
object MasterKeyProvider {

    private const val KEYSTORE_ALIAS = "arcium_master_key_wrap"
    private const val BLOB_FILE_NAME = "master_key.blob"
    private const val BLOB_VERSION: Byte = 1
    private const val GCM_IV_BYTES = 12
    private const val GCM_TAG_BITS = 128
    private const val MASTER_KEY_BYTES = 32

    fun getOrCreateMasterKey(context: Context): ByteArray {
        val blobFile = File(context.filesDir, BLOB_FILE_NAME)
        val wrapKey = getOrCreateWrapKey()
        if (blobFile.exists()) {
            return unwrap(blobFile.readBytes(), wrapKey)
        }
        val masterKey = ByteArray(MASTER_KEY_BYTES).also { SecureRandom().nextBytes(it) }
        // Write via temp file + rename so a crash mid-write cannot leave a
        // truncated blob that would permanently lock the database out.
        val tmp = File(context.filesDir, "$BLOB_FILE_NAME.tmp")
        tmp.writeBytes(wrap(masterKey, wrapKey))
        check(tmp.renameTo(blobFile)) { "failed to persist wrapped master key" }
        return masterKey
    }

    private fun getOrCreateWrapKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(KEYSTORE_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
        )
        generator.init(
            KeyGenParameterSpec.Builder(
                KEYSTORE_ALIAS,
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
        check(masterKey.size == MASTER_KEY_BYTES) { "unwrapped key has wrong length ${masterKey.size}" }
        return masterKey
    }
}
