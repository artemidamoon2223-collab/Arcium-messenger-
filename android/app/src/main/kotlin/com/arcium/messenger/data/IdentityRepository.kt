package com.arcium.messenger.data

import com.arcium.messenger.ffi.ArciumCoreWrapper
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class IdentityRepository @Inject constructor(
    private val core: ArciumCoreWrapper,
) {
    /** Generate a new identity and persist it via the encrypted store. */
    fun generateAndSave(): ByteArray {
        // TODO: call core.generateIdentity(), then core.openEncryptedDb() + save
        return core.generateIdentity()
    }

    /** Load the persisted identity public key, or null if none exists. */
    fun loadPublicKey(): ByteArray? {
        // TODO: open encrypted db, load IDENTITY_KEY entry
        return null
    }
}
