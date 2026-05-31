package com.arcium.messenger.data

import com.arcium.messenger.ffi.ArciumCoreWrapper

class IdentityRepository(private val core: ArciumCoreWrapper = ArciumCoreWrapper()) {

    fun generateAndSave(): ByteArray {
        // TODO: core.generateIdentity(), then core.openEncryptedDb() + persist
        return core.generateIdentity()
    }

    fun loadPublicKey(): ByteArray? {
        // TODO: open encrypted db, load IDENTITY_KEY entry
        return null
    }
}
