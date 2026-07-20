package com.arcium.messenger.data

import com.arcium.messenger.ArciumApp
import com.arcium.messenger.ffi.ArciumCoreWrapper

class IdentityRepository(private val core: ArciumCoreWrapper = ArciumApp.core) {

    /**
     * Generates a new identity, persists it into the encrypted store, and
     * returns the 32-byte public key. Errors (DB not open, storage failure)
     * propagate to the caller — there is no silent skip.
     */
    fun generateAndSave(): ByteArray = core.generateAndSaveIdentity()

    /** Returns the stored identity's public key, or null if none is saved. */
    fun loadPublicKey(): ByteArray? = core.loadIdentityPublicKey()
}
