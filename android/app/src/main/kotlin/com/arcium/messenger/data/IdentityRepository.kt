package com.arcium.messenger.data

import com.arcium.messenger.ArciumApp
import com.arcium.messenger.ffi.ArciumCoreWrapper
import uniffi.arcium_core.CoreException

/** What the app knows about this device's identity. */
sealed interface IdentityState {
    data object Loading : IdentityState

    data object Present : IdentityState

    /** The store holds no identity: the only state in which one is created. */
    data object Absent : IdentityState

    /** The identity could not be read. Not [Absent]: nothing may be created. */
    data class Failed(val message: String) : IdentityState
}

class IdentityRepository(
    private val loadKey: () -> ByteArray?,
    private val createKey: () -> ByteArray,
) {
    constructor(core: ArciumCoreWrapper = ArciumApp.core) :
        this(core::loadIdentityPublicKey, core::generateAndSaveIdentity)

    /**
     * Reads the identity. A failure is [IdentityState.Failed], never
     * [IdentityState.Absent]. Only reads: never creates, deletes or replaces.
     */
    fun load(): IdentityState = try {
        if (loadKey() != null) IdentityState.Present else IdentityState.Absent
    } catch (e: CoreException) {
        IdentityState.Failed(e.message.orEmpty())
    }

    /**
     * Creates an identity and returns its public key. If one is already
     * stored, it is kept and loaded instead, and its key is returned; an
     * identity that cannot be loaded throws. Other errors (DB not open,
     * storage failure, an unreadable identity) propagate — there is no silent
     * skip, and nothing is ever replaced.
     */
    fun createOrLoadExisting(): ByteArray = try {
        createKey()
    } catch (e: CoreException.IdentityAlreadyExists) {
        loadKey() ?: throw IllegalStateException("an identity is stored but none was found to load", e)
    }
}
