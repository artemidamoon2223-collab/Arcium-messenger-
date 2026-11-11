package com.arcium.messenger.startup

import com.arcium.messenger.ffi.ArciumCoreWrapper
import com.arcium.messenger.security.MasterKeyProvider
import com.arcium.messenger.security.MasterKeyResult
import java.io.File
import uniffi.arcium_core.CoreException

/**
 * Opens the encrypted store in a directory with its master key, or reports why
 * it cannot. Creates a key only on a first run (no blob and no store), so a
 * failure leaves every existing file as it was.
 */
object StoreStartup {

    const val STORE_FILE_NAME = "arcium.db"

    sealed interface Result {
        /** The store is open; the caller owns [core]. */
        class Opened(val core: ArciumCoreWrapper) : Result

        data class Failed(val problem: StartupProblem) : Result
    }

    /** [alias] is the Keystore alias of the wrapping key; tests pass their own. */
    fun open(dir: File, alias: String = MasterKeyProvider.KEYSTORE_ALIAS): Result {
        val store = File(dir, STORE_FILE_NAME)
        return when (val key = MasterKeyProvider.load(dir, store, alias)) {
            MasterKeyResult.MissingForExistingStore -> Result.Failed(StartupProblem.KeyMissingForExistingData)
            is MasterKeyResult.Unavailable -> Result.Failed(StartupProblem.KeyUnavailable(key.reason))
            is MasterKeyResult.Available -> {
                val core = ArciumCoreWrapper()
                try {
                    core.openEncryptedDb(store.absolutePath, key.key)
                    Result.Opened(core)
                } catch (e: CoreException) {
                    Result.Failed(StartupProblem.StoreUnavailable("the store did not open (${e.javaClass.simpleName})"))
                } finally {
                    // The raw key stays only inside the Rust store from here on.
                    key.key.fill(0)
                }
            }
        }
    }
}
