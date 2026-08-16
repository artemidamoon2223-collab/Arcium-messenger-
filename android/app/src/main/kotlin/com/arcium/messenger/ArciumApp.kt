package com.arcium.messenger

import android.app.Application
import com.arcium.messenger.ffi.ArciumCoreWrapper
import com.arcium.messenger.security.MasterKeyProvider
import java.io.File

class ArciumApp : Application() {

    override fun onCreate() {
        super.onCreate()
        // Open the encrypted store once per process. Failures propagate and
        // crash startup visibly — a silently-missing store would recreate the
        // false-success pattern this wiring exists to remove.
        val wrapper = ArciumCoreWrapper()
        val masterKey = MasterKeyProvider.getOrCreateMasterKey(this)
        try {
            wrapper.openEncryptedDb(File(filesDir, "arcium.db").absolutePath, masterKey)
        } finally {
            // The raw key stays only inside the Rust store from here on.
            masterKey.fill(0)
        }
        core = wrapper
    }

    companion object {
        /** Process-wide core handle, initialized in [onCreate]. */
        lateinit var core: ArciumCoreWrapper
            private set
    }
}
