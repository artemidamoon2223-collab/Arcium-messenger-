package com.arcium.messenger

import android.app.Application
import com.arcium.messenger.ffi.ArciumCoreWrapper
import com.arcium.messenger.messaging.BackgroundSettings
import com.arcium.messenger.messaging.MessengerService
import com.arcium.messenger.messaging.RelaySettings
import com.arcium.messenger.startup.AppStartup
import com.arcium.messenger.startup.StartupState
import com.arcium.messenger.startup.StoreStartup

class ArciumApp : Application() {

    override fun onCreate() {
        super.onCreate()
        // Open the encrypted store once per process. A missing or unusable
        // master key blocks start-up instead of crashing it or replacing the
        // key: `startup` reports why, and nothing below it exists until it is
        // Ready (MainActivity shows the error and a retry meanwhile).
        startup = AppStartup(::initialize)
        startup.start()
    }

    /** Called by [startup] only, one call at a time, until it returns Ready. */
    private fun initialize(): StartupState = when (val opened = StoreStartup.open(filesDir)) {
        is StoreStartup.Result.Failed -> StartupState.Blocked(opened.problem)
        is StoreStartup.Result.Opened -> {
            val service = try {
                MessengerService(this, opened.core, RelaySettings(this), BackgroundSettings(this))
            } catch (e: Exception) {
                opened.core.closeEncryptedDb()
                throw e
            }
            core = opened.core
            messenger = service
            StartupState.Ready
        }
    }

    companion object {
        /** Process-wide start-up gate, created in [onCreate]. */
        lateinit var startup: AppStartup
            private set

        /** Process-wide core handle. Set only once [startup] is Ready. */
        lateinit var core: ArciumCoreWrapper
            private set

        /** Process-wide messenger over [core]. Set only once [startup] is Ready. */
        lateinit var messenger: MessengerService
            private set
    }
}
