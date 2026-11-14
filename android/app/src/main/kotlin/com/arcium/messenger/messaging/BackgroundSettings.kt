package com.arcium.messenger.messaging

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Whether the user turned background receive on ([BackgroundReceiveService]).
 * Off until they do. Kept in the app's private preferences, as
 * [RelaySettings] keeps the relay address; whether the service may actually
 * run is [backgroundState].
 */
class BackgroundSettings(context: Context) {

    private val prefs = context.getSharedPreferences("background", Context.MODE_PRIVATE)

    private val _enabled = MutableStateFlow(prefs.getBoolean(KEY, false))

    val enabled: StateFlow<Boolean> = _enabled

    fun set(enabled: Boolean) {
        prefs.edit().putBoolean(KEY, enabled).apply()
        _enabled.value = enabled
    }

    private companion object {
        const val KEY = "receive_in_background"
    }
}
