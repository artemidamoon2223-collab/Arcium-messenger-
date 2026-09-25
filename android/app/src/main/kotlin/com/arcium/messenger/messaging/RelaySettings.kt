package com.arcium.messenger.messaging

import android.content.Context
import com.arcium.messenger.BuildConfig
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * The relay this device talks to. There is no default and no production
 * relay: the only relay that exists is the development relay
 * (`arcium-relay`, docs/NET-MESSAGING.md) — no TLS, no authentication, in
 * memory. Messaging stays off until a user enters one, and only a debug build
 * accepts one ([BuildConfig.DEV_RELAY_ALLOWED]), so a release build cannot
 * silently talk to an unauthenticated plaintext relay.
 */
class RelaySettings(context: Context) {

    private val prefs = context.getSharedPreferences("relay", Context.MODE_PRIVATE)

    private val _address = MutableStateFlow(
        if (BuildConfig.DEV_RELAY_ALLOWED) prefs.getString(KEY, null) else null,
    )

    /** `host:port`, or null while none is configured. */
    val address: StateFlow<String?> = _address

    /** Stores [value] after [validate]; throws IllegalArgumentException otherwise. */
    fun set(value: String) {
        check(BuildConfig.DEV_RELAY_ALLOWED) { "this build does not use a development relay" }
        val address = requireNotNull(validate(value)) { "enter host:port, for example 10.0.2.2:7700" }
        prefs.edit().putString(KEY, address).apply()
        _address.value = address
    }

    fun clear() {
        prefs.edit().remove(KEY).apply()
        _address.value = null
    }

    companion object {
        private const val KEY = "dev_relay_address"

        /** `host:port` with a port from 1 to 65535, trimmed; null if it is not one. */
        fun validate(value: String): String? {
            val trimmed = value.trim()
            val colon = trimmed.lastIndexOf(':')
            if (colon <= 0) return null
            val host = trimmed.substring(0, colon)
            val port = trimmed.substring(colon + 1).toIntOrNull() ?: return null
            if (port !in 1..65535 || host.any { it.isWhitespace() || it == '/' }) return null
            return "$host:$port"
        }
    }
}
