package com.arcium.messenger.messaging

import android.content.Context
import com.arcium.messenger.BuildConfig
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * The relay this device talks to. There is no default: messaging stays off
 * until the user enters one.
 *
 * Every build accepts a V2 connection string from the relay's operator
 * (`arcium-relay-v2:…`): TLS 1.3 to the relay's pinned key, and only this
 * device can read or delete its mailbox (docs/NET-MESSAGING.md, section 3).
 * Only a debug build ([BuildConfig.DEV_RELAY_ALLOWED]) also accepts
 * `host:port` of a development relay (V1: no TLS, no authentication), so a
 * release build never talks to an unauthenticated plaintext relay, not even
 * one stored earlier: what is stored is checked again on every start
 * ([relayChoice]).
 */
class RelaySettings(context: Context) {

    private val prefs = context.getSharedPreferences("relay", Context.MODE_PRIVATE)

    private val _address = MutableStateFlow(
        prefs.getString(KEY, null)?.let { relayChoice(it, BuildConfig.DEV_RELAY_ALLOWED)?.address },
    )

    /**
     * What the Rust core is given: a V2 connection string or, in a debug
     * build, `host:port`; null while none is configured.
     */
    val address: StateFlow<String?> = _address

    /** Stores [value] if this build may use it ([relayChoice]); throws IllegalArgumentException otherwise. */
    fun set(value: String) {
        val choice = requireNotNull(relayChoice(value, BuildConfig.DEV_RELAY_ALLOWED)) {
            relayInputHint(BuildConfig.DEV_RELAY_ALLOWED)
        }
        prefs.edit().putString(KEY, choice.address).apply()
        _address.value = choice.address
    }

    fun clear() {
        prefs.edit().remove(KEY).apply()
        _address.value = null
    }

    private companion object {
        /** The name predates V2; kept so a configured relay survives the update. */
        const val KEY = "dev_relay_address"
    }
}
