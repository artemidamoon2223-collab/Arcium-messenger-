package com.arcium.messenger.ui.settings

import androidx.lifecycle.ViewModel
import com.arcium.messenger.ArciumApp
import com.arcium.messenger.BuildConfig
import com.arcium.messenger.messaging.MessengerService
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

data class SettingsState(
    val relayInput: String = "",
    val savedRelay: String? = null,
    /** This build also accepts a development relay's `host:port` (debug builds). */
    val devRelayAllowed: Boolean = BuildConfig.DEV_RELAY_ALLOWED,
    val error: String? = null,
    /** The user turned background receive on. */
    val background: Boolean = false,
)

class SettingsViewModel(
    private val service: MessengerService = ArciumApp.messenger,
) : ViewModel() {

    private val _state = MutableStateFlow(
        SettingsState(
            relayInput = service.relay.address.value.orEmpty(),
            savedRelay = service.relay.address.value,
            background = service.background.enabled.value,
        ),
    )
    val state: StateFlow<SettingsState> = _state

    fun onRelayInput(value: String) {
        _state.value = _state.value.copy(relayInput = value, error = null)
    }

    fun saveRelay() {
        try {
            service.relay.set(_state.value.relayInput)
            _state.value = _state.value.copy(savedRelay = service.relay.address.value, error = null)
            service.changed()
        } catch (e: IllegalArgumentException) {
            _state.value = _state.value.copy(error = e.message)
        }
    }

    fun clearRelay() {
        service.relay.clear()
        _state.value = _state.value.copy(relayInput = "", savedRelay = null, error = null)
        service.changed()
    }

    /**
     * Stores the user's choice. The visible app starts the background service
     * when it may run (MainActivity); the service stops itself when it is
     * turned off.
     */
    fun setBackground(on: Boolean) {
        service.background.set(on)
        _state.value = _state.value.copy(background = on)
    }
}
