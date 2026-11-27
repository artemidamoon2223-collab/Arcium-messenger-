package com.arcium.messenger.ui.settings

import androidx.lifecycle.ViewModel
import com.arcium.messenger.ArciumApp
import com.arcium.messenger.BuildConfig
import com.arcium.messenger.messaging.MessengerService
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import uniffi.arcium_core.TorState

data class SettingsState(
    val relayInput: String = "",
    val savedRelay: String? = null,
    /** This build also accepts a development relay's `host:port` (debug builds). */
    val devRelayAllowed: Boolean = BuildConfig.DEV_RELAY_ALLOWED,
    val error: String? = null,
    /** The user turned background receive on. */
    val background: Boolean = false,
    /** The process's Tor client, as last read ([SettingsViewModel.refreshTor]); null before the first read. */
    val tor: TorState? = null,
)

class SettingsViewModel(
    private val service: MessengerService = ArciumApp.messenger,
    private val torState: () -> TorState = { ArciumApp.core.torState() },
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
        _state.update { it.copy(relayInput = value, error = null) }
    }

    fun saveRelay() {
        try {
            service.relay.set(_state.value.relayInput)
            _state.update { it.copy(savedRelay = service.relay.address.value, error = null) }
            service.changed()
        } catch (e: IllegalArgumentException) {
            _state.update { it.copy(error = e.message) }
        }
    }

    fun clearRelay() {
        service.relay.clear()
        _state.update { it.copy(relayInput = "", savedRelay = null, error = null) }
        service.changed()
    }

    /**
     * Reads the Tor client's state again; it answers at once (`tor_state()`).
     * Called off the main thread. Every change of the state in this class is
     * one atomic [update] of the fields it changes, so this one and those
     * made on the main thread (typing in the relay field, for one) never
     * undo each other.
     */
    fun refreshTor() {
        val tor = torState()
        _state.update { it.copy(tor = tor) }
    }

    /**
     * Stores the user's choice. The visible app starts the background service
     * when it may run (MainActivity); the service stops itself when it is
     * turned off.
     */
    fun setBackground(on: Boolean) {
        service.background.set(on)
        _state.update { it.copy(background = on) }
    }
}
