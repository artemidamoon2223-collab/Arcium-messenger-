package com.arcium.messenger.ui.settings

import androidx.lifecycle.ViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

data class SettingsState(
    val torEnabled: Boolean = true,
    val bluetoothMeshEnabled: Boolean = false,
    val keyBackupEnabled: Boolean = false,
)

class SettingsViewModel : ViewModel() {

    private val _state = MutableStateFlow(SettingsState())
    val state: StateFlow<SettingsState> = _state

    fun setTorEnabled(enabled: Boolean) {
        _state.value = _state.value.copy(torEnabled = enabled)
        // TODO: wire to core.startTorTransport() / stop via UniFFI
    }

    fun setBluetoothMeshEnabled(enabled: Boolean) {
        _state.value = _state.value.copy(bluetoothMeshEnabled = enabled)
        // TODO: start/stop BluetoothMeshManager
    }

    fun setKeyBackupEnabled(enabled: Boolean) {
        _state.value = _state.value.copy(keyBackupEnabled = enabled)
        // TODO: trigger encrypted key export flow
    }
}
