package com.arcium.messenger.ui.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

data class SettingsState(
    val torEnabled: Boolean = true,
    val bluetoothMeshEnabled: Boolean = false,
    val keyBackupEnabled: Boolean = false,
)

val KEY_TOR = booleanPreferencesKey("tor_enabled")
val KEY_MESH = booleanPreferencesKey("bluetooth_mesh_enabled")
val KEY_BACKUP = booleanPreferencesKey("key_backup_enabled")

@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val dataStore: DataStore<Preferences>,
) : ViewModel() {

    private val _state = MutableStateFlow(SettingsState())
    val state: StateFlow<SettingsState> = _state

    fun setTorEnabled(enabled: Boolean) {
        viewModelScope.launch {
            dataStore.edit { it[KEY_TOR] = enabled }
            _state.value = _state.value.copy(torEnabled = enabled)
            // TODO: start/stop TorManager accordingly
        }
    }

    fun setBluetoothMeshEnabled(enabled: Boolean) {
        viewModelScope.launch {
            dataStore.edit { it[KEY_MESH] = enabled }
            _state.value = _state.value.copy(bluetoothMeshEnabled = enabled)
            // TODO: start/stop BluetoothMeshManager accordingly
        }
    }

    fun setKeyBackupEnabled(enabled: Boolean) {
        viewModelScope.launch {
            dataStore.edit { it[KEY_BACKUP] = enabled }
            _state.value = _state.value.copy(keyBackupEnabled = enabled)
            // TODO: trigger encrypted key export flow
        }
    }
}
