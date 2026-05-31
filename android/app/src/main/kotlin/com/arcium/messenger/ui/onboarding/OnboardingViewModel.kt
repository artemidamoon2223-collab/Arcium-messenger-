package com.arcium.messenger.ui.onboarding

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.arcium.messenger.data.IdentityRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

data class OnboardingState(
    val isLoading: Boolean = false,
    val publicKey: ByteArray? = null,
    val error: String? = null,
)

class OnboardingViewModel(
    private val identityRepo: IdentityRepository = IdentityRepository(),
) : ViewModel() {

    private val _state = MutableStateFlow(OnboardingState())
    val state: StateFlow<OnboardingState> = _state

    fun generateIdentity() {
        viewModelScope.launch {
            _state.value = _state.value.copy(isLoading = true, error = null)
            try {
                val pk = identityRepo.generateAndSave()
                _state.value = _state.value.copy(isLoading = false, publicKey = pk)
            } catch (e: Exception) {
                _state.value = _state.value.copy(isLoading = false, error = e.message)
            }
        }
    }
}
