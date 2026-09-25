package com.arcium.messenger.ui.contacts

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.arcium.messenger.ArciumApp
import com.arcium.messenger.messaging.MessengerService
import com.arcium.messenger.messaging.RelayLink
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import uniffi.arcium_core.CoreException
import uniffi.arcium_core.Conversation

data class ContactsState(
    val conversations: List<Conversation> = emptyList(),
    val link: RelayLink = RelayLink.NotConfigured,
    val error: String? = null,
)

/** The contact list: every pinned contact with its conversation state, from Rust. */
class ContactsViewModel(
    private val service: MessengerService = ArciumApp.messenger,
) : ViewModel() {

    private val _state = MutableStateFlow(ContactsState())
    val state: StateFlow<ContactsState> = _state

    init {
        viewModelScope.launch {
            service.revision.collect {
                _state.value = try {
                    _state.value.copy(conversations = service.call { it.conversations() }, error = null)
                } catch (e: CoreException) {
                    _state.value.copy(error = "Could not read contacts: ${e.message}")
                }
            }
        }
        viewModelScope.launch {
            service.link.collect { _state.value = _state.value.copy(link = it) }
        }
    }
}
