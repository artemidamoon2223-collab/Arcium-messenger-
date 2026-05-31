package com.arcium.messenger.ui.contacts

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.arcium.messenger.data.Contact
import com.arcium.messenger.data.ContactRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

data class ContactsState(
    val contacts: List<Contact> = emptyList(),
    val isDiscovering: Boolean = false,
    val error: String? = null,
)

class ContactsViewModel(
    private val contactRepo: ContactRepository = ContactRepository(),
) : ViewModel() {

    private val _state = MutableStateFlow(ContactsState())
    val state: StateFlow<ContactsState> = _state

    init {
        _state.value = _state.value.copy(contacts = contactRepo.getAllContacts())
    }

    fun discoverContacts(phoneNumbers: List<String>) {
        viewModelScope.launch {
            _state.value = _state.value.copy(isDiscovering = true, error = null)
            try {
                val found = contactRepo.discoverContacts(phoneNumbers)
                _state.value = _state.value.copy(isDiscovering = false, contacts = found)
            } catch (e: Exception) {
                _state.value = _state.value.copy(isDiscovering = false, error = e.message)
            }
        }
    }
}
