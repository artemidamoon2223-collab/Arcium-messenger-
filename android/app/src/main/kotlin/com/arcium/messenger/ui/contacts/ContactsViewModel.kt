package com.arcium.messenger.ui.contacts

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.arcium.messenger.data.Contact
import com.arcium.messenger.data.ContactRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

data class ContactsState(
    val contacts: List<Contact> = emptyList(),
    val isDiscovering: Boolean = false,
    val error: String? = null,
)

@HiltViewModel
class ContactsViewModel @Inject constructor(
    private val contactRepo: ContactRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(ContactsState())
    val state: StateFlow<ContactsState> = _state

    init {
        loadContacts()
    }

    private fun loadContacts() {
        _state.value = _state.value.copy(contacts = contactRepo.getAllContacts())
    }

    fun discoverContacts(phoneNumbers: List<String>) {
        viewModelScope.launch {
            _state.value = _state.value.copy(isDiscovering = true, error = null)
            try {
                // TODO: run PSI via Arcium MPC cluster (core.submitPsiQuery)
                val found = contactRepo.discoverContacts(phoneNumbers)
                _state.value = _state.value.copy(isDiscovering = false, contacts = found)
            } catch (e: Exception) {
                _state.value = _state.value.copy(isDiscovering = false, error = e.message)
            }
        }
    }
}
