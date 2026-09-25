package com.arcium.messenger.ui.contacts

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.arcium.messenger.ArciumApp
import com.arcium.messenger.messaging.ContactCardText
import com.arcium.messenger.messaging.MessengerService
import com.arcium.messenger.ui.toHex
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.arcium_core.CoreException
import uniffi.arcium_core.contactCardFingerprint

data class AddContactState(
    /** This device's card, to give to the contact. */
    val myCardText: String = "",
    val myFingerprint: String = "",
    val input: String = "",
    /** Fingerprint of the pasted card, once it parses. */
    val theirFingerprint: String? = null,
    val inputError: String? = null,
    val name: String = "",
    /** The user confirmed both screens show the same fingerprint. */
    val fingerprintsMatch: Boolean = false,
    val saving: Boolean = false,
    /** A refusal to show, never cleared silently. */
    val error: String? = null,
    /** Set once the contact is pinned: the peer key in hex. */
    val added: String? = null,
) {
    val canAdd: Boolean
        get() = theirFingerprint != null && fingerprintsMatch && name.isNotBlank() && !saving
}

/**
 * Exchanging contact cards out of band. Nothing is trusted on first use: a
 * card is pinned only after the user confirms that its fingerprint equals the
 * one shown on the contact's own screen, and Rust refuses to replace an
 * identity already pinned (`ContactIdentityChanged`).
 */
class AddContactViewModel(
    private val service: MessengerService = ArciumApp.messenger,
) : ViewModel() {

    private val _state = MutableStateFlow(AddContactState())
    val state: StateFlow<AddContactState> = _state

    private var ownCard: ByteArray? = null

    init {
        viewModelScope.launch {
            try {
                val card = withContext(Dispatchers.IO) { ArciumApp.core.contactCard() }
                ownCard = card
                _state.value = _state.value.copy(
                    myCardText = ContactCardText.encode(card),
                    myFingerprint = contactCardFingerprint(card),
                )
            } catch (e: CoreException) {
                _state.value = _state.value.copy(error = "Could not read this device's card: ${e.message}")
            }
        }
    }

    fun onInput(text: String) {
        val card = ContactCardText.decode(text)
        val (fingerprint, error) = when {
            text.isBlank() -> null to null
            card == null -> null to "Not an Arcium contact card"
            card.contentEquals(ownCard) -> null to "This is your own card"
            else -> try {
                contactCardFingerprint(card) to null
            } catch (e: CoreException) {
                null to "Not a valid contact card: ${e.message}"
            }
        }
        _state.value = _state.value.copy(
            input = text,
            theirFingerprint = fingerprint,
            inputError = error,
            // A different card needs a new comparison.
            fingerprintsMatch = false,
            error = null,
        )
    }

    fun onName(name: String) {
        _state.value = _state.value.copy(name = name)
    }

    fun onFingerprintsMatch(match: Boolean) {
        _state.value = _state.value.copy(fingerprintsMatch = match)
    }

    fun add() {
        val s = _state.value
        val card = ContactCardText.decode(s.input)
        if (!s.canAdd || card == null) return
        _state.value = s.copy(saving = true, error = null)
        viewModelScope.launch {
            _state.value = try {
                val peer = service.call { it.addNamedContact(card, s.name.trim()) }
                service.changed()
                _state.value.copy(saving = false, added = peer.toHex())
            } catch (e: CoreException.ContactIdentityChanged) {
                _state.value.copy(
                    saving = false,
                    error = "Warning: a different card is already verified for this contact's " +
                        "identity. Nothing was changed. Someone may be impersonating your contact; " +
                        "this app does not replace a verified identity.",
                )
            } catch (e: CoreException) {
                _state.value.copy(saving = false, error = "Not added: ${e.message}")
            }
        }
    }
}
