package com.arcium.messenger.ui.chat

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.arcium.messenger.ArciumApp
import com.arcium.messenger.messaging.RelayLink
import com.arcium.messenger.ui.hexToBytes
import java.security.SecureRandom
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import uniffi.arcium_core.ChatEntry
import uniffi.arcium_core.CoreException
import uniffi.arcium_core.Conversation

data class ChatState(
    val conversation: Conversation? = null,
    val entries: List<ChatEntry> = emptyList(),
    val link: RelayLink = RelayLink.NotConfigured,
    val input: String = "",
    val sending: Boolean = false,
    val error: String? = null,
) {
    /**
     * The generated `toString` would print [input], the user's unsent draft.
     * This one prints `<redacted>` in its place and the other fields as
     * before; a field added later is not printed until it is added here. It
     * covers accidental formatting only: [input] is an ordinary `String`,
     * nothing wipes it, and code that reads it still gets the draft.
     */
    override fun toString(): String =
        "ChatState(conversation=$conversation, entries=$entries, link=$link, " +
            "input=<redacted>, sending=$sending, error=$error)"
}

/** Prefix of the error a failed reload shows; a later successful one clears it. */
internal const val READ_ERROR_PREFIX = "Could not read the conversation: "

/**
 * The state after a failed reload: the read error, replacing any error
 * shown before.
 */
internal fun ChatState.afterFailedReload(message: String?): ChatState =
    copy(error = READ_ERROR_PREFIX + message)

/**
 * The state after a successful reload. A read error a failed reload left is
 * cleared, because the conversation was read now; any other error (a text
 * not saved, a conflict not resolved) stays until the user acts on it.
 */
internal fun ChatState.afterReload(conversation: Conversation, entries: List<ChatEntry>): ChatState =
    copy(
        conversation = conversation,
        entries = entries,
        error = error?.takeUnless { it.startsWith(READ_ERROR_PREFIX) },
    )

/**
 * One conversation. The history, every message state and the session come
 * from Rust (`network/chat.rs`); this class holds only what the user is
 * typing and the id of a text whose recording has not been confirmed yet.
 *
 * Each logical message gets one random id when the user first sends it. If
 * recording it fails, the text and that id stay here, and sending again
 * repeats the call with the same id — Rust then returns what it already has
 * and never encrypts the text twice. A resend of a message that was given up
 * on is a new message with a new id, and only on the user's request.
 */
class ChatViewModel(savedState: SavedStateHandle) : ViewModel() {

    private val service = ArciumApp.messenger
    private val peer: ByteArray = checkNotNull(savedState.get<String>("peer")).hexToBytes()

    private val _state = MutableStateFlow(ChatState())
    val state: StateFlow<ChatState> = _state

    /** The text being sent and the id it was first sent under. */
    private var unconfirmed: Pair<String, ByteArray>? = null

    init {
        viewModelScope.launch { service.revision.collect { reload() } }
        viewModelScope.launch {
            service.link.collect { _state.value = _state.value.copy(link = it) }
        }
    }

    private suspend fun reload() {
        try {
            val (conversation, entries) = service.call { m ->
                val entries = m.chatEntries(peer)
                m.markSeen(peer)
                m.conversation(peer) to entries
            }
            _state.value = _state.value.afterReload(conversation, entries)
        } catch (e: CoreException) {
            _state.value = _state.value.afterFailedReload(e.message)
        }
    }

    fun onInput(text: String) {
        _state.value = _state.value.copy(input = text)
    }

    fun send() {
        val text = _state.value.input.trim()
        if (text.isEmpty() || _state.value.sending) return
        val id = unconfirmed?.takeIf { it.first == text }?.second ?: newAppId()
        unconfirmed = text to id
        record(text, id, clearInput = true)
    }

    /** Sends the text of a message given up on again, as a new message. */
    fun resend(entry: ChatEntry) {
        if (_state.value.sending) return
        record(entry.text.value, newAppId(), clearInput = false)
    }

    private fun record(text: String, id: ByteArray, clearInput: Boolean) {
        _state.value = _state.value.copy(sending = true, error = null)
        viewModelScope.launch {
            try {
                service.call { it.chatSend(peer, id, text) }
                if (clearInput) {
                    unconfirmed = null
                    if (_state.value.input.trim() == text) _state.value = _state.value.copy(input = "")
                }
                _state.value = _state.value.copy(sending = false)
            } catch (e: CoreException) {
                _state.value = _state.value.copy(
                    sending = false,
                    error = "Not saved: ${e.message}. Send again to retry.",
                )
            }
            service.changed()
        }
    }

    fun resolveConflict() {
        viewModelScope.launch {
            try {
                service.call { it.resolveSessionConflict(peer) }
            } catch (e: CoreException) {
                _state.value = _state.value.copy(error = "Not resolved: ${e.message}")
            }
            service.changed()
        }
    }

    private fun newAppId(): ByteArray = ByteArray(16).also { random.nextBytes(it) }

    private companion object {
        val random = SecureRandom()
    }
}
