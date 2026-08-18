package com.arcium.messenger.ui.chat

import androidx.lifecycle.ViewModel
import com.arcium.messenger.data.Message
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

data class ChatState(
    val messages: List<Message> = emptyList(),
    val isSending: Boolean = false,
    val error: String? = null,
)

/**
 * Chat screen state.
 *
 * This screen cannot yet send or show messages, and says so rather than looking
 * like it worked. Two pieces are missing below it, both outside this layer:
 *
 * - **Transport.** `mobile-ffi` exports none, so a ciphertext produced by
 *   MessageRepository has no way to reach the peer. Encryption without delivery
 *   is not a sent message.
 * - **A peer identity.** Sessions are addressed by the peer's 32-byte identity
 *   public key, and contact discovery (PSI) does not yet yield one. The route
 *   argument reaching this screen is a display label, not a key and not a
 *   session handle.
 *
 * History is likewise absent rather than empty: messages are not persisted
 * anywhere, since the encrypted store exposes no key-value surface over FFI.
 * Showing an empty list as though it were the full history would be the same
 * false success this rewrite removed from MessageRepository.
 */
class ChatViewModel : ViewModel() {

    private val _state = MutableStateFlow(ChatState())
    val state: StateFlow<ChatState> = _state

    fun sendMessage(text: String) {
        if (text.isBlank()) return
        _state.value = _state.value.copy(
            isSending = false,
            error = "Not sent. Message transport is not wired yet: the Rust core can " +
                "encrypt for an established session, but nothing can deliver the " +
                "ciphertext to the peer, and this chat has no peer identity key.",
        )
    }
}
