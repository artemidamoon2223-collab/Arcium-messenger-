package com.arcium.messenger.ui.chat

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.arcium.messenger.data.Message
import com.arcium.messenger.data.MessageRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

data class ChatState(
    val messages: List<Message> = emptyList(),
    val isSending: Boolean = false,
    val error: String? = null,
)

class ChatViewModel(
    private val messageRepo: MessageRepository = MessageRepository(),
) : ViewModel() {

    private val _state = MutableStateFlow(ChatState())
    val state: StateFlow<ChatState> = _state

    private var sessionId: String = ""

    fun init(sessionId: String) {
        this.sessionId = sessionId
        _state.value = _state.value.copy(messages = messageRepo.getHistory(sessionId))
    }

    /**
     * [onSent] is invoked only when [messageRepo.send] reports a real success —
     * never unconditionally. This keeps UI state (e.g. clearing the input field)
     * honest about whether an outbound message operation actually happened.
     */
    fun sendMessage(text: String, onSent: () -> Unit = {}) {
        viewModelScope.launch {
            _state.value = _state.value.copy(isSending = true, error = null)
            val result = messageRepo.send(sessionId, text.toByteArray())
            _state.value = _state.value.copy(isSending = false)
            result.onSuccess { onSent() }
            result.onFailure { _state.value = _state.value.copy(error = it.message) }
        }
    }
}
