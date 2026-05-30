package com.arcium.messenger.ui.chat

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.arcium.messenger.data.Message
import com.arcium.messenger.data.MessageRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

data class ChatState(
    val messages: List<Message> = emptyList(),
    val isSending: Boolean = false,
    val error: String? = null,
)

@HiltViewModel
class ChatViewModel @Inject constructor(
    private val messageRepo: MessageRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(ChatState())
    val state: StateFlow<ChatState> = _state

    private var sessionId: String = ""

    fun init(sessionId: String) {
        this.sessionId = sessionId
        _state.value = _state.value.copy(messages = messageRepo.getHistory(sessionId))
    }

    fun sendMessage(text: String) {
        viewModelScope.launch {
            _state.value = _state.value.copy(isSending = true, error = null)
            // TODO: encode text as UTF-8, call messageRepo.send(sessionId, bytes)
            val result = messageRepo.send(sessionId, text.toByteArray())
            _state.value = _state.value.copy(isSending = false)
            result.onFailure { _state.value = _state.value.copy(error = it.message) }
        }
    }
}
