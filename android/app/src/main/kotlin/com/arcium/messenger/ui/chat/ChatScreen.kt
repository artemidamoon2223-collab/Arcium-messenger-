package com.arcium.messenger.ui.chat

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.lifecycle.viewmodel.compose.viewModel

/**
 * [peerLabel] is a display label only. It is not a session handle and not a
 * peer identity key: sessions are addressed by the peer's 32-byte public key,
 * which contact discovery does not yet provide.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(
    peerLabel: String,
    onBack: () -> Unit,
    viewModel: ChatViewModel = viewModel(),
) {
    val state by viewModel.state.collectAsState()
    var input by remember { mutableStateOf("") }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(peerLabel) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        bottomBar = {
            Row(
                modifier = Modifier.fillMaxWidth().padding(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedTextField(
                    value = input,
                    onValueChange = { input = it },
                    modifier = Modifier.weight(1f),
                    placeholder = { Text("Message (E2E encrypted)") },
                )
                Spacer(Modifier.width(8.dp))
                IconButton(
                    onClick = { viewModel.sendMessage(input); input = "" },
                    enabled = input.isNotBlank() && !state.isSending,
                ) {
                    Icon(Icons.AutoMirrored.Filled.Send, contentDescription = "Send")
                }
            }
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            reverseLayout = true,
        ) {
            // Surfaced, not swallowed: a send that failed must not look to the
            // user exactly like a send that succeeded.
            state.error?.let { message ->
                item {
                    Text(
                        message,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.padding(16.dp),
                    )
                }
            }
            if (state.messages.isEmpty()) {
                item {
                    Text(
                        "No message history. Messages are not stored on this device yet.",
                        modifier = Modifier.padding(16.dp),
                    )
                }
            }
            items(state.messages) { msg ->
                // A Message holds ciphertext. Decoding those bytes as text would
                // paint an encrypted payload as if it had been read; showing the
                // size is the most this screen can honestly say until decryption
                // is wired to a peer identity. TODO: bubbles with isMine alignment.
                ListItem(
                    headlineContent = {
                        Text("Encrypted message (${msg.ciphertext.size} bytes), not decrypted")
                    },
                )
            }
        }
    }
}
