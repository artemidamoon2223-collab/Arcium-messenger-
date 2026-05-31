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
import androidx.lifecycle.viewmodel.compose.viewModel

@Composable
fun ChatScreen(
    sessionId: String,
    onBack: () -> Unit,
    viewModel: ChatViewModel = viewModel(),
) {
    val state by viewModel.state.collectAsState()
    var input by remember { mutableStateOf("") }

    LaunchedEffect(sessionId) { viewModel.init(sessionId) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(sessionId) },
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
            if (state.messages.isEmpty()) {
                item { Text("No messages yet.", modifier = Modifier.padding(16.dp)) }
            }
            items(state.messages) { msg ->
                // TODO: render bubbles with isMine alignment
                ListItem(headlineContent = { Text(msg.ciphertext.decodeToString()) })
            }
        }
    }
}
