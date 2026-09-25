package com.arcium.messenger.ui.chat

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.arcium.messenger.ui.contacts.LinkBanner
import java.text.DateFormat
import java.util.Date
import uniffi.arcium_core.ChatEntry
import uniffi.arcium_core.ChatEntryState
import uniffi.arcium_core.ChatSessionState
import uniffi.arcium_core.Conversation

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(
    onBack: () -> Unit,
    onOpenSettings: () -> Unit,
    viewModel: ChatViewModel = viewModel(),
) {
    val state by viewModel.state.collectAsState()
    val list = rememberLazyListState()
    LaunchedEffect(state.entries.size) {
        if (state.entries.isNotEmpty()) list.animateScrollToItem(state.entries.size - 1)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(state.conversation?.name ?: "")
                        Text(
                            state.conversation?.fingerprint ?: "",
                            style = MaterialTheme.typography.labelSmall,
                        )
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        bottomBar = {
            Row(
                modifier = Modifier.fillMaxWidth().imePadding().padding(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedTextField(
                    value = state.input,
                    onValueChange = viewModel::onInput,
                    modifier = Modifier.weight(1f).testTag("messageInput"),
                    placeholder = { Text("Message") },
                )
                IconButton(
                    onClick = viewModel::send,
                    enabled = state.input.isNotBlank() && !state.sending,
                    modifier = Modifier.testTag("send"),
                ) {
                    Icon(Icons.AutoMirrored.Filled.Send, contentDescription = "Send")
                }
            }
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            LinkBanner(state.link, onOpenSettings)
            state.conversation?.let { SessionBanner(it, viewModel::resolveConflict) }
            state.error?.let {
                Text(
                    it,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(horizontal = 16.dp).testTag("chatError"),
                )
            }
            LazyColumn(
                state = list,
                modifier = Modifier.fillMaxSize().padding(horizontal = 8.dp).testTag("chatList"),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                items(state.entries, key = { it.seq.toLong() }) { entry ->
                    Bubble(entry, onResend = { viewModel.resend(entry) })
                }
            }
        }
    }
}

/** The session and anything that stops texts from going out, in words. */
@Composable
private fun SessionBanner(c: Conversation, onResolve: () -> Unit) {
    val warnings = buildList {
        if (c.identityMismatch) {
            add(
                "⚠ The keys published for ${c.name} do not match the card you verified. " +
                    "Nothing was sent. Someone may be impersonating them; verify the " +
                    "fingerprint again.",
            )
        }
        if (c.handshakeRefused) {
            add("A secure session request from ${c.name} could not be accepted.")
        }
        when (val s = c.session) {
            is ChatSessionState.Conflict -> add(
                "You and ${c.name} both started a secure session at the same time, so neither " +
                    "can be read by the other. " + if (s.canResolve) {
                        "Resolve it here: your unsent messages will be marked not delivered " +
                            "and you can send them again."
                    } else {
                        "Waiting for ${c.name} to resolve it on their device."
                    },
            )
            ChatSessionState.AwaitingPeer -> add("Waiting for ${c.name} to accept the secure session.")
            ChatSessionState.AwaitingPeerSession -> add("Waiting for ${c.name}'s secure session.")
            ChatSessionState.None, ChatSessionState.Established -> {}
        }
        if (c.note.isNotEmpty()) add("Messages are queued: ${c.note}.")
    }
    if (warnings.isEmpty()) return
    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp).testTag("sessionBanner")) {
        warnings.forEach {
            Text(
                it,
                style = MaterialTheme.typography.bodySmall,
                color = if (it.startsWith("⚠")) MaterialTheme.colorScheme.error else Color.Unspecified,
            )
        }
        val session = c.session
        if (session is ChatSessionState.Conflict && session.canResolve) {
            Button(onClick = onResolve, modifier = Modifier.testTag("resolveConflict")) {
                Text("Resolve")
            }
        }
    }
}

/** What an entry state means to the user. Delivered is the only claim about the peer. */
fun statusLabel(state: ChatEntryState): String = when (state) {
    ChatEntryState.QUEUED -> "Queued"
    ChatEntryState.PENDING -> "Not sent yet"
    ChatEntryState.TRANSMITTED -> "Sent to relay"
    ChatEntryState.DELIVERED -> "Delivered"
    ChatEntryState.NOT_DELIVERED -> "Not delivered"
    ChatEntryState.RECEIVED -> "Received"
}

@Composable
private fun Bubble(entry: ChatEntry, onResend: () -> Unit) {
    val status = statusLabel(entry.state)
    Box(Modifier.fillMaxWidth()) {
        Column(
            Modifier
                .align(if (entry.outgoing) Alignment.CenterEnd else Alignment.CenterStart)
                .widthIn(max = 300.dp)
                .background(
                    if (entry.outgoing) MaterialTheme.colorScheme.primaryContainer
                    else MaterialTheme.colorScheme.surfaceVariant,
                    RoundedCornerShape(12.dp),
                )
                .padding(10.dp)
                .testTag("msg")
                .semantics(mergeDescendants = true) { stateDescription = status },
        ) {
            Text(entry.text)
            Text(
                DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(entry.timestampMs.toLong())) +
                    if (entry.outgoing) " · $status" else "",
                style = MaterialTheme.typography.labelSmall,
            )
            if (entry.state == ChatEntryState.NOT_DELIVERED) {
                TextButton(onClick = onResend) { Text("Send again") }
            }
        }
    }
}
