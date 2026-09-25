package com.arcium.messenger.ui.contacts

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Badge
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.arcium.messenger.messaging.RelayLink
import com.arcium.messenger.ui.toHex
import uniffi.arcium_core.ChatSessionState

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ContactsScreen(
    onOpenChat: (peerHex: String) -> Unit,
    onAddContact: () -> Unit,
    onOpenSettings: () -> Unit,
    viewModel: ContactsViewModel = viewModel(),
) {
    val state by viewModel.state.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Arcium Messenger") },
                actions = {
                    IconButton(onClick = onOpenSettings, modifier = Modifier.testTag("openSettings")) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings")
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = onAddContact, modifier = Modifier.testTag("openAddContact")) {
                Icon(Icons.Default.Add, contentDescription = "Add contact")
            }
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            LinkBanner(state.link, onOpenSettings)
            state.error?.let {
                Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(16.dp))
            }
            LazyColumn(Modifier.fillMaxSize()) {
                if (state.conversations.isEmpty()) {
                    item {
                        Text(
                            "No contacts yet. Tap + to exchange contact cards with someone " +
                                "and compare fingerprints.",
                            modifier = Modifier.padding(16.dp),
                        )
                    }
                }
                items(state.conversations, key = { it.peer.toHex() }) { c ->
                    ListItem(
                        headlineContent = { Text(c.name) },
                        supportingContent = {
                            Text(
                                when {
                                    c.identityMismatch -> "⚠ Keys on the relay do not match the verified card"
                                    c.session is ChatSessionState.Conflict -> "⚠ Session conflict"
                                    else -> c.last?.let { (if (it.outgoing) "You: " else "") + it.text }
                                        ?: "No messages yet"
                                },
                                maxLines = 1,
                            )
                        },
                        trailingContent = {
                            if (c.unread > 0u) Badge { Text(c.unread.toString()) }
                        },
                        modifier = Modifier
                            .testTag("contact:${c.name}")
                            .clickable { onOpenChat(c.peer.toHex()) },
                    )
                    HorizontalDivider()
                }
            }
        }
    }
}

/** What the app can and cannot do with the relay right now. */
@Composable
fun LinkBanner(link: RelayLink, onOpenSettings: () -> Unit) {
    val (text, isProblem) = when (link) {
        RelayLink.NotConfigured ->
            "No relay configured: messages are not sent or received. Tap to set one." to true
        RelayLink.NoIdentity -> "No identity yet." to true
        RelayLink.Connecting -> "Connecting to the relay…" to false
        is RelayLink.Online -> "Connected to the development relay" to false
        is RelayLink.Offline ->
            (if (link.networkAvailable) "Relay unreachable" else "No network") +
                ": messages wait on this device and are sent when it is back." to true
    }
    Text(
        text,
        style = MaterialTheme.typography.bodySmall,
        color = if (isProblem) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier
            .fillMaxWidth()
            .testTag("link")
            .clickable(enabled = link == RelayLink.NotConfigured, onClick = onOpenSettings)
            .padding(horizontal = 16.dp, vertical = 6.dp),
    )
}
