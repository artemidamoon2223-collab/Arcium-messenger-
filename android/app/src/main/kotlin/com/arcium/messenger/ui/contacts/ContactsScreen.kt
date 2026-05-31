package com.arcium.messenger.ui.contacts

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.lifecycle.viewmodel.compose.viewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ContactsScreen(
    onOpenChat: (sessionId: String) -> Unit,
    onOpenSettings: () -> Unit,
    viewModel: ContactsViewModel = viewModel(),
) {
    val state by viewModel.state.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Contacts") },
                actions = {
                    IconButton(onClick = onOpenSettings) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings")
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = {
                // TODO: open phone picker, then call viewModel.discoverContacts(...)
            }) {
                Text("+")
            }
        },
    ) { padding ->
        if (state.isDiscovering) {
            Box(Modifier.fillMaxSize().padding(padding)) {
                CircularProgressIndicator(Modifier.align(androidx.compose.ui.Alignment.Center))
            }
        } else {
            LazyColumn(modifier = Modifier.fillMaxSize().padding(padding)) {
                if (state.contacts.isEmpty()) {
                    item {
                        Text(
                            "No contacts yet. Tap + to discover via PSI.",
                            modifier = Modifier.padding(16.dp),
                        )
                    }
                }
                items(state.contacts) { contact ->
                    ListItem(
                        headlineContent = { Text(contact.name) },
                        supportingContent = { Text(contact.phone) },
                        modifier = Modifier.clickable {
                            // TODO: derive sessionId from contact.publicKey
                            onOpenChat(contact.phone)
                        },
                    )
                    HorizontalDivider()
                }
            }
        }
    }
}
