package com.arcium.messenger.ui.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onBack: () -> Unit,
    viewModel: SettingsViewModel = viewModel(),
) {
    val state by viewModel.state.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("settingsBack")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Development relay", style = MaterialTheme.typography.titleMedium)
            if (!state.relayAllowed) {
                Text(
                    "This build has no relay: there is no production relay yet, and the " +
                        "development relay is available only in debug builds. Messages cannot " +
                        "be sent or received.",
                )
                return@Column
            }
            Text(
                "Messages travel through a relay you run yourself (arcium-relay). It is for " +
                    "development only: no TLS, no authentication, nothing kept on disk. It " +
                    "cannot read messages, but it and anyone on the network see who talks to " +
                    "whom, when and how much. There is no Tor and no anonymity.",
                style = MaterialTheme.typography.bodySmall,
            )
            OutlinedTextField(
                value = state.relayInput,
                onValueChange = viewModel::onRelayInput,
                label = { Text("host:port") },
                singleLine = true,
                isError = state.error != null,
                supportingText = { state.error?.let { Text(it) } },
                modifier = Modifier.fillMaxWidth().testTag("relayInput"),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = viewModel::saveRelay, modifier = Modifier.testTag("saveRelay")) {
                    Text("Save")
                }
                OutlinedButton(onClick = viewModel::clearRelay) { Text("Disconnect") }
            }
            Text(
                state.savedRelay?.let { "Using $it" } ?: "No relay: messaging is off.",
                modifier = Modifier.testTag("savedRelay"),
            )
            HorizontalDivider()
            Text("Not provided", style = MaterialTheme.typography.titleMedium)
            Text(
                "Messages are synced only while the app is open; nothing arrives while it is " +
                    "closed. No Tor routing, no Bluetooth mesh, no key backup.",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}
