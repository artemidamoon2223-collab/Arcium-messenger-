package com.arcium.messenger.ui.settings

import android.Manifest
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.viewmodel.compose.viewModel
import com.arcium.messenger.messaging.BackgroundReceive
import com.arcium.messenger.messaging.BackgroundState
import com.arcium.messenger.messaging.RelayProtocol
import com.arcium.messenger.messaging.backgroundState
import com.arcium.messenger.messaging.relayProtocolOf
import com.arcium.messenger.startup.StartupState

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onBack: () -> Unit,
    viewModel: SettingsViewModel = viewModel(),
) {
    val state by viewModel.state.collectAsState()
    val context = LocalContext.current
    // On Android 13 and later, turning background receive on first asks for
    // the notification permission. The choice is stored whatever the answer:
    // without notifications the service does not run, and the status says so.
    var notificationsAllowed by remember { mutableStateOf(BackgroundReceive.notificationsAllowed(context)) }
    val askForNotifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        notificationsAllowed = BackgroundReceive.notificationsAllowed(context)
        viewModel.setBackground(true)
    }
    // Read again whenever the screen returns, for example from the system's
    // notification settings, so the status below is not stale.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                notificationsAllowed = BackgroundReceive.notificationsAllowed(context)
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

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
            Text("Relay", style = MaterialTheme.typography.titleMedium)
            Text(
                "Messages travel through a relay. Paste the connection string its operator " +
                    "gives you (arcium-relay-v2:…). The app then reaches the relay over TLS, " +
                    "checks that it is that relay, and only this device can read or delete its " +
                    "mailbox. The relay cannot read messages, but it sees who talks to whom, " +
                    "when and how much. There is no Tor and no anonymity.",
                style = MaterialTheme.typography.bodySmall,
            )
            if (state.devRelayAllowed) {
                Text(
                    "This debug build also accepts host:port of a development relay " +
                        "(arcium-relay without --keys): no TLS and no authentication, so anyone " +
                        "on the network sees what the relay sees, and anyone who reaches it can " +
                        "read or delete any mailbox.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            OutlinedTextField(
                value = state.relayInput,
                onValueChange = viewModel::onRelayInput,
                label = { Text("Connection string") },
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
            state.savedRelay?.let { saved ->
                Text(
                    protocolStatus(relayProtocolOf(saved)),
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.testTag("relayProtocol"),
                )
            }
            HorizontalDivider()
            Text("Background receive", style = MaterialTheme.typography.titleMedium)
            Text(
                "Off by default. When on, the app keeps syncing with the relay after you leave " +
                    "it, about every 30 seconds, so messages can arrive while it is closed. Android " +
                    "shows a notice for as long as this runs, and a \"New message\" notification, " +
                    "without the sender or the text and hidden on the lock screen, when one arrives. " +
                    "It costs battery and data, and messages can arrive late while the screen is " +
                    "off. It stops if Android ends the app, and after the phone restarts, until you " +
                    "open the app again.",
                style = MaterialTheme.typography.bodySmall,
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Receive in the background", modifier = Modifier.weight(1f))
                Switch(
                    checked = state.background,
                    onCheckedChange = { on ->
                        if (on && BackgroundReceive.mustAskForNotifications(context)) {
                            askForNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
                        } else {
                            viewModel.setBackground(on)
                        }
                    },
                )
            }
            Text(
                // This screen exists only once start-up is Ready (StartupGate).
                backgroundStatus(
                    backgroundState(
                        enabled = state.background,
                        startup = StartupState.Ready,
                        relayAddress = state.savedRelay,
                        notificationsAllowed = notificationsAllowed,
                    ),
                ),
                style = MaterialTheme.typography.bodySmall,
            )
            HorizontalDivider()
            Text("Not provided", style = MaterialTheme.typography.titleMedium)
            Text(
                "Unless background receive is on, messages are synced only while the app is " +
                    "open. No push notifications: nothing wakes the app when a message reaches " +
                    "the relay. No Tor routing, no Bluetooth mesh, no key backup.",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

/** What the screen says about the protocol of the configured relay. */
private fun protocolStatus(protocol: RelayProtocol): String = when (protocol) {
    RelayProtocol.V2 -> "Encrypted relay (V2): TLS to the pinned key, mailbox authentication."
    RelayProtocol.DEV_V1 -> "Development relay (V1): no TLS, no authentication."
}

/** What the screen says about background receive in [state]. */
private fun backgroundStatus(state: BackgroundState): String = when (state) {
    BackgroundState.OFF -> "Off: messages arrive only while the app is open."
    BackgroundState.RUN -> "On: the app stays connected to the relay while it is closed."
    BackgroundState.NO_RELAY -> "Not running: no relay is set."
    BackgroundState.NOTIFICATIONS_BLOCKED ->
        "Not running: Android does not allow this app's notifications. Allow them in Android settings."
    BackgroundState.WAITING_FOR_STARTUP, BackgroundState.STARTUP_BLOCKED -> "Not running: the app has not started."
}
