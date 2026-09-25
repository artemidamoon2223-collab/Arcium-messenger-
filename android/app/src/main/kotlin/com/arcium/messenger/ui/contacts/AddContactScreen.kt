package com.arcium.messenger.ui.contacts

import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddContactScreen(
    onBack: () -> Unit,
    onAdded: (peerHex: String) -> Unit,
    viewModel: AddContactViewModel = viewModel(),
) {
    val state by viewModel.state.collectAsState()
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current

    LaunchedEffect(state.added) { state.added?.let(onAdded) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Add contact") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
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
            Text("1. Give your card to your contact", style = MaterialTheme.typography.titleMedium)
            Text(
                "Send it by any channel. It holds only public keys.",
                style = MaterialTheme.typography.bodySmall,
            )
            SelectionContainer {
                Text(
                    state.myCardText,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.testTag("myCard"),
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { clipboard.setText(AnnotatedString(state.myCardText)) }) {
                    Text("Copy")
                }
                OutlinedButton(onClick = {
                    val send = Intent(Intent.ACTION_SEND)
                        .setType("text/plain")
                        .putExtra(Intent.EXTRA_TEXT, state.myCardText)
                    context.startActivity(Intent.createChooser(send, "Share contact card"))
                }) { Text("Share") }
            }
            Text("Your fingerprint", style = MaterialTheme.typography.labelLarge)
            Text(
                state.myFingerprint,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier.testTag("myFingerprint"),
            )

            HorizontalDivider()
            Text("2. Paste your contact's card", style = MaterialTheme.typography.titleMedium)
            OutlinedTextField(
                value = state.input,
                onValueChange = viewModel::onInput,
                label = { Text("ARCIUM-CARD-1:…") },
                isError = state.inputError != null,
                supportingText = { state.inputError?.let { Text(it) } },
                modifier = Modifier.fillMaxWidth().testTag("cardInput"),
            )
            state.theirFingerprint?.let { fingerprint ->
                Text("Their fingerprint", style = MaterialTheme.typography.labelLarge)
                Text(
                    fingerprint,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier.testTag("theirFingerprint"),
                )
                Text(
                    "Compare it with the fingerprint on your contact's screen, in person or on a " +
                        "call. If it differs, the card is not theirs: do not add it.",
                    style = MaterialTheme.typography.bodySmall,
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(
                        checked = state.fingerprintsMatch,
                        onCheckedChange = viewModel::onFingerprintsMatch,
                        modifier = Modifier.testTag("fingerprintsMatch"),
                    )
                    Text("The fingerprints match")
                }
                OutlinedTextField(
                    value = state.name,
                    onValueChange = viewModel::onName,
                    label = { Text("Name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag("contactName"),
                )
            }
            state.error?.let {
                Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.testTag("addError"))
            }
            Button(
                onClick = viewModel::add,
                enabled = state.canAdd,
                modifier = Modifier.testTag("addContact"),
            ) { Text("Add contact") }
        }
    }
}
