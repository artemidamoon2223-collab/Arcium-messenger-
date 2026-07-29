package com.arcium.messenger.ui.onboarding

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * Shown at startup instead of [OnboardingScreen] when an identity is already
 * persisted, so the existing "Generate Identity Keys" button is never
 * reachable while a real identity exists — see AppNavigation's startup check.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExistingIdentityScreen(
    publicKey: ByteArray,
    onContinue: () -> Unit,
) {
    Scaffold(
        topBar = { TopAppBar(title = { Text("Arcium Messenger") }) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text("Identity already exists", style = MaterialTheme.typography.titleLarge)
            Spacer(Modifier.height(16.dp))
            Text(
                publicKey.joinToString("") { "%02x".format(it) },
                style = MaterialTheme.typography.bodyMedium,
            )
            Spacer(Modifier.height(32.dp))
            Button(onClick = onContinue) { Text("Continue") }
        }
    }
}
