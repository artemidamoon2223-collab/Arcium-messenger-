package com.arcium.messenger.ui.startup

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.arcium.messenger.startup.AppStartup
import com.arcium.messenger.startup.StartupProblem
import com.arcium.messenger.startup.StartupState
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Shows [content] only once [startup] is Ready. While it is blocked, shows
 * why and a retry that runs the same safe check again; [content] — the app's
 * navigation and every ViewModel in it — is not composed at all.
 */
@Composable
fun StartupGate(
    startup: AppStartup,
    retryDispatcher: CoroutineDispatcher = Dispatchers.IO,
    content: @Composable () -> Unit,
) {
    val state by startup.state.collectAsState()
    val scope = rememberCoroutineScope()
    when (val current = state) {
        StartupState.Ready -> content()
        is StartupState.Blocked -> StartupBlocked(current.problem) {
            scope.launch(retryDispatcher) { startup.retry() }
        }
        StartupState.Checking -> Centered {
            CircularProgressIndicator(modifier = Modifier.testTag("startupChecking"))
        }
    }
}

@Composable
private fun StartupBlocked(problem: StartupProblem, onRetry: () -> Unit) = Centered {
    Text(
        "Arcium Messenger could not open its encrypted data.",
        style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.testTag("startupBlocked"),
    )
    Spacer(Modifier.height(8.dp))
    Text(describe(problem), color = MaterialTheme.colorScheme.error)
    Spacer(Modifier.height(8.dp))
    Text("Nothing was deleted or replaced, and no new identity was created.")
    Spacer(Modifier.height(24.dp))
    Button(onClick = onRetry, modifier = Modifier.testTag("startupRetry")) { Text("Try again") }
}

internal fun describe(problem: StartupProblem): String = when (problem) {
    StartupProblem.KeyMissingForExistingData -> "The encryption key for this data is missing."
    is StartupProblem.KeyUnavailable -> "The encryption key is unavailable: ${problem.reason}."
    is StartupProblem.StoreUnavailable -> "The data store is unavailable: ${problem.reason}."
}

@Composable
private fun Centered(content: @Composable () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) { content() }
}
