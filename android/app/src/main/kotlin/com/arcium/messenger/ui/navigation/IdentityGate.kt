package com.arcium.messenger.ui.navigation

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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.arcium.messenger.data.IdentityRepository
import com.arcium.messenger.data.IdentityState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Reads the identity off the main thread, and again on [load]. */
class IdentityGateViewModel(
    private val identity: IdentityRepository = IdentityRepository(),
) : ViewModel() {

    private val _state = MutableStateFlow<IdentityState>(IdentityState.Loading)
    val state: StateFlow<IdentityState> = _state

    init {
        load()
    }

    /** Reads the identity again. Never creates, deletes or replaces one. */
    fun load() {
        _state.value = IdentityState.Loading
        viewModelScope.launch {
            _state.value = withContext(Dispatchers.IO) { identity.load() }
        }
    }
}

/**
 * Where the app starts for [state]; null while there is nothing to start.
 * Onboarding — whose button creates an identity — only for a store that holds
 * none, never after a failed read.
 */
fun startDestinationFor(state: IdentityState): String? = when (state) {
    IdentityState.Present -> Routes.CONTACTS
    IdentityState.Absent -> Routes.ONBOARDING
    IdentityState.Loading, is IdentityState.Failed -> null
}

/**
 * Shows [content] once the identity is read. A failed read shows the error
 * and a retry that only reads again.
 */
@Composable
fun IdentityGate(gate: IdentityGateViewModel, content: @Composable (startDestination: String) -> Unit) {
    val state by gate.state.collectAsState()
    val current = state
    val start = startDestinationFor(current)
    when {
        start != null -> content(start)
        current is IdentityState.Failed -> IdentityLoadFailed(current.message, gate::load)
        else -> Centered { CircularProgressIndicator(modifier = Modifier.testTag("identityLoading")) }
    }
}

@Composable
private fun IdentityLoadFailed(message: String, onRetry: () -> Unit) = Centered {
    Text(
        "Your identity could not be read. Nothing was changed.",
        style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.testTag("identityLoadFailed"),
    )
    Spacer(Modifier.height(8.dp))
    Text(message, color = MaterialTheme.colorScheme.error)
    Spacer(Modifier.height(24.dp))
    Button(onClick = onRetry, modifier = Modifier.testTag("identityRetry")) { Text("Try again") }
}

@Composable
private fun Centered(content: @Composable () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) { content() }
}
