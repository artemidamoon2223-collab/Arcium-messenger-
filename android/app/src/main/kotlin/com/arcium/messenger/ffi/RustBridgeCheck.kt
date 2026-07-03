package com.arcium.messenger.ffi

import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * Exercises the real Kotlin<->Rust FFI smoke path (`ArciumCoreWrapper.checkBridge()`).
 * Shows only a non-secret success/failure marker — never key material,
 * ciphertext, storage contents, or raw exception detail.
 *
 * Callers are expected to render this only when `BuildConfig.DEBUG` is true;
 * it is not itself release/debug gated.
 */
@Composable
fun CheckRustBridgeButton(core: ArciumCoreWrapper = ArciumCoreWrapper()) {
    var result by remember { mutableStateOf<String?>(null) }
    Button(onClick = {
        result = try {
            "Rust bridge OK: ${core.checkBridge()}"
        } catch (e: Exception) {
            "Rust bridge check failed"
        }
    }) {
        Text("Check Rust bridge")
    }
    result?.let { Text(it, modifier = Modifier.padding(top = 4.dp)) }
}
