package com.arcium.messenger

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.arcium.messenger.ui.navigation.AppNavigation
import com.arcium.messenger.ui.theme.ArciumTheme
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        // Messages are synced only while the app is visible; see MessengerService.
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) { ArciumApp.messenger.syncWhileVisible() }
        }
        setContent {
            ArciumTheme {
                AppNavigation()
            }
        }
    }
}
