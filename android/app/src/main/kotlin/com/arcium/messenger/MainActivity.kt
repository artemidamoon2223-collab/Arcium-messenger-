package com.arcium.messenger

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.arcium.messenger.startup.StartupState
import com.arcium.messenger.ui.navigation.AppNavigation
import com.arcium.messenger.ui.startup.StartupGate
import com.arcium.messenger.ui.theme.ArciumTheme
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Keeps conversations out of screenshots, screen recordings and the
        // recent-apps preview (tracker R-18 a). The user cannot screenshot
        // their own chats either.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        // Messages are synced only while the app is visible (MessengerService),
        // and only once start-up is Ready: before that, the messenger does not
        // exist.
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                ArciumApp.startup.state.first { it == StartupState.Ready }
                ArciumApp.messenger.syncWhileVisible()
            }
        }
        setContent {
            ArciumTheme {
                StartupGate(ArciumApp.startup) { AppNavigation() }
            }
        }
    }
}
