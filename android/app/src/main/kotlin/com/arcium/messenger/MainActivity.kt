package com.arcium.messenger

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.arcium.messenger.messaging.BackgroundReceive
import com.arcium.messenger.startup.StartupState
import com.arcium.messenger.ui.navigation.AppNavigation
import com.arcium.messenger.ui.startup.StartupGate
import com.arcium.messenger.ui.theme.ArciumTheme
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        // Messages are synced while the app is visible (MessengerService), and
        // only once start-up is Ready: before that, the messenger does not
        // exist. While visible, the app also starts background receive if the
        // user turned it on (it keeps syncing after the app leaves the screen),
        // and clears the "new message" notification.
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                ArciumApp.startup.state.first { it == StartupState.Ready }
                val messenger = ArciumApp.messenger
                BackgroundReceive.clearNewMessage(this@MainActivity)
                launch { BackgroundReceive.startWhileAllowed(this@MainActivity, messenger) }
                messenger.syncWhileVisible()
            }
        }
        setContent {
            ArciumTheme {
                StartupGate(ArciumApp.startup) { AppNavigation() }
            }
        }
    }
}
