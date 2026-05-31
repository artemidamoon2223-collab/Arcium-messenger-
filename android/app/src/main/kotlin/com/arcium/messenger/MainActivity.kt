package com.arcium.messenger

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.arcium.messenger.ui.navigation.AppNavigation
import com.arcium.messenger.ui.theme.ArciumTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            ArciumTheme {
                AppNavigation()
            }
        }
    }
}
