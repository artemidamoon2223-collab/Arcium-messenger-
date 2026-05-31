package com.arcium.messenger.ui.navigation

import androidx.compose.runtime.Composable
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.arcium.messenger.ui.chat.ChatScreen
import com.arcium.messenger.ui.contacts.ContactsScreen
import com.arcium.messenger.ui.onboarding.OnboardingScreen
import com.arcium.messenger.ui.settings.SettingsScreen

object Routes {
    const val ONBOARDING = "onboarding"
    const val CONTACTS = "contacts"
    const val CHAT = "chat/{sessionId}"
    const val SETTINGS = "settings"

    fun chat(sessionId: String) = "chat/$sessionId"
}

@Composable
fun AppNavigation() {
    val navController = rememberNavController()
    NavHost(navController = navController, startDestination = Routes.ONBOARDING) {
        composable(Routes.ONBOARDING) {
            OnboardingScreen(onIdentityReady = { navController.navigate(Routes.CONTACTS) })
        }
        composable(Routes.CONTACTS) {
            ContactsScreen(
                onOpenChat = { sessionId -> navController.navigate(Routes.chat(sessionId)) },
                onOpenSettings = { navController.navigate(Routes.SETTINGS) },
            )
        }
        composable(
            route = Routes.CHAT,
            arguments = listOf(navArgument("sessionId") { type = NavType.StringType }),
        ) { backStack ->
            val sessionId = backStack.arguments?.getString("sessionId") ?: ""
            ChatScreen(sessionId = sessionId, onBack = { navController.popBackStack() })
        }
        composable(Routes.SETTINGS) {
            SettingsScreen(onBack = { navController.popBackStack() })
        }
    }
}
