package com.arcium.messenger.ui.navigation

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.arcium.messenger.data.IdentityRepository
import com.arcium.messenger.ui.chat.ChatScreen
import com.arcium.messenger.ui.contacts.ContactsScreen
import com.arcium.messenger.ui.onboarding.ExistingIdentityScreen
import com.arcium.messenger.ui.onboarding.OnboardingScreen
import com.arcium.messenger.ui.settings.SettingsScreen

object Routes {
    const val ONBOARDING = "onboarding"
    const val IDENTITY_EXISTS = "identity_exists"
    const val CONTACTS = "contacts"
    const val CHAT = "chat/{sessionId}"
    const val SETTINGS = "settings"

    fun chat(sessionId: String) = "chat/$sessionId"
}

@Composable
fun AppNavigation() {
    val navController = rememberNavController()
    // Startup check, computed once: if a real identity is already persisted
    // (ArciumApp.core's DB is opened synchronously in Application.onCreate,
    // before this composable ever runs), Routes.ONBOARDING — and therefore
    // its "Generate Identity Keys" button — must never be reachable, since
    // generateAndSaveIdentity() silently overwrites any existing identity.
    val existingPublicKey = remember { IdentityRepository().loadPublicKey() }
    val startDestination = if (existingPublicKey != null) Routes.IDENTITY_EXISTS else Routes.ONBOARDING
    NavHost(navController = navController, startDestination = startDestination) {
        composable(Routes.ONBOARDING) {
            OnboardingScreen(onIdentityReady = { navController.navigate(Routes.CONTACTS) })
        }
        composable(Routes.IDENTITY_EXISTS) {
            ExistingIdentityScreen(
                publicKey = existingPublicKey ?: ByteArray(0),
                onContinue = {
                    navController.navigate(Routes.CONTACTS) {
                        popUpTo(Routes.IDENTITY_EXISTS) { inclusive = true }
                    }
                },
            )
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
