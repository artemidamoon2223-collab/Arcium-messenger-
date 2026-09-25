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
import com.arcium.messenger.ui.contacts.AddContactScreen
import com.arcium.messenger.ui.contacts.ContactsScreen
import com.arcium.messenger.ui.onboarding.OnboardingScreen
import com.arcium.messenger.ui.settings.SettingsScreen

object Routes {
    const val ONBOARDING = "onboarding"
    const val CONTACTS = "contacts"
    const val ADD_CONTACT = "add_contact"
    const val CHAT = "chat/{peer}"
    const val SETTINGS = "settings"

    /** [peerHex] is the contact's X25519 identity key in hex. */
    fun chat(peerHex: String) = "chat/$peerHex"
}

@Composable
fun AppNavigation() {
    val navController = rememberNavController()
    // Computed once. With an identity stored, onboarding — whose button
    // generates and saves a new identity, replacing the old one — is never
    // reachable.
    val hasStoredIdentity = remember { IdentityRepository().loadPublicKey() != null }
    val startDestination = if (hasStoredIdentity) Routes.CONTACTS else Routes.ONBOARDING
    NavHost(navController = navController, startDestination = startDestination) {
        composable(Routes.ONBOARDING) {
            OnboardingScreen(
                onIdentityReady = {
                    navController.navigate(Routes.CONTACTS) {
                        popUpTo(Routes.ONBOARDING) { inclusive = true }
                    }
                },
            )
        }
        composable(Routes.CONTACTS) {
            ContactsScreen(
                onOpenChat = { peer -> navController.navigate(Routes.chat(peer)) },
                onAddContact = { navController.navigate(Routes.ADD_CONTACT) },
                onOpenSettings = { navController.navigate(Routes.SETTINGS) },
            )
        }
        composable(Routes.ADD_CONTACT) {
            AddContactScreen(
                onBack = { navController.popBackStack() },
                onAdded = { peer ->
                    navController.navigate(Routes.chat(peer)) {
                        popUpTo(Routes.ADD_CONTACT) { inclusive = true }
                    }
                },
            )
        }
        composable(
            route = Routes.CHAT,
            arguments = listOf(navArgument("peer") { type = NavType.StringType }),
        ) {
            ChatScreen(
                onBack = { navController.popBackStack() },
                onOpenSettings = { navController.navigate(Routes.SETTINGS) },
            )
        }
        composable(Routes.SETTINGS) {
            SettingsScreen(onBack = { navController.popBackStack() })
        }
    }
}
