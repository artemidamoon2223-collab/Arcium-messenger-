package com.arcium.messenger.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val DarkColorScheme = darkColorScheme(
    primary = ArciumPurple,
    secondary = ArciumPurpleVariant,
    background = ArciumDark,
    surface = ArciumSurface,
    onSurface = ArciumOnSurface,
)

@Composable
fun ArciumTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        typography = ArciumTypography,
        content = content,
    )
}
