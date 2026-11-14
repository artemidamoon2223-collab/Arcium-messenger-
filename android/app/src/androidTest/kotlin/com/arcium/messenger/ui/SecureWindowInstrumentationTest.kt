package com.arcium.messenger.ui

import android.view.WindowManager
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.arcium.messenger.MainActivity
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * R-18 (a): the app's window is secure, so the system keeps it out of
 * screenshots, screen recordings and the recent-apps preview. Checks the
 * window flag on the emulator; what a given phone's screenshot tool does is
 * not checked.
 */
@RunWith(AndroidJUnit4::class)
class SecureWindowInstrumentationTest {

    @get:Rule
    val rule = createAndroidComposeRule<MainActivity>()

    @Test
    fun theMainWindowIsSecure() {
        var flags = 0
        rule.runOnUiThread { flags = rule.activity.window.attributes.flags }
        assertTrue(
            "FLAG_SECURE must be set on MainActivity's window",
            flags and WindowManager.LayoutParams.FLAG_SECURE != 0,
        )
    }
}
