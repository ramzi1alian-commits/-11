package com.securekeyboard.app

import android.content.res.Resources
import androidx.appcompat.app.AppCompatActivity

/**
 * Base class of every themed screen.
 *
 * Bug fixed: switching from a light theme to a dark one left some labels of the SAME screen
 * invisible (dark text on the new dark background) until another dark theme was picked.
 * The palette overlay (skBg / skText / ... attributes) used to be applied once, in onCreate,
 * with `theme.applyStyle(...)`. AppCompat changes the activity's night-mode configuration
 * while the activity is being created, which rebuilds the Resources.Theme; views inflated
 * before and after that point then resolved `?attr/skText` against different themes.
 *
 * Re-applying the overlay in [onApplyThemeResource] puts the current palette on top of EVERY
 * (re)built theme, so all views of the screen always resolve the same palette.
 */
abstract class SkActivity : AppCompatActivity() {
    override fun onApplyThemeResource(theme: Resources.Theme, resid: Int, first: Boolean) {
        super.onApplyThemeResource(theme, resid, first)
        try {
            theme.applyStyle(Prefs.palette(this).styleRes, true)
        } catch (_: Exception) {
            // Context not fully attached yet: ThemeUtil.applyTo() applies the overlay right after.
        }
    }
}
