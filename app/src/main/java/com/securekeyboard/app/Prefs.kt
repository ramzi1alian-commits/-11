package com.securekeyboard.app

import android.content.Context
import android.content.SharedPreferences
import android.content.res.Configuration
import android.graphics.Typeface
import android.graphics.drawable.Drawable
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.StateListDrawable
import androidx.core.content.ContextCompat

object Prefs {
    private const val FILE = "secure_keyboard_prefs"
    private const val KEY_ACCENT = "accent_color_name"
    private const val KEY_DARK = "dark_mode"
    private const val KEY_THEME = "app_theme_id"
    private const val KEY_FONT = "font_choice"
    private const val KEY_DENSITY = "density"
    private const val KEY_KEYBOARD_HEIGHT = "keyboard_height_dp"
    private const val KEY_AUTOCORRECT = "autocorrect_enabled"
    private const val KEY_PHRASE_LEARNING = "phrase_learning_enabled"
    private const val KEY_CLIPBOARD_HISTORY = "clipboard_history_enabled"
    private const val KEY_INCOGNITO = "incognito_mode"
    private const val KEY_FIPS_MODE = "fips_compatible_mode"
    private const val KEY_RETURN_TO_CRYPTO = "return_to_crypto"
    private const val KEY_RETURN_TO_SECURE_COMPOSE = "return_to_secure_compose"
    private const val KEY_PENDING_ATTACH_URI = "pending_attach_uri"
    private const val KEY_PENDING_ATTACH_NAME = "pending_attach_name"
    private const val KEY_PICKER_RETURNED = "picker_returned"

    // Preferences here are only UI/configuration state, not secrets.  The
    // performance fix is to keep ONE process-local SharedPreferences handle
    // instead of reopening and rereading the same XML file on every key draw.
    // The previous implementation performed a disk-backed lookup for nearly
    // every keyboard repaint. Values remain persisted across restarts, while
    // hot-path reads are now memory-only.
    @Volatile
    private var sharedPrefs: SharedPreferences? = null

    private fun prefs(context: Context): SharedPreferences =
        sharedPrefs ?: synchronized(this) {
            sharedPrefs ?: context.applicationContext
                .getSharedPreferences(FILE, Context.MODE_PRIVATE)
                .also { sharedPrefs = it }
        }

    // Reasonable dp bounds for a comfortable-but-compact keyboard row.
    // (For reference: 1cm on a phone screen is roughly 63dp - the slider
    // lets the user go a bit under or over that instead of a single
    // hardcoded value baked into the code.)
    const val MIN_KEYBOARD_HEIGHT_DP = 40
    const val MAX_KEYBOARD_HEIGHT_DP = 72
    const val DEFAULT_KEYBOARD_HEIGHT_DP = 52

    // SECURITY/RELIABILITY FIX: the accent color used to be stored as a
    // raw android resource id (prefs.getInt(KEY_ACCENT, R.color.accent_cyan)
    // / putInt(..., colorRes)). Resource ids are NOT guaranteed stable
    // across build variants - and this project's release build has BOTH
    // minifyEnabled and shrinkResources enabled (see app/build.gradle),
    // either of which can renumber resource ids when the resource table
    // is stripped/repacked. A value saved by one installed build could
    // silently resolve to a completely different (or nonexistent)
    // resource after an app update, and ContextCompat.getColor() throws
    // Resources.NotFoundException on an invalid id - uncaught, that
    // crashes every single screen AND the keyboard itself (accentColor()
    // is called from SettingsActivity, ThemeSettingsActivity,
    // EncryptActivity, and every key drawn by the IME). A crashing
    // keyboard is a real availability problem: it can lock the user out
    // of typing in ANY app, not just this one.
    //
    // Fixed by storing a small, stable string key instead and mapping it
    // through a fixed table. An unrecognized/corrupted stored value can
    // only ever fall back to a safe default - it can never resolve to an
    // arbitrary or invalid resource id.
    private const val ACCENT_CYAN = "cyan"
    private const val ACCENT_TEAL = "teal"
    private const val ACCENT_GOLD = "gold"
    private const val ACCENT_PURPLE = "purple"
    private const val ACCENT_SECURE_GREEN = "secure_green"

    private fun accentNameToRes(name: String?): Int = when (name) {
        ACCENT_CYAN -> R.color.accent_cyan
        ACCENT_TEAL -> R.color.accent_teal
        ACCENT_GOLD -> R.color.accent_gold
        ACCENT_PURPLE -> R.color.accent_purple
        ACCENT_SECURE_GREEN -> R.color.accent_secure_green
        else -> R.color.accent_secure_green
    }

    private fun resToAccentName(colorRes: Int): String = when (colorRes) {
        R.color.accent_cyan -> ACCENT_CYAN
        R.color.accent_teal -> ACCENT_TEAL
        R.color.accent_gold -> ACCENT_GOLD
        R.color.accent_purple -> ACCENT_PURPLE
        R.color.accent_secure_green -> ACCENT_SECURE_GREEN
        else -> ACCENT_SECURE_GREEN
    }

    fun accentColorRes(context: Context): Int {
        val pref = prefs(context)
        return accentNameToRes(pref.getString(KEY_ACCENT, ACCENT_CYAN))
    }

    /** True when the user has not picked a custom accent: the theme's own accent is used. */
    fun accentIsAuto(context: Context): Boolean = !prefs(context).contains(KEY_ACCENT)

    fun setAccentColorRes(context: Context, colorRes: Int) {
        prefs(context).edit()
            .putString(KEY_ACCENT, resToAccentName(colorRes)).apply()
    }

    fun clearAccent(context: Context) {
        prefs(context).edit().remove(KEY_ACCENT).apply()
    }

    /** Current theme id (see [Themes]). Migrates the old day/night flag on first read. */
    fun themeId(context: Context): String {
        val p = prefs(context)
        val stored = p.getString(KEY_THEME, null)
        if (stored != null) return Themes.byId(stored).id
        return if (p.getBoolean(KEY_DARK, false)) "dark" else Themes.DEFAULT_ID
    }

    fun setThemeId(context: Context, id: String) {
        prefs(context).edit().putString(KEY_THEME, Themes.byId(id).id).commit()
        // Switch AppCompat's day/night mode NOW, before any screen is re-created, so the new
        // screen starts in the right configuration instead of flipping it mid-onCreate.
        ThemeUtil.syncNightMode(context)
    }

    fun palette(context: Context): Palette = Themes.byId(themeId(context))

    /** True for any dark theme (drives AppCompat night mode and the keyboard's rebuild check). */
    fun isDarkMode(context: Context): Boolean = palette(context).dark

    fun setDarkMode(context: Context, dark: Boolean) {
        setThemeId(context, if (dark) "dark" else "day")
    }

    // OFF by default - autocorrect only ever touches a tiny fixed table
    // of unambiguous typos (see Autocorrect.kt), but it still changes
    // what gets typed without an explicit tap, so it stays opt-in.
    fun autocorrectEnabled(context: Context): Boolean {
        val prefs = prefs(context)
        return prefs.getBoolean(KEY_AUTOCORRECT, false)
    }

    // OFF by default: Argon2id is the stronger default against GPU guessing. This switches NEW
    // contact messages to the FIPS-compatible v5 format (PBKDF2-HMAC-SHA-256). Reading is
    // always supported for every format regardless of this setting.
    fun fipsMode(context: Context): Boolean = prefs(context).getBoolean(KEY_FIPS_MODE, false)

    fun setFipsMode(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_FIPS_MODE, enabled).apply()
    }

    // V60: ON by default (keeps the existing behaviour). OFF = no new phrases are saved and the saved
    // ones are not suggested; nothing is deleted (the separate clear button does that).
    fun phraseLearningEnabled(context: Context): Boolean = prefs(context).getBoolean(KEY_PHRASE_LEARNING, true)

    // V65: incognito = nothing new is learned or saved (words, sentences, clipboard history). OFF by default.
    fun incognitoMode(context: Context): Boolean = prefs(context).getBoolean(KEY_INCOGNITO, false)

    fun setIncognitoMode(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_INCOGNITO, enabled).apply()
    }

    // V63: OFF by default - a permanent clipboard history is real storage of what the user copies.
    fun clipboardHistoryEnabled(context: Context): Boolean = prefs(context).getBoolean(KEY_CLIPBOARD_HISTORY, false)

    fun setClipboardHistoryEnabled(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_CLIPBOARD_HISTORY, enabled).apply()
    }

    fun setPhraseLearningEnabled(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_PHRASE_LEARNING, enabled).apply()
    }

    fun setAutocorrectEnabled(context: Context, enabled: Boolean) {
        prefs(context).edit()
            .putBoolean(KEY_AUTOCORRECT, enabled).apply()
    }


    /** UI-only handoff flag used when the keyboard temporarily opens the
     * separate encryption/composition Activity. It contains no sensitive
     * text; it only tells a recreated IME which page to restore. */
    fun markReturnToCrypto(context: Context) {
        prefs(context).edit().putBoolean(KEY_RETURN_TO_CRYPTO, true).apply()
    }

    fun consumeReturnToCrypto(context: Context): Boolean {
        val p = prefs(context)
        val value = p.getBoolean(KEY_RETURN_TO_CRYPTO, false)
        if (value) p.edit().remove(KEY_RETURN_TO_CRYPTO).apply()
        return value
    }

    /**
     * Same idea and same reason as markReturnToCrypto/consumeReturnToCrypto,
     * for secure-compose specifically. Before this, secure-compose's own
     * "return after picker" state (secureComposeSticky in
     * SecureInputMethodService) lived ONLY in memory - fine if the IME's
     * process survives the whole AttachmentPickerActivity round trip, but
     * that process is backgrounded/cached for the whole time the picker is
     * in the foreground, and Android is free to kill cached processes
     * under memory pressure. If it does, a freshly recreated service
     * starts with secureComposeSticky back at its default (false), with no
     * way left to know a return to secure-compose was ever pending -
     * exactly "returns to the default keyboard, exits the secure pad"
     * reports. Persisting this the same way markReturnToCrypto already
     * does closes that gap.
     */
    fun markReturnToSecureCompose(context: Context) {
        prefs(context).edit().putBoolean(KEY_RETURN_TO_SECURE_COMPOSE, true).apply()
    }

    /**
     * The file chosen in AttachmentPickerActivity is persisted here BEFORE the
     * picker finishes, so it no longer depends on a live BroadcastReceiver:
     * if the keyboard process was killed or the service re-created while the
     * system picker was open, the broadcast was silently lost and the file
     * "never happened". commit() (not apply()) because the process may die
     * right after the picker finishes.
     */
    fun setPendingAttachment(context: Context, uri: String, name: String) {
        prefs(context).edit()
            .putString(KEY_PENDING_ATTACH_URI, uri)
            .putString(KEY_PENDING_ATTACH_NAME, name)
            .commit()
    }

    fun hasPendingAttachment(context: Context): Boolean =
        prefs(context).getString(KEY_PENDING_ATTACH_URI, null) != null

    /** Returns (uri, name) once and clears it. */
    fun takePendingAttachment(context: Context): Pair<String, String>? {
        val p = prefs(context)
        val uri = p.getString(KEY_PENDING_ATTACH_URI, null) ?: return null
        val name = p.getString(KEY_PENDING_ATTACH_NAME, "") ?: ""
        p.edit().remove(KEY_PENDING_ATTACH_URI).remove(KEY_PENDING_ATTACH_NAME).commit()
        return Pair(uri, name)
    }

    /** Set when the picker has closed (picked or cancelled): the next onStartInput belongs to the chat app. */
    fun markPickerReturned(context: Context) {
        prefs(context).edit().putBoolean(KEY_PICKER_RETURNED, true).commit()
    }

    fun consumePickerReturned(context: Context): Boolean {
        val p = prefs(context)
        val v = p.getBoolean(KEY_PICKER_RETURNED, false)
        if (v) p.edit().remove(KEY_PICKER_RETURNED).apply()
        return v
    }

    fun consumeReturnToSecureCompose(context: Context): Boolean {
        val p = prefs(context)
        val value = p.getBoolean(KEY_RETURN_TO_SECURE_COMPOSE, false)
        if (value) p.edit().remove(KEY_RETURN_TO_SECURE_COMPOSE).apply()
        return value
    }

    // 0 = default sans-serif, 1 = serif, 2 = monospace
    fun fontChoice(context: Context): Int {
        val prefs = prefs(context)
        return prefs.getInt(KEY_FONT, 0)
    }

    fun setFontChoice(context: Context, choice: Int) {
        prefs(context).edit()
            .putInt(KEY_FONT, choice).apply()
    }

    // 0 = comfortable, 1 = compact
    fun density(context: Context): Int {
        val prefs = prefs(context)
        return prefs.getInt(KEY_DENSITY, 0)
    }

    fun setDensity(context: Context, value: Int) {
        prefs(context).edit()
            .putInt(KEY_DENSITY, value).apply()
    }

    /**
     * Height (in dp, NOT raw pixels) of a single keyboard key row.
     *
     * IMPORTANT FIX: the keyboard used to hardcode a raw pixel value
     * (130px) for key height. Raw pixels are NOT device-independent, so
     * the same "130" produced wildly different physical sizes depending
     * on screen density (huge on an old mdpi screen, tiny on a modern
     * xxxhdpi screen). Storing/using dp here and converting to px with
     * the device's actual density (see SecureInputMethodService.dpToPx)
     * makes the key height consistent across devices, and adjustable by
     * the user in Settings instead of a single value baked in once.
     */
    fun keyboardHeightDp(context: Context): Int {
        val prefs = prefs(context)
        val value = prefs.getInt(KEY_KEYBOARD_HEIGHT, DEFAULT_KEYBOARD_HEIGHT_DP)
        return value.coerceIn(MIN_KEYBOARD_HEIGHT_DP, MAX_KEYBOARD_HEIGHT_DP)
    }

    fun setKeyboardHeightDp(context: Context, dp: Int) {
        val clamped = dp.coerceIn(MIN_KEYBOARD_HEIGHT_DP, MAX_KEYBOARD_HEIGHT_DP)
        prefs(context).edit()
            .putInt(KEY_KEYBOARD_HEIGHT, clamped).apply()
    }
}

object Fonts {
    /**
     * IMPORTANT (fixed after a real bug report): this used to return the raw
     * generic families Typeface.SERIF / Typeface.MONOSPACE for the "classic"
     * and "mono" choices. On many ROMs (MIUI/Xiaomi in particular) those
     * generic families have NO Arabic glyph coverage at all, so Arabic text
     * silently fell back to tofu boxes or unrelated glyphs from a fallback
     * font - this is exactly what showed up as "symbols instead of letters"
     * on the keyboard.
     *
     * Typeface.DEFAULT (and its bold variant) is backed by the system's
     * default font family, which always includes a proper Arabic fallback
     * chain on stock Android and every major OEM skin. So instead of
     * swapping the font family for "classic"/"mono", we keep the same
     * Arabic-safe family and only vary the style, which gives visual
     * differentiation without ever risking broken Arabic rendering.
     */
    fun currentTypeface(context: Context): Typeface {
        return when (Prefs.fontChoice(context)) {
            1 -> Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            2 -> Typeface.create(Typeface.DEFAULT, Typeface.ITALIC)
            else -> Typeface.DEFAULT
        }
    }

    /** Recursively applies the chosen typeface to every TextView/Button/EditText in a view tree. */
    fun applyToTree(view: android.view.View, typeface: Typeface) {
        if (view is android.widget.TextView) {
            view.typeface = typeface
        }
        if (view is android.view.ViewGroup) {
            for (i in 0 until view.childCount) {
                applyToTree(view.getChildAt(i), typeface)
            }
        }
    }
}

/**
 * Centralizes accent-color application so every screen (including the
 * theme-picker screen itself) actually reflects the chosen accent, instead
 * of each Activity manually tinting one or two buttons and forgetting the
 * rest - which was the root cause of "the theme doesn't apply" bug reports.
 */
object ThemeUtil {

    /**
     * FIXED: the keyboard (SecureInputMethodService, a plain
     * InputMethodService - not an AppCompatActivity) used to resolve all
     * of its colors straight from `context.resources`, whose day/night
     * qualifier is driven ONLY by the phone's SYSTEM dark-mode setting.
     * The in-app "الوضع الليلي/النهاري" toggle in ThemeSettingsActivity
     * only ever called AppCompatDelegate.setDefaultNightMode(), which
     * AppCompat applies to AppCompatActivity screens (Settings, theme
     * settings, the encrypt tool) by wrapping THEIR OWN Resources - it
     * has no effect on a Service. Net result: picking "الوضع الليلي"
     * inside the app correctly darkened those three screens, but the
     * actual typing keyboard kept rendering values/colors.xml (the light
     * palette) unless the PHONE itself also happened to be in system
     * dark mode - which read as "doesn't turn black, looks washed out".
     *
     * Fixed by making Prefs.isDarkMode() the single source of truth
     * everywhere, instead of two different, sometimes-disagreeing
     * signals (AppCompatDelegate for activities, system Configuration
     * for the service). Every color/drawable lookup in this object goes
     * through a Context whose night-mode bit is explicitly forced to
     * match Prefs.isDarkMode(), so values-night/colors.xml is always the
     * one actually driving the keyboard's colors when the user picked
     * night mode - regardless of what the phone's own system setting is.
     */
    private fun themedContext(context: Context): Context {
        val forced = Configuration(context.resources.configuration)
        val nightBit = if (Prefs.isDarkMode(context)) {
            Configuration.UI_MODE_NIGHT_YES
        } else {
            Configuration.UI_MODE_NIGHT_NO
        }
        forced.uiMode = (forced.uiMode and Configuration.UI_MODE_NIGHT_MASK.inv()) or nightBit
        return context.createConfigurationContext(forced)
    }

    /**
     * The accent is used both as a fill and as text/stroke color on the theme
     * background. A custom accent picked in settings can be unreadable on some
     * themes (e.g. gold on a light theme), so it is nudged toward white (dark
     * themes) or black (light themes) until it reaches a readable contrast.
     */
    fun accentColor(context: Context): Int {
        val p = Prefs.palette(context)
        val raw = if (Prefs.accentIsAuto(context)) p.accent
        else ContextCompat.getColor(themedContext(context), Prefs.accentColorRes(context))
        return ensureContrast(raw, p.bg, 4.5)
    }

    fun dangerColor(context: Context): Int =
        if (Prefs.palette(context).dark) 0xFFF87171.toInt() else 0xFFC62828.toInt()

    private fun luminance(c: Int): Double {
        fun f(v: Int): Double { val x = v / 255.0; return if (x <= 0.03928) x / 12.92 else Math.pow((x + 0.055) / 1.055, 2.4) }
        return 0.2126 * f(android.graphics.Color.red(c)) + 0.7152 * f(android.graphics.Color.green(c)) + 0.0722 * f(android.graphics.Color.blue(c))
    }

    private fun contrast(a: Int, b: Int): Double {
        val la = luminance(a); val lb = luminance(b)
        return (maxOf(la, lb) + 0.05) / (minOf(la, lb) + 0.05)
    }

    fun ensureContrast(color: Int, bg: Int, min: Double): Int {
        if (contrast(color, bg) >= min) return color
        val target = if (luminance(bg) < 0.5) android.graphics.Color.WHITE else android.graphics.Color.BLACK
        var c = color
        for (i in 1..20) {
            c = androidx.core.graphics.ColorUtils.blendARGB(color, target, i * 0.05f)
            if (contrast(c, bg) >= min) return c
        }
        return c
    }

    fun textColor(context: Context): Int = Prefs.palette(context).text

    fun textSecondaryColor(context: Context): Int = Prefs.palette(context).textSecondary

    /** Readable label color for text drawn on the accent color (picked by luminance). */
    fun textOnAccentColor(context: Context): Int = onColor(accentColor(context))

    private fun onColor(bg: Int): Int {
        val r = android.graphics.Color.red(bg) / 255.0
        val g = android.graphics.Color.green(bg) / 255.0
        val b = android.graphics.Color.blue(bg) / 255.0
        val lum = 0.2126 * r + 0.7152 * g + 0.0722 * b
        return if (lum > 0.5) 0xFF111827.toInt() else 0xFFFFFFFF.toInt()
    }

    /**
     * Call at the very top of an Activity.onCreate (before super.onCreate):
     * applies the chosen palette's theme overlay, window/status/navigation
     * colors and the matching AppCompat day/night mode.
     */
    /** Makes AppCompat's day/night mode match the chosen palette (no-op when it already does). */
    fun syncNightMode(context: Context) {
        androidx.appcompat.app.AppCompatDelegate.setDefaultNightMode(
            if (Prefs.palette(context).dark) androidx.appcompat.app.AppCompatDelegate.MODE_NIGHT_YES
            else androidx.appcompat.app.AppCompatDelegate.MODE_NIGHT_NO
        )
    }

    fun applyTo(activity: android.app.Activity) {
        val p = Prefs.palette(activity)
        syncNightMode(activity)
        activity.theme.applyStyle(p.styleRes, true)
        // Window/status/navigation bar colors come from the SkTheme.* overlay itself.
    }

    /** Tints a filled ("primary") button's background with the current accent. */
    fun tintPrimary(context: Context, vararg buttons: com.google.android.material.button.MaterialButton) {
        val accent = accentColor(context)
        val tint = android.content.res.ColorStateList.valueOf(accent)
        val label = onColor(accent)
        buttons.forEach { it.backgroundTintList = tint; it.setTextColor(label) }
    }

    /** Colors an outline ("secondary") button's stroke with the current accent. */
    fun tintOutline(context: Context, vararg buttons: com.google.android.material.button.MaterialButton) {
        val color = accentColor(context)
        buttons.forEach {
            it.strokeColor = android.content.res.ColorStateList.valueOf(color)
            it.setTextColor(color)
        }
    }

    /**
     * Draws a colored selection border around a plain swatch card (a
     * LinearLayout, not a Material widget) so the user can see which
     * accent color is active - this was missing entirely before, which
     * made color choices look like they weren't being saved.
     */
    fun setSelected(view: android.view.View, selected: Boolean, accent: Int) {
        val bg = GradientDrawable()
        bg.cornerRadius = 10f * view.resources.displayMetrics.density
        bg.setColor(Prefs.palette(view.context).surface2)
        val strokeWidthDp = if (selected) 2f else 1f
        val strokeColor = if (selected) accent else Prefs.palette(view.context).border
        bg.setStroke((strokeWidthDp * view.resources.displayMetrics.density).toInt(), strokeColor)
        view.background = bg
    }

    /**
     * Same idea but for a MaterialButton (mode/font/density buttons) -
     * uses MaterialButton's own stroke properties instead of replacing its
     * background drawable outright, so we don't fight its built-in ripple
     * and corner-radius handling.
     */
    fun setSelected(
        button: com.google.android.material.button.MaterialButton,
        selected: Boolean,
        accent: Int
    ) {
        val context = button.context
        if (selected) {
            button.strokeWidth = (2 * context.resources.displayMetrics.density).toInt()
            button.strokeColor = android.content.res.ColorStateList.valueOf(accent)
            button.setTextColor(accent)
        } else {
            button.strokeWidth = (1 * context.resources.displayMetrics.density).toInt()
            button.strokeColor = android.content.res.ColorStateList.valueOf(Prefs.palette(context).border)
            button.setTextColor(Prefs.palette(context).text)
        }
    }

    /**
     * Corner radius used for every key / chip surface. Updated visual system: 9dp corners keep keys soft and modern without
     * becoming oversized pills; paired with a restrained elevation system
     * for clear tactile separation.
     */
    private const val KEY_CORNER_RADIUS_DP = 5.5f

    /**
     * Elevation (real View.elevation, not a drawn gradient trick) applied
     * to each key so it reads as a raised card floating over the darker
     * keyboard surface (see keyboardBackground) - this is the main thing
     * that was missing before and made the keyboard look flat/dated. Key
     * presses drop to a lower elevation (see applyPressedElevation) to
     * sell a tactile "push down" on touch.
     */
    const val KEY_ELEVATION_DP = 3.0f
    const val KEY_ELEVATION_PRESSED_DP = 0.8f

    /**
     * Professional-looking keyboard key background: a subtle vertical
     * gradient (instead of a flat single color) with a thin border, built
     * as a proper pressed/normal state-list so keys give visual feedback
     * on touch. When [accented] is true (the space/delete/enter action
     * keys) the border uses the user's chosen accent color instead of a
     * neutral one, so those keys read as visually distinct actions.
     */
    fun keyBackgroundSelector(context: Context, accented: Boolean): Drawable {
        val states = StateListDrawable()
        states.addState(intArrayOf(android.R.attr.state_pressed), keyShape(context, pressed = true, accented = accented))
        states.addState(intArrayOf(), keyShape(context, pressed = false, accented = accented))
        return states
    }

    /**
     * Plain solid color matching keyShape's normal (non-pressed) fill -
     * for spots that need a guaranteed-opaque background on an individual
     * child view rather than a whole StateListDrawable (see showVariantPopup's
     * per-chip background in SecureInputMethodService: relying solely on a
     * parent container's background left the popup showing as
     * transparent/unreadable on some devices).
     */
    fun keyShapeFillColor(context: Context): Int {
        return Prefs.palette(context).surface2
    }

    private fun keyShape(context: Context, pressed: Boolean, accented: Boolean): GradientDrawable {
        val density = context.resources.displayMetrics.density
        val bg = GradientDrawable()
        bg.cornerRadius = KEY_CORNER_RADIUS_DP * density
        bg.orientation = GradientDrawable.Orientation.TOP_BOTTOM
        if (pressed) {
            val pressedColor = Prefs.palette(context).border
            bg.colors = intArrayOf(pressedColor, pressedColor)
        } else {
            // Subtle surface gradient with clear separation from the keyboard
            // background. The same surface hierarchy is used in both
            // light and dark modes so the keyboard stays calm and premium.
            bg.colors = intArrayOf(Prefs.palette(context).surface, Prefs.palette(context).surface2)
        }
        val strokeColor = if (accented) accentColor(context) else Prefs.palette(context).border
        val strokeWidthDp = if (accented) 1.6f else 1f
        bg.setStroke((strokeWidthDp * density).toInt(), strokeColor)
        return bg
    }

    /**
     * Pill-shaped background (state-list, so tapping still gives visual
     * feedback exactly like a key) for suggestion-strip chips - fully
     * rounded rather than the boxier key corner radius, matching the
     * rounded "chip" look of modern keyboard suggestion bars.
     */
    fun suggestionChipBackground(context: Context): Drawable {
        val states = StateListDrawable()
        states.addState(intArrayOf(android.R.attr.state_pressed), pillShape(context, pressed = true))
        states.addState(intArrayOf(), pillShape(context, pressed = false))
        return states
    }

    /**
     * Background for the whole suggestion strip container: a slightly
     * lighter, rounded card than the raw keyboard surface, so the strip
     * reads as one distinct panel (rather than chips floating directly
     * on the keyboard background) and has something solid to cast the
     * shadow from [KEY_ELEVATION_DP]-style elevation onto.
     */
    fun suggestionBarBackground(context: Context): Drawable {
        val density = context.resources.displayMetrics.density
        val bg = GradientDrawable()
        bg.cornerRadius = (KEY_CORNER_RADIUS_DP + 2f) * density
        bg.setColor(Prefs.palette(context).surface)
        return bg
    }

    /**
     * Thin vertical rule dropped between (not around) suggestion chips,
     * so a row of 3+ suggestions reads as clearly separated options
     * instead of one run-on strip of text.
     */
    fun suggestionDividerColor(context: Context): Int =
        Prefs.palette(context).border

    private fun pillShape(context: Context, pressed: Boolean): GradientDrawable {
        val density = context.resources.displayMetrics.density
        val bg = GradientDrawable()
        bg.cornerRadius = 999f * density // large enough to always render as a full pill
        bg.setColor(
            if (pressed) Prefs.palette(context).border else Prefs.palette(context).surface2
        )
        return bg
    }

    /**
     * Applies (or removes) the "pressed" elevation drop for tactile
     * feedback on touch. Animated (short ObjectAnimator, not an instant
     * jump) so the key visibly "settles" down and back up instead of
     * snapping between the two elevations - a small touch, but it's
     * what separates a raised card that feels alive from one that just
     * flickers between two fixed heights.
     */
    fun applyPressedElevation(view: android.view.View, pressed: Boolean) {
        val density = view.resources.displayMetrics.density
        val target = (if (pressed) KEY_ELEVATION_PRESSED_DP else KEY_ELEVATION_DP) * density
        view.animate().cancel()
        view.animate()
            .z(target)
            .setDuration(if (pressed) 40L else 120L)
            .start()
    }

    /** Flat, slightly darker fill for the whole keyboard surface so raised keys have contrast to sit on. */
    fun keyboardBackground(context: Context): Drawable {
        val bg = GradientDrawable()
        bg.setColor(Prefs.palette(context).bg)
        return bg
    }
}
