package com.securekeyboard.app

import android.os.Bundle
import android.view.View
import android.widget.SeekBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import com.google.android.material.button.MaterialButton

class ThemeSettingsActivity : AppCompatActivity() {

    private lateinit var swatchCyan: View
    private lateinit var swatchTeal: View
    private lateinit var swatchGold: View
    private lateinit var swatchPurple: View
    private lateinit var swatchSecureGreen: View

    private lateinit var themeGrid: android.widget.LinearLayout
    private lateinit var btnAccentAuto: MaterialButton
    private lateinit var btnFontSans: MaterialButton
    private lateinit var btnFontSerif: MaterialButton
    private lateinit var btnFontMono: MaterialButton
    private lateinit var btnCompact: MaterialButton
    private lateinit var btnComfortable: MaterialButton

    private lateinit var seekKeyboardHeight: SeekBar
    private lateinit var textKeyboardHeightValue: TextView
    private lateinit var previewKeyA: TextView
    private lateinit var previewKeyB: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        ThemeUtil.applyTo(this)
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_theme_settings)

        swatchCyan = findViewById(R.id.swatchCyan)
        swatchTeal = findViewById(R.id.swatchTeal)
        swatchGold = findViewById(R.id.swatchGold)
        swatchPurple = findViewById(R.id.swatchPurple)
        swatchSecureGreen = findViewById(R.id.swatchSecureGreen)

        themeGrid = findViewById(R.id.themeGrid)
        btnAccentAuto = findViewById(R.id.btnAccentAuto)
        btnAccentAuto.setOnClickListener { Prefs.clearAccent(this); recreate() }
        btnFontSans = findViewById(R.id.btnFontSans)
        btnFontSerif = findViewById(R.id.btnFontSerif)
        btnFontMono = findViewById(R.id.btnFontMono)
        btnCompact = findViewById(R.id.btnCompact)
        btnComfortable = findViewById(R.id.btnComfortable)

        seekKeyboardHeight = findViewById(R.id.seekKeyboardHeight)
        textKeyboardHeightValue = findViewById(R.id.textKeyboardHeightValue)
        previewKeyA = findViewById(R.id.previewKeyA)
        previewKeyB = findViewById(R.id.previewKeyB)

        swatchCyan.setOnClickListener { pickAccent(R.color.accent_cyan) }
        swatchTeal.setOnClickListener { pickAccent(R.color.accent_teal) }
        swatchGold.setOnClickListener { pickAccent(R.color.accent_gold) }
        swatchPurple.setOnClickListener { pickAccent(R.color.accent_purple) }
        swatchSecureGreen.setOnClickListener { pickAccent(R.color.accent_secure_green) }

        btnFontSans.setOnClickListener { Prefs.setFontChoice(this, 0); recreate() }
        btnFontSerif.setOnClickListener { Prefs.setFontChoice(this, 1); recreate() }
        btnFontMono.setOnClickListener { Prefs.setFontChoice(this, 2); recreate() }

        btnCompact.setOnClickListener { Prefs.setDensity(this, 1); refreshSelectionState() }
        btnComfortable.setOnClickListener { Prefs.setDensity(this, 0); refreshSelectionState() }

        // Keyboard height: instead of a single hardcoded shorter value,
        // the user controls it directly with this slider. The keyboard
        // (SecureInputMethodService) picks up the new value live the
        // next time it's shown - see onStartInputView there.
        seekKeyboardHeight.max = Prefs.MAX_KEYBOARD_HEIGHT_DP - Prefs.MIN_KEYBOARD_HEIGHT_DP
        val currentDp = Prefs.keyboardHeightDp(this)
        seekKeyboardHeight.progress = currentDp - Prefs.MIN_KEYBOARD_HEIGHT_DP
        updateHeightPreview(currentDp)

        seekKeyboardHeight.setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
            override fun onProgressChanged(seekBar: SeekBar?, progress: Int, fromUser: Boolean) {
                val dp = Prefs.MIN_KEYBOARD_HEIGHT_DP + progress
                Prefs.setKeyboardHeightDp(this@ThemeSettingsActivity, dp)
                updateHeightPreview(dp)
            }
            override fun onStartTrackingTouch(seekBar: SeekBar?) {}
            override fun onStopTrackingTouch(seekBar: SeekBar?) {}
        })

        applyFontToScreen()
        refreshSelectionState()
    }

    private fun updateHeightPreview(dp: Int) {
        textKeyboardHeightValue.text = getString(R.string.keyboard_height_value, dp)
        val px = (dp * resources.displayMetrics.density).toInt()
        previewKeyA.layoutParams = previewKeyA.layoutParams.apply { height = px }
        previewKeyB.layoutParams = previewKeyB.layoutParams.apply { height = px }
        previewKeyA.requestLayout()
        previewKeyB.requestLayout()
        val accent = ThemeUtil.accentColor(this)
        previewKeyA.background = ThemeUtil.keyBackgroundSelector(this, accented = false)
        previewKeyB.background = ThemeUtil.keyBackgroundSelector(this, accented = true)
        previewKeyB.setTextColor(accent)
    }

    private fun pickAccent(colorRes: Int) {
        Prefs.setAccentColorRes(this, colorRes)
        recreate()
    }

    private fun applyFontToScreen() {
        val root = findViewById<View>(android.R.id.content)
        Fonts.applyToTree(root, Fonts.currentTypeface(this))
    }

    /**
     * Applies the current accent to every swatch/button on THIS screen too
     * (previously nothing here reflected the chosen accent at all), and
     * draws a visible border around whichever color/mode/font/density
     * option is currently active, so choices are actually visible instead
     * of only being saved silently to SharedPreferences.
     */
    private fun refreshSelectionState() {
        val accent = ThemeUtil.accentColor(this)
        val selectedAccentRes = Prefs.accentColorRes(this)

        ThemeUtil.setSelected(swatchCyan, selectedAccentRes == R.color.accent_cyan, accent)
        ThemeUtil.setSelected(swatchTeal, selectedAccentRes == R.color.accent_teal, accent)
        ThemeUtil.setSelected(swatchGold, selectedAccentRes == R.color.accent_gold, accent)
        ThemeUtil.setSelected(swatchPurple, selectedAccentRes == R.color.accent_purple, accent)
        ThemeUtil.setSelected(swatchSecureGreen, selectedAccentRes == R.color.accent_secure_green, accent)

        ThemeUtil.setSelected(btnAccentAuto, Prefs.accentIsAuto(this), accent)
        buildThemeCards(accent)

        val font = Prefs.fontChoice(this)
        ThemeUtil.setSelected(btnFontSans, font == 0, accent)
        ThemeUtil.setSelected(btnFontSerif, font == 1, accent)
        ThemeUtil.setSelected(btnFontMono, font == 2, accent)

        val density = Prefs.density(this)
        ThemeUtil.setSelected(btnCompact, density == 1, accent)
        ThemeUtil.setSelected(btnComfortable, density == 0, accent)

        updateHeightPreview(Prefs.keyboardHeightDp(this))
    }

    /** One card per theme: a mini preview (background / surface / accent) plus its name, two per row. */
    private fun buildThemeCards(accent: Int) {
        themeGrid.removeAllViews()
        val d = resources.displayMetrics.density
        val current = Prefs.themeId(this)
        var row: android.widget.LinearLayout? = null
        Themes.all.forEachIndexed { i, p ->
            if (i % 2 == 0) {
                row = android.widget.LinearLayout(this).apply { orientation = android.widget.LinearLayout.HORIZONTAL }
                themeGrid.addView(row, android.widget.LinearLayout.LayoutParams(-1, -2))
            }
            val card = android.widget.LinearLayout(this).apply {
                orientation = android.widget.LinearLayout.VERTICAL
                gravity = android.view.Gravity.CENTER
                setPadding((10 * d).toInt(), (10 * d).toInt(), (10 * d).toInt(), (10 * d).toInt())
                isClickable = true
                isFocusable = true
                val selected = p.id == current
                background = android.graphics.drawable.GradientDrawable().apply {
                    cornerRadius = 14 * d
                    setColor(p.bg)
                    setStroke(((if (selected) 3 else 1) * d).toInt(), if (selected) accent else p.border)
                }
                setOnClickListener {
                    Prefs.setThemeId(this@ThemeSettingsActivity, p.id)
                    Prefs.clearAccent(this@ThemeSettingsActivity)
                    recreate()
                }
            }
            val preview = android.widget.LinearLayout(this).apply {
                orientation = android.widget.LinearLayout.HORIZONTAL
                gravity = android.view.Gravity.CENTER
            }
            for (c in intArrayOf(p.surface, p.surface2, p.accent)) {
                val dot = View(this).apply {
                    background = android.graphics.drawable.GradientDrawable().apply {
                        shape = android.graphics.drawable.GradientDrawable.OVAL
                        setColor(c)
                        setStroke((1 * d).toInt(), p.border)
                    }
                }
                preview.addView(dot, android.widget.LinearLayout.LayoutParams((22 * d).toInt(), (22 * d).toInt()).apply {
                    setMargins((3 * d).toInt(), 0, (3 * d).toInt(), 0)
                })
            }
            card.addView(preview)
            card.addView(TextView(this).apply {
                text = (if (p.id == current) "✓ " else "") + getString(p.nameRes)
                setTextColor(p.text)
                textSize = 14f
                gravity = android.view.Gravity.CENTER
                setPadding(0, (8 * d).toInt(), 0, 0)
            })
            row!!.addView(card, android.widget.LinearLayout.LayoutParams(0, -2, 1f).apply {
                setMargins((5 * d).toInt(), (5 * d).toInt(), (5 * d).toInt(), (5 * d).toInt())
            })
        }
    }
}
