package com.securekeyboard.app

/**
 * Display themes. Each palette fills the same eight roles the UI uses
 * (background, surfaces, border, text colors, accent), so every screen AND the
 * keyboard recolor together. XML screens read the roles through the skBg/skSurface/...
 * theme attributes (see res/values/styles.xml, SkTheme.*), the keyboard
 * reads them from [Palette] through ThemeUtil.
 */
class Palette(
    val id: String,
    val nameRes: Int,
    val styleRes: Int,
    val dark: Boolean,
    val bg: Int,
    val surface: Int,
    val surface2: Int,
    val border: Int,
    val textSecondary: Int,
    val text: Int,
    val accent: Int
)

object Themes {
    val all: List<Palette> = listOf(
        Palette("day", R.string.theme_name_day, R.style.SkTheme_Day, false,
            0xFFF4F7FB.toInt(), 0xFFFFFFFF.toInt(), 0xFFEEF2F7.toInt(), 0xFFCBD5E1.toInt(), 0xFF64748B.toInt(), 0xFF0F172A.toInt(), 0xFF0891B2.toInt()),
        Palette("night", R.string.theme_name_night, R.style.SkTheme_Night, true,
            0xFF0B1020.toInt(), 0xFF111A33.toInt(), 0xFF18233F.toInt(), 0xFF2A3A66.toInt(), 0xFF9FB0D6.toInt(), 0xFFEAF0FF.toInt(), 0xFF5AA9FF.toInt()),
        Palette("dark", R.string.theme_name_dark, R.style.SkTheme_Dark, true,
            0xFF000000.toInt(), 0xFF0D0D0D.toInt(), 0xFF1A1A1A.toInt(), 0xFF2E2E2E.toInt(), 0xFFA3A3A3.toInt(), 0xFFF5F5F5.toInt(), 0xFF69FF46.toInt()),
        Palette("light", R.string.theme_name_light, R.style.SkTheme_Light, false,
            0xFFFFFFFF.toInt(), 0xFFF8F8F8.toInt(), 0xFFF0F0F0.toInt(), 0xFFDADADA.toInt(), 0xFF6B7280.toInt(), 0xFF111111.toInt(), 0xFF2563EB.toInt()),
        Palette("gold", R.string.theme_name_gold, R.style.SkTheme_Gold, true,
            0xFF0F0B04.toInt(), 0xFF1A1408.toInt(), 0xFF261D0B.toInt(), 0xFF5A4410.toInt(), 0xFFC9B27A.toInt(), 0xFFFFF3CF.toInt(), 0xFFF0B94A.toInt()),
        Palette("gray", R.string.theme_name_gray, R.style.SkTheme_Gray, true,
            0xFF2B2E33.toInt(), 0xFF363A40.toInt(), 0xFF40444B.toInt(), 0xFF585D66.toInt(), 0xFFB5BAC4.toInt(), 0xFFF1F3F5.toInt(), 0xFF8AB4F8.toInt()),
        Palette("emerald", R.string.theme_name_emerald, R.style.SkTheme_Emerald, true,
            0xFF06140F.toInt(), 0xFF0B2219.toInt(), 0xFF11301F.toInt(), 0xFF1F5C40.toInt(), 0xFF9AD6BA.toInt(), 0xFFE6FFF3.toInt(), 0xFF34D399.toInt()),
        Palette("ocean", R.string.theme_name_ocean, R.style.SkTheme_Ocean, false,
            0xFFE8F6FA.toInt(), 0xFFFFFFFF.toInt(), 0xFFD7EEF5.toInt(), 0xFFA5D4E2.toInt(), 0xFF3E6B7B.toInt(), 0xFF0A2A36.toInt(), 0xFF0E7490.toInt()),
        Palette("royal", R.string.theme_name_royal, R.style.SkTheme_Royal, true,
            0xFF140B24.toInt(), 0xFF1E1236.toInt(), 0xFF2A1B4A.toInt(), 0xFF4C3380.toInt(), 0xFFBBA7E8.toInt(), 0xFFF3ECFF.toInt(), 0xFFB388FF.toInt()),
        Palette("sunset", R.string.theme_name_sunset, R.style.SkTheme_Sunset, false,
            0xFFFFF4EA.toInt(), 0xFFFFFFFF.toInt(), 0xFFFFE6D2.toInt(), 0xFFF2C5A0.toInt(), 0xFF8A5A3C.toInt(), 0xFF3B1D0E.toInt(), 0xFFE8590C.toInt())
    )

    const val DEFAULT_ID = "day"

    fun byId(id: String?): Palette = all.firstOrNull { it.id == id } ?: all.first { it.id == DEFAULT_ID }
}
