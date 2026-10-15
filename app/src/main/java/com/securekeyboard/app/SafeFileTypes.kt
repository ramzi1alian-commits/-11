package com.securekeyboard.app

/**
 * Decrypted files come from other people. Types that can run code or active
 * content are never opened by the app itself (they can still be saved/shared).
 */
object SafeFileTypes {
    private val RISKY = setOf(
        "apk", "apks", "xapk", "aab", "dex", "jar", "so", "sh", "bat", "cmd", "com", "exe", "msi", "scr",
        "pif", "lnk", "vbs", "vbe", "js", "jse", "wsf", "wsh", "ps1", "psm1", "py", "pl", "rb", "php",
        "html", "htm", "xhtml", "svg", "hta", "jnlp", "reg", "dll", "app", "command", "desktop", "iso", "img"
    )

    fun isRisky(name: String): Boolean {
        val parts = name.lowercase().trim().split('.')
        if (parts.size < 2) return false
        // Checks every extension so "photo.jpg.apk" and "a.apk.txt" are both flagged.
        return parts.drop(1).any { it in RISKY }
    }
}
