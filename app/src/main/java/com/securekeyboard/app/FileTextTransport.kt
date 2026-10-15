package com.securekeyboard.app

import android.content.Context
import android.util.Base64
import java.io.File
import java.security.SecureRandom

/**
 * OPTIONAL extra transport (V53): an already-encrypted SKF2 file sent as plain chat TEXT.
 *
 * Chat apps do not let a keyboard drop an arbitrary file into a chat, but they do accept text.
 * The bytes sent are exactly the encrypted .skf file (nothing is decrypted or weakened); they
 * are only Base64url-encoded behind the "SKFT1:" prefix. The receiver copies the message, taps
 * 🔓, and the keyboard rebuilds the .skf and opens the normal secure receive screen.
 *
 * Off by default: the normal file flow (commit / share) is untouched unless the user turns the
 * "send as text" switch on for the attached file.
 */
object FileTextTransport {
    const val PREFIX = "SKFT1:"
    private const val DIR = "secure_inbox"
    private const val MAX_DECODED_BYTES = 64 * 1024
    private const val MAX_AGE_MS = 60L * 60L * 1000L
    private val NAME_RE = Regex("^in_[0-9a-f]{16}\\.skf$")
    private val B64URL = Regex("^[A-Za-z0-9_-]+$")
    private val MAGIC = byteArrayOf('S'.code.toByte(), 'K'.code.toByte(), 'F'.code.toByte(), '2'.code.toByte())

    fun isToken(text: String?): Boolean = text != null && text.trimStart().startsWith(PREFIX)

    /** Longest message the target app takes: WhatsApp ~65k chars, Telegram and most others ~4k. */
    fun maxChars(pkg: String?): Int =
        if (pkg == "com.whatsapp" || pkg == "com.whatsapp.w4b") 40_000 else 3_800

    fun fits(file: File, pkg: String?): Boolean {
        val chars = PREFIX.length + ((file.length() * 4 + 2) / 3)
        return chars <= maxChars(pkg)
    }

    fun encode(file: File): String =
        PREFIX + Base64.encodeToString(file.readBytes(), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    /** Rebuilds the encrypted file from a copied message. Returns the inbox file NAME (not a path), or null. */
    fun decodeToInbox(context: Context, text: String): String? {
        val body = text.trim().removePrefix(PREFIX).filterNot { it.isWhitespace() }
        if (body.length < 40 || !B64URL.matches(body)) return null
        val bytes = try { Base64.decode(body, Base64.URL_SAFE or Base64.NO_WRAP) } catch (e: Exception) { return null }
        if (bytes.size < MAGIC.size || bytes.size > MAX_DECODED_BYTES) return null
        for (i in MAGIC.indices) if (bytes[i] != MAGIC[i]) return null
        val dir = File(context.filesDir, DIR).apply { mkdirs() }
        purgeOld(context)
        val rnd = ByteArray(8).also { SecureRandom().nextBytes(it) }
        val name = "in_" + rnd.joinToString("") { "%02x".format(it) } + ".skf"
        File(dir, name).writeBytes(bytes)
        return name
    }

    /** Only files this app wrote into its own inbox; anything else (paths, "..") is refused. */
    fun resolveInbox(context: Context, name: String?): File? {
        if (name == null || !NAME_RE.matches(name)) return null
        val dir = File(context.filesDir, DIR)
        val f = File(dir, name)
        return try {
            if (f.isFile && f.canonicalFile.parentFile == dir.canonicalFile) f else null
        } catch (e: Exception) { null }
    }

    fun purgeOld(context: Context) {
        val now = System.currentTimeMillis()
        File(context.filesDir, DIR).listFiles()?.forEach {
            if (now - it.lastModified() > MAX_AGE_MS) it.delete()
        }
    }
}
