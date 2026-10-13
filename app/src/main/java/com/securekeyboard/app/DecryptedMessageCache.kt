package com.securekeyboard.app

import android.content.Context
import java.io.File
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Arrays

/**
 * Encrypted-at-rest store of message plaintexts, keyed by the ciphertext.
 *
 * Why it exists:
 *  - A v4 message can only be decrypted once (ReplayGuard). Auto-decrypt shows the same
 *    message every time it scrolls into view, so the plaintext has to be remembered.
 *  - Messages you SEND are encrypted to the recipient and cannot be decrypted by you, so
 *    their plaintext is stored at send time to be shown in your own chat bubbles.
 *
 * Stored with the Keystore-backed LocalStorageCrypto. Bounded by entry count, total size
 * and age. [clear] wipes everything. Set [ENABLED] = false to turn the feature off
 * (nothing is then written or shown).
 */
object DecryptedMessageCache {
    const val ENABLED = true

    private const val FILE_NAME = "decrypted_cache_v1.enc"
    private const val TEMP_NAME = "decrypted_cache_v1.enc.tmp"
    private const val FORMAT = 1
    private const val KEY_LENGTH = 16
    private const val MAX_ENTRIES = 500
    private const val MAX_TEXT_BYTES = 16 * 1024
    private const val MAX_TOTAL_BYTES = 2 * 1024 * 1024
    private const val MAX_AGE_MS = 30L * 24L * 60L * 60L * 1000L

    private class Entry(val storedAtMs: Long, val text: ByteArray)

    // Insertion-ordered: the first entry is the oldest.
    private var memory: LinkedHashMap<String, Entry>? = null

    fun keyOf(ciphertext: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(ciphertext.trim().toByteArray(Charsets.UTF_8))
        val sb = StringBuilder(KEY_LENGTH * 2)
        for (i in 0 until KEY_LENGTH) {
            val v = digest[i].toInt() and 0xff
            sb.append("0123456789abcdef"[v ushr 4]).append("0123456789abcdef"[v and 0x0f])
        }
        return sb.toString()
    }

    @Synchronized
    fun preload(context: Context) {
        if (ENABLED) load(context)
    }

    @Synchronized
    fun get(context: Context, ciphertext: String): String? {
        if (!ENABLED) return null
        val entry = load(context)[keyOf(ciphertext)] ?: return null
        if (System.currentTimeMillis() - entry.storedAtMs > MAX_AGE_MS) return null
        return String(entry.text, Charsets.UTF_8)
    }

    @Synchronized
    fun put(context: Context, ciphertext: String, plain: CharArray) {
        if (!ENABLED) return
        val bytes = CryptoEngine.charsToUtf8Bytes(plain)
        if (bytes.isEmpty() || bytes.size > MAX_TEXT_BYTES) {
            Arrays.fill(bytes, 0)
            return
        }
        val map = load(context)
        val key = keyOf(ciphertext)
        map.remove(key)?.let { Arrays.fill(it.text, 0) }
        map[key] = Entry(System.currentTimeMillis(), bytes)
        prune(map)
        save(context, map)
    }

    @Synchronized
    fun clear(context: Context) {
        memory?.values?.forEach { Arrays.fill(it.text, 0) }
        memory = LinkedHashMap()
        File(context.filesDir, FILE_NAME).delete()
        File(context.filesDir, TEMP_NAME).delete()
    }

    private fun prune(map: LinkedHashMap<String, Entry>) {
        val now = System.currentTimeMillis()
        var total = 0
        for (e in map.values) total += e.text.size
        val it = map.entries.iterator()
        while (it.hasNext()) {
            val e = it.next()
            val tooOld = now - e.value.storedAtMs > MAX_AGE_MS
            val tooMany = map.size > MAX_ENTRIES
            val tooBig = total > MAX_TOTAL_BYTES
            if (!tooOld && !tooMany && !tooBig) break
            total -= e.value.text.size
            Arrays.fill(e.value.text, 0)
            it.remove()
        }
    }

    private fun load(context: Context): LinkedHashMap<String, Entry> {
        memory?.let { return it }
        val result = LinkedHashMap<String, Entry>()
        val file = File(context.filesDir, FILE_NAME)
        if (file.exists()) {
            var plain: ByteArray? = null
            try {
                plain = LocalStorageCrypto.decrypt(file.readBytes())
                if (plain != null) {
                    val buf = ByteBuffer.wrap(plain)
                    if (buf.int == FORMAT) {
                        val count = buf.int
                        if (count in 0..MAX_ENTRIES) {
                            repeat(count) {
                                if (buf.remaining() < KEY_LENGTH + 12) throw IllegalStateException("truncated")
                                val keyBytes = ByteArray(KEY_LENGTH)
                                buf.get(keyBytes)
                                val storedAt = buf.long
                                val len = buf.int
                                if (len < 0 || len > MAX_TEXT_BYTES || buf.remaining() < len) throw IllegalStateException("bad length")
                                val text = ByteArray(len)
                                buf.get(text)
                                result[hex(keyBytes)] = Entry(storedAt, text)
                            }
                        }
                    }
                }
            } catch (_: Exception) {
                result.clear()
            } finally {
                plain?.let { Arrays.fill(it, 0) }
            }
        }
        memory = result
        return result
    }

    private fun save(context: Context, map: LinkedHashMap<String, Entry>) {
        var total = 8
        for (e in map.values) total += KEY_LENGTH + 8 + 4 + e.text.size
        val buf = ByteBuffer.allocate(total)
        buf.putInt(FORMAT).putInt(map.size)
        for ((k, e) in map) {
            buf.put(unhex(k)).putLong(e.storedAtMs).putInt(e.text.size).put(e.text)
        }
        val bytes = buf.array()
        var encrypted: ByteArray? = null
        try {
            encrypted = LocalStorageCrypto.encrypt(bytes)
            val target = File(context.filesDir, FILE_NAME)
            val temp = File(context.filesDir, TEMP_NAME)
            temp.outputStream().use { out ->
                out.write(encrypted)
                out.flush()
                try { out.fd.sync() } catch (_: Exception) { /* best effort */ }
            }
            if (!temp.renameTo(target)) {
                temp.delete()
                throw java.io.IOException("atomic cache replace failed")
            }
        } finally {
            Arrays.fill(bytes, 0)
            encrypted?.let { Arrays.fill(it, 0) }
        }
    }

    private fun hex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xff
            sb.append("0123456789abcdef"[v ushr 4]).append("0123456789abcdef"[v and 0x0f])
        }
        return sb.toString()
    }

    private fun unhex(s: String): ByteArray {
        val out = ByteArray(s.length / 2)
        for (i in out.indices) {
            out[i] = ((Character.digit(s[2 * i], 16) shl 4) or Character.digit(s[2 * i + 1], 16)).toByte()
        }
        return out
    }
}
