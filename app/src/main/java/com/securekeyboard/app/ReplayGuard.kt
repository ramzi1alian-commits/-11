package com.securekeyboard.app

import android.content.Context
import java.io.File
import java.nio.ByteBuffer
import java.util.Arrays

/**
 * Remembers the IDs of v4 messages that were already successfully decrypted,
 * so a captured ciphertext cannot be fed back to the app a second time.
 *
 * Design notes:
 *  - IDs are only recorded AFTER the AEAD tag verified, so an attacker cannot
 *    poison the cache with garbage.
 *  - The cache is bounded (oldest entries are evicted). A replay of a message
 *    older than the last [MAX_ENTRIES] successful decryptions is therefore
 *    not detected; the optional per-message expiry covers that case.
 *  - The cache file is encrypted with the Keystore-backed LocalStorageCrypto.
 *    If it cannot be read it is treated as empty (fail-open) rather than
 *    locking the user out of all messages.
 *  - Trade-off: the same ciphertext cannot be opened twice. Re-read the
 *    plaintext that was already shown instead of decrypting again.
 */
object ReplayGuard {
    private const val FILE_NAME = "replay_cache_v1.enc"
    private const val TEMP_NAME = "replay_cache_v1.enc.tmp"
    private const val FORMAT = 1
    const val ID_LENGTH = 16
    private const val MAX_ENTRIES = 4096

    @Synchronized
    fun isSeen(context: Context, id: ByteArray): Boolean {
        require(id.size == ID_LENGTH) { "invalid message id" }
        return load(context).contains(hex(id))
    }

    @Synchronized
    fun markSeen(context: Context, id: ByteArray) {
        require(id.size == ID_LENGTH) { "invalid message id" }
        val entries = load(context)
        val key = hex(id)
        entries.remove(key)
        entries.add(key)
        while (entries.size > MAX_ENTRIES) {
            val oldest = entries.iterator()
            oldest.next()
            oldest.remove()
        }
        save(context, entries)
    }

    private fun load(context: Context): LinkedHashSet<String> {
        val result = LinkedHashSet<String>()
        val file = File(context.filesDir, FILE_NAME)
        if (!file.exists()) return result
        var plain: ByteArray? = null
        try {
            plain = LocalStorageCrypto.decrypt(file.readBytes()) ?: return result
            val buf = ByteBuffer.wrap(plain)
            if (buf.int != FORMAT) return LinkedHashSet()
            val count = buf.int
            if (count < 0 || count > MAX_ENTRIES || buf.remaining() < count * ID_LENGTH) return LinkedHashSet()
            val id = ByteArray(ID_LENGTH)
            repeat(count) {
                buf.get(id)
                result.add(hex(id))
            }
        } catch (_: Exception) {
            return LinkedHashSet()
        } finally {
            plain?.let { Arrays.fill(it, 0) }
        }
        return result
    }

    private fun save(context: Context, entries: LinkedHashSet<String>) {
        val plain = ByteBuffer.allocate(8 + entries.size * ID_LENGTH)
        plain.putInt(FORMAT).putInt(entries.size)
        for (e in entries) plain.put(unhex(e))
        val bytes = plain.array()
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
                throw java.io.IOException("atomic replay cache replace failed")
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
