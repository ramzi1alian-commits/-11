package com.securekeyboard.app

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.MessageDigest
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Short-lived store of message plaintexts, keyed by the ciphertext.
 *
 * Why it exists:
 *  - A v4 message can only be decrypted once (ReplayGuard). Auto-decrypt shows the same message every
 *    time it scrolls into view, so the plaintext has to be remembered for a while.
 *  - Messages you SEND are encrypted to the recipient and cannot be decrypted by you, so their plaintext
 *    is stored at send time to be shown in your own chat bubbles.
 *
 * V66 - nothing stays longer than [MAX_AGE_MS] (30 minutes) and what expires cannot be brought back:
 *  - Every entry is dropped 30 minutes after it was stored. After that it cannot be shown again, not even
 *    your own sent message (the replay guard stops re-decryption by design).
 *  - The file is encrypted with an Android-Keystore key that is created for each rewrite and valid only
 *    until the OLDEST entry expires (setKeyValidityForConsumptionEnd). The previous key is DELETED as soon
 *    as the new file is in place, so older copies of the file left behind by flash storage are
 *    undecryptable at once (cryptographic erasure), and the live file dies by itself at expiry even if the
 *    app is not running.
 *  - Besides that, the old file is overwritten with zeros before it is replaced or deleted, in-memory
 *    plaintext is zeroed, and a timer re-keys the file at the next expiry while the app is alive.
 *
 * Every entry is bound to a fingerprint of the passphrase it was produced with and is only returned while
 * the SAME passphrase is in use. Bounded by entry count, total size and age. [clear] wipes everything.
 */
object DecryptedMessageCache {
    const val ENABLED = true

    private const val FILE_NAME = "decrypted_cache_v3.enc"
    private const val TEMP_NAME = "decrypted_cache_v3.enc.tmp"
    private val LEGACY_FILES = arrayOf("decrypted_cache_v1.enc", "decrypted_cache_v1.enc.tmp")
    private const val FORMAT = 2 // plaintext layout inside the encrypted blob
    private const val FILE_VERSION: Byte = 3
    private const val KEY_LENGTH = 16
    private const val FP_LENGTH = 16
    private const val MAX_ENTRIES = 500
    private const val MAX_TEXT_BYTES = 16 * 1024
    private const val MAX_TOTAL_BYTES = 2 * 1024 * 1024
    private const val MAX_AGE_MS = 30L * 60L * 1000L // V66: 30 minutes (V65: 6 h, before: 30 days)
    private const val ALIAS_A = "sk_msgcache_a_v3"
    private const val ALIAS_B = "sk_msgcache_b_v3"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    private class Entry(val storedAtMs: Long, val text: ByteArray, val fp: String)

    // Insertion-ordered: the first entry is the oldest.
    private var memory: LinkedHashMap<String, Entry>? = null
    private var currentAliasIdx = -1
    private val handler by lazy { Handler(Looper.getMainLooper()) }
    private var expiryRunnable: Runnable? = null

    fun keyOf(ciphertext: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(ciphertext.trim().toByteArray(Charsets.UTF_8))
        val sb = StringBuilder(KEY_LENGTH * 2)
        for (i in 0 until KEY_LENGTH) {
            val v = digest[i].toInt() and 0xff
            sb.append("0123456789abcdef"[v ushr 4]).append("0123456789abcdef"[v and 0x0f])
        }
        return sb.toString()
    }

    /**
     * Identifies a passphrase without revealing it. Only ever stored inside the
     * Keystore-encrypted cache file and compared in memory.
     */
    fun fingerprintOf(passphrase: CharArray): String {
        val bytes = CryptoEngine.charsToUtf8Bytes(passphrase)
        try {
            val md = MessageDigest.getInstance("SHA-256")
            md.update("SecureKeyboard/message-cache-binding/v1".toByteArray(Charsets.UTF_8))
            md.update(0)
            md.update(bytes)
            val digest = md.digest()
            val sb = StringBuilder(FP_LENGTH * 2)
            for (i in 0 until FP_LENGTH) {
                val v = digest[i].toInt() and 0xff
                sb.append("0123456789abcdef"[v ushr 4]).append("0123456789abcdef"[v and 0x0f])
            }
            return sb.toString()
        } finally {
            Arrays.fill(bytes, 0)
        }
    }

    @Synchronized
    fun preload(context: Context) {
        if (ENABLED) load(context)
    }

    @Synchronized
    fun get(context: Context, ciphertext: String, fingerprint: String): String? {
        if (!ENABLED) return null
        val map = load(context)
        val k = keyOf(ciphertext)
        val entry = map[k] ?: return null
        if (System.currentTimeMillis() - entry.storedAtMs > MAX_AGE_MS) {
            // Expired: zero it now and re-key the file without it.
            map.remove(k)?.let { Arrays.fill(it.text, 0) }
            saveQuietly(context, map)
            return null
        }
        // Stored under a different passphrase: not visible with the current one.
        if (!MessageDigest.isEqual(entry.fp.toByteArray(Charsets.UTF_8), fingerprint.toByteArray(Charsets.UTF_8))) return null
        return String(entry.text, Charsets.UTF_8)
    }

    @Synchronized
    fun put(context: Context, ciphertext: String, plain: CharArray, fingerprint: String) {
        if (!ENABLED) return
        val bytes = CryptoEngine.charsToUtf8Bytes(plain)
        if (bytes.isEmpty() || bytes.size > MAX_TEXT_BYTES) {
            Arrays.fill(bytes, 0)
            return
        }
        val map = load(context)
        val key = keyOf(ciphertext)
        map.remove(key)?.let { Arrays.fill(it.text, 0) }
        map[key] = Entry(System.currentTimeMillis(), bytes, fingerprint)
        saveQuietly(context, map)
    }

    @Synchronized
    fun clear(context: Context) {
        memory?.values?.forEach { Arrays.fill(it.text, 0) }
        memory = LinkedHashMap()
        wipeStorage(context)
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

    // ---- storage -----------------------------------------------------------------------------------

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    private fun aliasOf(idx: Int) = if (idx == 0) ALIAS_A else ALIAS_B

    private fun dropAlias(idx: Int) {
        if (idx !in 0..1) return
        try { val ks = keyStore(); if (ks.containsAlias(aliasOf(idx))) ks.deleteEntry(aliasOf(idx)) } catch (_: Throwable) {}
    }

    private fun newKey(idx: Int, validUntilMs: Long): SecretKey {
        val ks = keyStore()
        if (ks.containsAlias(aliasOf(idx))) ks.deleteEntry(aliasOf(idx))
        val spec = KeyGenParameterSpec.Builder(
            aliasOf(idx), KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setKeyValidityForConsumptionEnd(java.util.Date(validUntilMs))
            .build()
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        gen.init(spec)
        return gen.generateKey()
    }

    /** Overwrites a file with zeros (best effort on flash) and deletes it. */
    private fun shred(f: File) {
        try {
            if (f.isFile) {
                java.io.RandomAccessFile(f, "rw").use { raf ->
                    val zeros = ByteArray(16 * 1024)
                    var left = raf.length()
                    raf.seek(0)
                    while (left > 0) {
                        val n = minOf(left, zeros.size.toLong()).toInt()
                        raf.write(zeros, 0, n)
                        left -= n
                    }
                    raf.fd.sync()
                }
            }
        } catch (_: Throwable) {}
        try { f.delete() } catch (_: Throwable) {}
    }

    private fun wipeStorage(context: Context) {
        expiryRunnable?.let { handler.removeCallbacks(it) }
        expiryRunnable = null
        shred(File(context.filesDir, FILE_NAME))
        shred(File(context.filesDir, TEMP_NAME))
        dropAlias(0)
        dropAlias(1)
        currentAliasIdx = -1
    }

    private fun scheduleExpiry(context: Context, validUntilMs: Long) {
        expiryRunnable?.let { handler.removeCallbacks(it) }
        val app = context.applicationContext
        val r = Runnable { refresh(app) }
        expiryRunnable = r
        handler.postDelayed(r, (validUntilMs - System.currentTimeMillis()).coerceAtLeast(0L) + 500L)
    }

    /** Timer / maintenance: drop expired entries and re-key the file for the rest. */
    @Synchronized
    private fun refresh(context: Context) {
        val map = load(context)
        saveQuietly(context, map)
    }

    private fun load(context: Context): LinkedHashMap<String, Entry> {
        memory?.let { return it }
        for (name in LEGACY_FILES) shred(File(context.filesDir, name)) // old format: gone for good
        val result = LinkedHashMap<String, Entry>()
        val file = File(context.filesDir, FILE_NAME)
        if (file.exists()) {
            var plain: ByteArray? = null
            try {
                val blob = file.readBytes()
                val minLen = 1 + 1 + 8 + 12 + 16
                if (blob.size < minLen || blob[0] != FILE_VERSION) throw IllegalStateException("bad file")
                val idx = blob[1].toInt()
                if (idx !in 0..1) throw IllegalStateException("bad key index")
                val iv = blob.copyOfRange(10, 22)
                val ct = blob.copyOfRange(22, blob.size)
                val key = keyStore().getKey(aliasOf(idx), null) ?: throw IllegalStateException("key gone")
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                // Throws once the key's validity window has ended: expired data cannot be recovered.
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
                plain = cipher.doFinal(ct)
                val buf = ByteBuffer.wrap(plain)
                if (buf.int == FORMAT) {
                    val count = buf.int
                    if (count in 0..MAX_ENTRIES) {
                        repeat(count) {
                            if (buf.remaining() < KEY_LENGTH + FP_LENGTH + 12) throw IllegalStateException("truncated")
                            val keyBytes = ByteArray(KEY_LENGTH)
                            buf.get(keyBytes)
                            val fpBytes = ByteArray(FP_LENGTH)
                            buf.get(fpBytes)
                            val storedAt = buf.long
                            val len = buf.int
                            if (len < 0 || len > MAX_TEXT_BYTES || buf.remaining() < len) throw IllegalStateException("bad length")
                            val text = ByteArray(len)
                            buf.get(text)
                            result[hex(keyBytes)] = Entry(storedAt, text, hex(fpBytes))
                        }
                    }
                }
                currentAliasIdx = idx
            } catch (_: Throwable) {
                result.values.forEach { Arrays.fill(it.text, 0) }
                result.clear()
                wipeStorage(context) // unreadable / expired: remove file and keys
            } finally {
                plain?.let { Arrays.fill(it, 0) }
            }
        }
        memory = result
        if (result.isNotEmpty()) saveQuietly(context, result) // drops anything already expired, re-keys
        return result
    }

    private fun saveQuietly(context: Context, map: LinkedHashMap<String, Entry>) {
        try {
            save(context, map)
        } catch (_: Throwable) {
            // Persistence failed (e.g. Keystore problem): keep the short-lived in-memory copy only.
            try { wipeStorage(context) } catch (_: Throwable) {}
        }
    }

    private fun save(context: Context, map: LinkedHashMap<String, Entry>) {
        prune(map)
        if (map.isEmpty()) {
            wipeStorage(context)
            return
        }
        val oldestStored = map.values.minOf { it.storedAtMs }
        val validUntil = oldestStored + MAX_AGE_MS
        val newIdx = if (currentAliasIdx == 0) 1 else 0
        val key = newKey(newIdx, validUntil)

        var total = 8
        for (e in map.values) total += KEY_LENGTH + FP_LENGTH + 8 + 4 + e.text.size
        val buf = ByteBuffer.allocate(total)
        buf.putInt(FORMAT).putInt(map.size)
        for ((k, e) in map) {
            buf.put(unhex(k)).put(unhex(e.fp)).putLong(e.storedAtMs).putInt(e.text.size).put(e.text)
        }
        val bytes = buf.array()
        var ct: ByteArray? = null
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            ct = cipher.doFinal(bytes)
            val iv = cipher.iv
            val out = ByteBuffer.allocate(1 + 1 + 8 + iv.size + ct.size)
            out.put(FILE_VERSION).put(newIdx.toByte()).putLong(validUntil).put(iv).put(ct)
            val target = File(context.filesDir, FILE_NAME)
            val temp = File(context.filesDir, TEMP_NAME)
            temp.outputStream().use { o ->
                o.write(out.array())
                o.flush()
                try { o.fd.sync() } catch (_: Exception) { /* best effort */ }
            }
            // Overwrite the previous file with zeros before it is replaced.
            shred(target)
            if (!temp.renameTo(target)) {
                temp.delete()
                throw java.io.IOException("cache replace failed")
            }
            // New file is in place: kill the previous key so every older copy is undecryptable.
            dropAlias(currentAliasIdx)
            currentAliasIdx = newIdx
            scheduleExpiry(context, validUntil)
        } finally {
            Arrays.fill(bytes, 0)
            ct?.let { Arrays.fill(it, 0) }
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
