package com.securekeyboard.app

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

/**
 * Short-lived session passphrase.
 *
 * V62 - the key now really DIES at expiry and cannot be brought back:
 *  - While active, the passphrase is kept in memory and (so leaving a screen does not lose it) as an
 *    AES-GCM blob encrypted with a dedicated Android-Keystore key created for THIS session only.
 *  - That Keystore key is created with setKeyValidityForConsumptionEnd(expiry): after the expiry time the
 *    Keystore itself refuses to decrypt with it - enforced outside the app, even if the app was not running
 *    at that moment and even for the app's own code.
 *  - At expiry (timer while the app is alive) and on every later start/read, the in-memory copy is wiped,
 *    the blob is deleted and the Keystore key entry is deleted.
 *  - The old V2 storage (blob wrapped with the long-lived app key) is deleted on first start.
 */
object SessionKeyStore {
    const val DEFAULT_DURATION_MS = 30 * 60 * 1000L
    private const val MAX_DURATION_MS = 24 * 60 * 60 * 1000L
    private const val PREFS = "secure_session_key_v3"
    private const val OLD_PREFS = "secure_session_key_v2"
    private const val BLOB = "encrypted_passphrase"
    private const val EXPIRES_WALL = "expires_wall_ms"
    private const val KS_ALIAS = "sk_session_wrap_v3"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    @Volatile private var passphrase: CharArray? = null
    @Volatile private var expiresAtElapsedMs: Long = 0L
    @Volatile private var expiresAtWallMs: Long = 0L
    @Volatile private var initialized = false
    private var appContext: Context? = null

    private val handler by lazy { Handler(Looper.getMainLooper()) }
    private val expireRunnable = Runnable { clear() }

    @Synchronized
    fun initialize(context: Context) {
        if (initialized) return
        appContext = context.applicationContext
        initialized = true
        // Old storage format (key wrapped by the permanent app key) must not linger.
        try {
            appContext?.getSharedPreferences(OLD_PREFS, Context.MODE_PRIVATE)?.edit()?.clear()?.apply()
        } catch (_: Exception) {}
        restorePersisted()
    }

    @Synchronized
    private fun restorePersisted() {
        val ctx = appContext ?: return
        val prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val expiresWall = prefs.getLong(EXPIRES_WALL, 0L)
        val stored = prefs.getString(BLOB, null)
        if (expiresWall <= System.currentTimeMillis() || stored.isNullOrEmpty()) {
            clear()
            return
        }
        try {
            val parts = stored.split(":")
            require(parts.size == 2)
            val iv = android.util.Base64.decode(parts[0], android.util.Base64.NO_WRAP)
            val ct = android.util.Base64.decode(parts[1], android.util.Base64.NO_WRAP)
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val key = ks.getKey(KS_ALIAS, null) ?: run { clear(); return }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            // Throws once the key's validity window has ended: the key cannot be recovered after expiry.
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            val plain = cipher.doFinal(ct)
            try {
                val text = String(plain, Charsets.UTF_8)
                if (text.isNotEmpty()) {
                    passphrase = text.toCharArray()
                    expiresAtWallMs = expiresWall
                    val remaining = (expiresWall - System.currentTimeMillis()).coerceAtLeast(1L)
                    expiresAtElapsedMs = SystemClock.elapsedRealtime() + remaining
                    scheduleExpiry(remaining)
                }
            } finally {
                SecureMemory.wipe(plain)
            }
        } catch (_: Throwable) {
            clear()
        }
    }

    @Synchronized
    fun set(chars: CharArray, durationMs: Long = DEFAULT_DURATION_MS) {
        require(chars.isNotEmpty()) { "passphrase is empty" }
        val safeDuration = durationMs.coerceIn(1L, MAX_DURATION_MS)
        clear()
        passphrase = chars.copyOf()
        expiresAtElapsedMs = SystemClock.elapsedRealtime() + safeDuration
        expiresAtWallMs = System.currentTimeMillis() + safeDuration
        persist()
        scheduleExpiry(safeDuration)
    }

    private fun scheduleExpiry(delayMs: Long) {
        handler.removeCallbacks(expireRunnable)
        handler.postDelayed(expireRunnable, delayMs)
    }

    @Synchronized
    private fun persist() {
        val ctx = appContext ?: return
        val p = passphrase ?: return
        try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (ks.containsAlias(KS_ALIAS)) ks.deleteEntry(KS_ALIAS)
            val spec = KeyGenParameterSpec.Builder(
                KS_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setKeyValidityForConsumptionEnd(java.util.Date(expiresAtWallMs))
                .build()
            val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            gen.init(spec)
            val key = gen.generateKey()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val plain = String(p).toByteArray(Charsets.UTF_8)
            try {
                val ct = cipher.doFinal(plain)
                val blob = android.util.Base64.encodeToString(cipher.iv, android.util.Base64.NO_WRAP) + ":" +
                    android.util.Base64.encodeToString(ct, android.util.Base64.NO_WRAP)
                ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                    .putString(BLOB, blob)
                    .putLong(EXPIRES_WALL, expiresAtWallMs)
                    .commit()
                SecureMemory.wipe(ct)
            } finally {
                SecureMemory.wipe(plain)
            }
        } catch (_: Throwable) {
            // If persistence fails, keep the secure in-memory session alive (it still expires on time).
        }
    }

    @Synchronized
    fun get(): CharArray? {
        if (!initialized) return null
        val p = passphrase ?: return null
        if (SystemClock.elapsedRealtime() >= expiresAtElapsedMs ||
            System.currentTimeMillis() >= expiresAtWallMs) {
            clear()
            return null
        }
        return p.copyOf()
    }

    @Synchronized
    fun isActive(): Boolean = get()?.also { SecureMemory.wipe(it) } != null

    @Synchronized
    fun remainingMinutes(): Long {
        if (passphrase == null) return 0L
        val remainingMs = minOf(
            expiresAtElapsedMs - SystemClock.elapsedRealtime(),
            expiresAtWallMs - System.currentTimeMillis()
        )
        if (remainingMs <= 0L) {
            clear()
            return 0L
        }
        return ((remainingMs + 59_999L) / 60_000L).coerceAtLeast(1L)
    }

    /** Wipes memory, deletes the stored blob and DELETES the Keystore key: nothing is left to recover. */
    @Synchronized
    fun clear() {
        handler.removeCallbacks(expireRunnable)
        passphrase?.let { SecureMemory.wipe(it) }
        passphrase = null
        expiresAtElapsedMs = 0L
        expiresAtWallMs = 0L
        try {
            appContext?.getSharedPreferences(PREFS, Context.MODE_PRIVATE)?.edit()
                ?.remove(BLOB)?.remove(EXPIRES_WALL)?.commit()
        } catch (_: Exception) {}
        try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (ks.containsAlias(KS_ALIAS)) ks.deleteEntry(KS_ALIAS)
        } catch (_: Throwable) {}
    }
}
