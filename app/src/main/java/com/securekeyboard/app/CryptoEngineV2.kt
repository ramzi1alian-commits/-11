package com.securekeyboard.app

import android.util.Base64
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.security.SecureRandom
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Contact-bound message encryption.
 *
 * FORMAT v4 (all new messages)
 * ----------------------------
 * header (authenticated as AAD, and hashed into the key schedule):
 *   version(1)=4 | expiryFlag(1) | expiryEpochSec(8) |
 *   argonMemoryKb(4) | argonIterations(1) | argonParallelism(1) |
 *   argonSalt(16) | ephemeralKeyLen(2) | ephemeralPublicKey(X.509)
 * then: iv(12) | AES-256-GCM ciphertext+tag
 *
 * Key schedule:
 *   dh1 = ECDH(ephemeral, recipient identity)   - fresh per message
 *   dh2 = ECDH(sender identity, recipient identity) - authenticates the sender
 *   pw  = Argon2id(passphrase, argonSalt, params from header)
 *   key = HKDF-SHA256(ikm = lenprefix(dh1, dh2, pw),
 *                     info = label | senderPoint | recipientPoint | SHA-256(header))
 *
 * What this gives: confidentiality + integrity, sender authentication (a message
 * only decrypts if it came from the selected contact's identity key AND the
 * right passphrase), a memory-hard passphrase factor, and key separation per
 * sender/recipient pair. Replays of an already-opened message are rejected.
 *
 * What this does NOT give: forward secrecy against theft of the RECIPIENT's
 * long-term identity key. That needs recipient-published rotating prekeys, which
 * a serverless QR-pairing app cannot distribute. See docs/security/V41_CHANGES.md.
 *
 * Older formats: v3 (ephemeral-static, no sender auth) is still readable;
 * v2 (static-static) is refused unless [ALLOW_LEGACY_V2_DECRYPT] is enabled.
 */
object CryptoEngineV2 {
    private const val IV_LENGTH = 12
    private const val SALT_LENGTH = 16
    private const val TAG_BYTES = 16
    private const val MAX_EPHEMERAL_KEY_BYTES = 200
    private const val MAX_CIPHERTEXT_BASE64_CHARS = 2_000_000
    private const val LEGACY_HEADER_LENGTH = 1 + 1 + 8
    private const val V3_PREFIX_LENGTH = 1 + 1 + 8 + 2
    // version, expiryFlag, expiry, argonMem, argonIter, argonPar, salt, ephLen
    private const val V4_FIXED_LENGTH = 1 + 1 + 8 + 4 + 1 + 1 + SALT_LENGTH + 2

    const val FORMAT_VERSION: Byte = 4
    private const val V3_FORMAT_VERSION: Byte = 3
    private const val LEGACY_FORMAT_VERSION: Byte = 2

    /** v3 messages (no sender authentication) remain readable so old conversations still open. */
    const val ALLOW_LEGACY_V3_DECRYPT = true

    /** v2 used one static-static key per contact pair forever. Off by default. */
    const val ALLOW_LEGACY_V2_DECRYPT = false

    /** Reject a v4 ciphertext that was already decrypted once on this device. */
    const val ENFORCE_REPLAY_PROTECTION = true

    fun encrypt(
        context: android.content.Context,
        textChars: CharArray,
        passphraseChars: CharArray,
        recipientPublicKey: PublicKey,
        expirySeconds: Long? = null
    ): String {
        require(passphraseChars.isNotEmpty()) { "passphrase is empty" }
        if (expirySeconds != null) require(expirySeconds > 0) { "invalid expiry" }
        DeviceIdentity.requireValidP256PublicKey(recipientPublicKey)

        val random = SecureRandom()
        val ephemeral = DeviceIdentity.generateEphemeralKeyPair()
        val ephemeralBytes = ephemeral.public.encoded
        val salt = ByteArray(SALT_LENGTH).also { random.nextBytes(it) }
        val iv = ByteArray(IV_LENGTH).also { random.nextBytes(it) }
        val memoryKb = CryptoEngine.chooseArgonMemoryKb()
        val iterations = CryptoEngine.ARGON_ITERATIONS
        val parallelism = CryptoEngine.ARGON_PARALLELISM

        var passphraseKey = ByteArray(0)
        var dhEphemeral = ByteArray(0)
        var dhStatic = ByteArray(0)
        var senderPoint = ByteArray(0)
        var recipientPoint = ByteArray(0)
        var key = ByteArray(0)
        var plainBytes = ByteArray(0)
        var header = ByteArray(0)
        try {
            require(ephemeralBytes.size in 50..MAX_EPHEMERAL_KEY_BYTES) { "invalid ephemeral public key" }
            val hasExpiry = expirySeconds != null
            val expiryEpoch = if (hasExpiry) (System.currentTimeMillis() / 1000L) + expirySeconds!! else 0L
            header = ByteBuffer.allocate(V4_FIXED_LENGTH + ephemeralBytes.size)
                .put(FORMAT_VERSION)
                .put(if (hasExpiry) 1.toByte() else 0.toByte())
                .putLong(expiryEpoch)
                .putInt(memoryKb)
                .put(iterations.toByte())
                .put(parallelism.toByte())
                .put(salt)
                .putShort(ephemeralBytes.size.toShort())
                .put(ephemeralBytes)
                .array()

            passphraseKey = CryptoEngine.deriveKey(passphraseChars, salt, memoryKb, iterations, parallelism)
            dhEphemeral = DeviceIdentity.computeSharedSecretWithPrivateKey(ephemeral.private, recipientPublicKey)
            dhStatic = DeviceIdentity.computeSharedSecret(context, recipientPublicKey)
            senderPoint = DeviceIdentity.myPublicPoint(context)
            recipientPoint = DeviceIdentity.publicPoint(recipientPublicKey)
            key = ContactCrypto.deriveMessageKeyV4(
                dhEphemeral, dhStatic, passphraseKey, senderPoint, recipientPoint, header
            )

            plainBytes = CryptoEngine.charsToUtf8Bytes(textChars)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            cipher.updateAAD(header)
            val cipherBytes = cipher.doFinal(plainBytes)
            val encoded = Base64.encodeToString(header + iv + cipherBytes, Base64.NO_WRAP)
            // You cannot decrypt your own outgoing message (it is encrypted to the recipient),
            // so remember its plaintext to show it in your own chat bubble. Never fails a send.
            try { DecryptedMessageCache.put(context, encoded, textChars, DecryptedMessageCache.fingerprintOf(passphraseChars)) } catch (_: Exception) { }
            return encoded
        } finally {
            Arrays.fill(passphraseKey, 0); Arrays.fill(dhEphemeral, 0); Arrays.fill(dhStatic, 0)
            Arrays.fill(senderPoint, 0); Arrays.fill(recipientPoint, 0); Arrays.fill(key, 0)
            Arrays.fill(plainBytes, 0); Arrays.fill(header, 0)
            Arrays.fill(iv, 0); Arrays.fill(salt, 0); Arrays.fill(ephemeralBytes, 0)
        }
    }

    fun decrypt(
        context: android.content.Context,
        b64: String,
        passphraseChars: CharArray,
        senderPublicKey: PublicKey
    ): CharArray {
        require(passphraseChars.isNotEmpty()) { "passphrase is empty" }
        val encoded = b64.trim()
        require(encoded.isNotEmpty() && encoded.length <= MAX_CIPHERTEXT_BASE64_CHARS) {
            "ciphertext too large or empty"
        }
        DeviceIdentity.requireValidP256PublicKey(senderPublicKey)
        val combined = Base64.decode(encoded, Base64.NO_WRAP)
        try {
            require(combined.size > LEGACY_HEADER_LENGTH + IV_LENGTH) { "ciphertext too short" }
            val plain = when (combined[0]) {
                FORMAT_VERSION -> decryptV4(context, combined, passphraseChars, senderPublicKey)
                V3_FORMAT_VERSION -> {
                    require(ALLOW_LEGACY_V3_DECRYPT) { "legacy v3 messages are disabled" }
                    decryptV3(context, combined, passphraseChars)
                }
                LEGACY_FORMAT_VERSION -> {
                    require(ALLOW_LEGACY_V2_DECRYPT) { "legacy v2 messages are disabled" }
                    decryptLegacy(context, combined, passphraseChars, senderPublicKey)
                }
                else -> throw IllegalArgumentException("unsupported format version")
            }
            // A v4 message opens only once (replay protection); remember it for re-display.
            try { DecryptedMessageCache.put(context, encoded, plain, DecryptedMessageCache.fingerprintOf(passphraseChars)) } catch (_: Exception) { }
            return plain
        } finally {
            Arrays.fill(combined, 0)
        }
    }

    private fun decryptV4(
        context: android.content.Context,
        combined: ByteArray,
        passphraseChars: CharArray,
        senderPublicKey: PublicKey
    ): CharArray {
        require(combined.size >= V4_FIXED_LENGTH + 50 + IV_LENGTH + TAG_BYTES) { "ciphertext too short" }
        val buf = ByteBuffer.wrap(combined)
        buf.get() // version
        val expiryFlag = buf.get().toInt()
        val expiryEpochSeconds = buf.long
        val memoryKb = buf.int
        val iterations = buf.get().toInt() and 0xff
        val parallelism = buf.get().toInt() and 0xff
        val salt = ByteArray(SALT_LENGTH)
        buf.get(salt)
        val ephLen = buf.short.toInt() and 0xffff
        require(ephLen in 50..MAX_EPHEMERAL_KEY_BYTES) { "invalid ephemeral key length" }
        val headerLength = V4_FIXED_LENGTH + ephLen
        require(combined.size > headerLength + IV_LENGTH + TAG_BYTES) { "ciphertext too short" }

        // The header is untrusted until the GCM tag verifies, so bound the Argon2 work
        // BEFORE allocating memory (otherwise a crafted header is a memory-exhaustion DoS).
        require(memoryKb in CryptoEngine.MIN_ARGON_MEMORY_KB..CryptoEngine.MAX_ARGON_MEMORY_KB) { "invalid Argon2 memory cost" }
        require(iterations in CryptoEngine.MIN_ARGON_ITERATIONS..CryptoEngine.MAX_ARGON_ITERATIONS) { "invalid Argon2 iteration count" }
        require(parallelism in CryptoEngine.MIN_ARGON_PARALLELISM..CryptoEngine.MAX_ARGON_PARALLELISM) { "invalid Argon2 parallelism" }
        validateExpiry(expiryFlag, expiryEpochSeconds)

        val header = combined.copyOfRange(0, headerLength)
        val ephemeralBytes = combined.copyOfRange(V4_FIXED_LENGTH, headerLength)
        val iv = combined.copyOfRange(headerLength, headerLength + IV_LENGTH)
        val cipherBytes = combined.copyOfRange(headerLength + IV_LENGTH, combined.size)

        // Cheap early rejection of an already-opened message (before Argon2).
        val messageId = replayId(header, iv)
        if (ENFORCE_REPLAY_PROTECTION && ReplayGuard.isSeen(context, messageId)) {
            Arrays.fill(header, 0); Arrays.fill(ephemeralBytes, 0); Arrays.fill(iv, 0); Arrays.fill(cipherBytes, 0)
            throw ReplayedMessageException()
        }

        var passphraseKey = ByteArray(0)
        var dhEphemeral = ByteArray(0)
        var dhStatic = ByteArray(0)
        var senderPoint = ByteArray(0)
        var recipientPoint = ByteArray(0)
        var key = ByteArray(0)
        try {
            val ephemeralPublic = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(ephemeralBytes))
            DeviceIdentity.requireValidP256PublicKey(ephemeralPublic)
            passphraseKey = CryptoEngine.deriveKey(passphraseChars, salt, memoryKb, iterations, parallelism)
            dhEphemeral = DeviceIdentity.computeSharedSecret(context, ephemeralPublic)
            dhStatic = DeviceIdentity.computeSharedSecret(context, senderPublicKey)
            senderPoint = DeviceIdentity.publicPoint(senderPublicKey)
            recipientPoint = DeviceIdentity.myPublicPoint(context)
            key = ContactCrypto.deriveMessageKeyV4(
                dhEphemeral, dhStatic, passphraseKey, senderPoint, recipientPoint, header
            )
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            cipher.updateAAD(header)
            val plainBytes = cipher.doFinal(cipherBytes)
            try {
                // Only a message that authenticated may enter the replay cache.
                if (ENFORCE_REPLAY_PROTECTION) ReplayGuard.markSeen(context, messageId)
                return utf8ToChars(plainBytes)
            } finally { Arrays.fill(plainBytes, 0) }
        } finally {
            Arrays.fill(passphraseKey, 0); Arrays.fill(dhEphemeral, 0); Arrays.fill(dhStatic, 0)
            Arrays.fill(senderPoint, 0); Arrays.fill(recipientPoint, 0); Arrays.fill(key, 0)
            Arrays.fill(header, 0); Arrays.fill(ephemeralBytes, 0); Arrays.fill(iv, 0)
            Arrays.fill(cipherBytes, 0); Arrays.fill(salt, 0); Arrays.fill(messageId, 0)
        }
    }

    /** v3: ephemeral-static ECDH + unstretched passphrase. Read-only support. */
    private fun decryptV3(
        context: android.content.Context,
        combined: ByteArray,
        passphraseChars: CharArray
    ): CharArray {
        require(combined.size >= V3_PREFIX_LENGTH + 50 + IV_LENGTH + TAG_BYTES) { "ciphertext too short" }
        val headerPrefix = combined.copyOfRange(0, V3_PREFIX_LENGTH)
        val buf = ByteBuffer.wrap(headerPrefix)
        buf.get()
        val expiryFlag = buf.get().toInt()
        val expiryEpochSeconds = buf.long
        val ephLen = buf.short.toInt() and 0xffff
        require(ephLen in 50..MAX_EPHEMERAL_KEY_BYTES) { "invalid ephemeral key length" }
        val headerLength = V3_PREFIX_LENGTH + ephLen
        require(combined.size > headerLength + IV_LENGTH + TAG_BYTES) { "ciphertext too short" }
        val header = combined.copyOfRange(0, headerLength)
        val ephemeralBytes = combined.copyOfRange(V3_PREFIX_LENGTH, headerLength)
        val iv = combined.copyOfRange(headerLength, headerLength + IV_LENGTH)
        val cipherBytes = combined.copyOfRange(headerLength + IV_LENGTH, combined.size)
        try {
            validateExpiry(expiryFlag, expiryEpochSeconds)
            val ephemeralPublic = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(ephemeralBytes))
            val keyBytes = ContactCrypto.deriveAes256KeyFromEphemeralPublic(context, ephemeralPublic, passphraseChars, ContactCrypto.Purpose.MESSAGE)
            try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(keyBytes, "AES"), GCMParameterSpec(128, iv))
                cipher.updateAAD(header)
                val plainBytes = cipher.doFinal(cipherBytes)
                try { return utf8ToChars(plainBytes) } finally { Arrays.fill(plainBytes, 0) }
            } finally { Arrays.fill(keyBytes, 0) }
        } finally {
            Arrays.fill(headerPrefix, 0); Arrays.fill(header, 0); Arrays.fill(ephemeralBytes, 0)
            Arrays.fill(iv, 0); Arrays.fill(cipherBytes, 0)
        }
    }

    /** v2: static-static. Disabled by default (see ALLOW_LEGACY_V2_DECRYPT). */
    private fun decryptLegacy(context: android.content.Context, combined: ByteArray, passphraseChars: CharArray, senderPublicKey: PublicKey): CharArray {
        val header = combined.copyOfRange(0, LEGACY_HEADER_LENGTH)
        try {
            val headerBuffer = ByteBuffer.wrap(header)
            headerBuffer.get()
            val expiryFlag = headerBuffer.get().toInt()
            val expiryEpochSeconds = headerBuffer.long
            validateExpiry(expiryFlag, expiryEpochSeconds)
            val iv = combined.copyOfRange(LEGACY_HEADER_LENGTH, LEGACY_HEADER_LENGTH + IV_LENGTH)
            val cipherBytes = combined.copyOfRange(LEGACY_HEADER_LENGTH + IV_LENGTH, combined.size)
            try {
                val keyBytes = ContactCrypto.deriveAes256Key(context, senderPublicKey, passphraseChars, ContactCrypto.Purpose.MESSAGE)
                try {
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(keyBytes, "AES"), GCMParameterSpec(128, iv))
                    cipher.updateAAD(header)
                    val plainBytes = cipher.doFinal(cipherBytes)
                    try { return utf8ToChars(plainBytes) } finally { Arrays.fill(plainBytes, 0) }
                } finally { Arrays.fill(keyBytes, 0) }
            } finally { Arrays.fill(iv, 0); Arrays.fill(cipherBytes, 0) }
        } finally { Arrays.fill(header, 0) }
    }

    /** 16-byte identifier unique to one message: SHA-256(header || iv), truncated. */
    private fun replayId(header: ByteArray, iv: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(header)
        md.update(iv)
        val full = md.digest()
        try {
            return full.copyOf(ReplayGuard.ID_LENGTH)
        } finally {
            Arrays.fill(full, 0)
        }
    }

    private fun validateExpiry(flag: Int, epoch: Long) {
        require(flag == 0 || flag == 1) { "invalid expiry flag" }
        if (flag != 0) {
            require(epoch > 0L) { "invalid expiry" }
            if (System.currentTimeMillis() / 1000L >= epoch) throw ExpiredMessageException()
        }
    }

    private fun utf8ToChars(bytes: ByteArray): CharArray {
        val decoder = Charsets.UTF_8.newDecoder()
        val chars = decoder.decode(ByteBuffer.wrap(bytes)).let { buffer -> CharArray(buffer.remaining()).also { buffer.get(it) } }
        return chars
    }

    class ExpiredMessageException : Exception()

    /** This exact ciphertext was already decrypted on this device. */
    class ReplayedMessageException : Exception()
}
