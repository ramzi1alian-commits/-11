package com.securekeyboard.app

import android.content.Context
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.PublicKey
import java.util.Arrays
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Single cryptographic identity layer for contact-bound content.
 *
 * Every contact-bound operation starts from the same device identity and the
 * selected contact public key through ECDH. The resulting secret is then
 * domain-separated with HKDF/HMAC-SHA384 (Suite 2) so messages and files never reuse
 * the same AES key, while still belonging to the exact same contact identity.
 *
 * Two derivation families live here:
 *
 *  - v1 ("FILE" and legacy "MESSAGE"): sharedSecret || passphrase -> HKDF.
 *    Output is byte-for-byte unchanged from earlier releases so existing
 *    files and v2/v3 messages stay decryptable. (The passphrase is NOT
 *    stretched in this family; that is why new messages use v4.)
 *
 *  - v4 ("deriveMessageKeyV4"): two DH secrets (ephemeral-static for
 *    per-message freshness, static-static for sender authentication), an
 *    Argon2id-stretched passphrase key, and a transcript hash binding both
 *    identities and the whole message header into the derived key.
 *
 * Nothing is sent to a server.
 */
object ContactCrypto {
    private const val KEY_LENGTH_BYTES = 32

    private const val MESSAGE_SALT = "SecureKeyboard-v1-e2e-salt"
    private const val MESSAGE_INFO = "SecureKeyboard-message-key-v1"
    private const val FILE_SALT = "SecureKeyboard-file-salt-v1"
    private const val FILE_INFO = "SecureKeyboard-file-key-v1"

    private const val MESSAGE_V4_SALT = "SecureKeyboard-S2-msg-salt"
    private const val MESSAGE_V4_INFO = "SecureKeyboard-S2-message-key"

    init {
        // See CryptoProvider's doc comment / DeviceIdentity's init block.
        CryptoProvider.ensureRegistered()
    }

    enum class Purpose(val salt: String, val info: String) {
        MESSAGE(MESSAGE_SALT, MESSAGE_INFO),
        FILE(FILE_SALT, FILE_INFO)
    }

    fun deriveAes256KeyFromEphemeralPrivate(
        ephemeralPrivateKey: java.security.PrivateKey,
        recipientPublicKey: PublicKey,
        passphraseChars: CharArray,
        purpose: Purpose
    ): ByteArray = deriveFromSharedSecretForInternal(
        DeviceIdentity.computeSharedSecretWithPrivateKey(ephemeralPrivateKey, recipientPublicKey),
        passphraseChars,
        purpose
    )

    fun deriveAes256KeyFromEphemeralPublic(
        context: Context,
        senderEphemeralPublicKey: PublicKey,
        passphraseChars: CharArray,
        purpose: Purpose
    ): ByteArray = deriveFromSharedSecretForInternal(
        DeviceIdentity.computeSharedSecret(context, senderEphemeralPublicKey),
        passphraseChars,
        purpose
    )

    /**
     * v3 file key (pure public-key, no passphrase): HKDF over ECDH(ephemeral, recipient)
     * bound to both public points. Wipes [sharedSecret]; the caller owns the points.
     */
    fun deriveFileKeyV3(sharedSecret: ByteArray, ephemeralPoint: ByteArray, recipientPoint: ByteArray): ByteArray {
        require(ephemeralPoint.size == Suite.POINT_LENGTH && recipientPoint.size == Suite.POINT_LENGTH) { "invalid identity point" }
        val salt = "SecureKeyboard-S2-file-salt".toByteArray(Charsets.UTF_8)
        val label = "SecureKeyboard-S2-file-key".toByteArray(Charsets.UTF_8)
        val info = label + byteArrayOf(0) + ephemeralPoint + recipientPoint
        return try {
            hkdf(salt, sharedSecret, info)
        } finally {
            Arrays.fill(sharedSecret, 0); Arrays.fill(salt, 0); Arrays.fill(label, 0); Arrays.fill(info, 0)
        }
    }

    /** v1 derivation. Wipes [sharedSecret] before returning. Output unchanged from earlier releases. */
    fun deriveFromSharedSecretForInternal(
        sharedSecret: ByteArray,
        passphraseChars: CharArray,
        purpose: Purpose
    ): ByteArray {
        require(passphraseChars.isNotEmpty()) { "passphrase is empty" }
        val passBytes = CryptoEngine.charsToUtf8Bytes(passphraseChars)
        val ikm = sharedSecret + passBytes
        val salt = purpose.salt.toByteArray(Charsets.UTF_8)
        val info = purpose.info.toByteArray(Charsets.UTF_8)
        return try {
            hkdf(salt, ikm, info)
        } finally {
            Arrays.fill(sharedSecret, 0)
            Arrays.fill(passBytes, 0)
            Arrays.fill(ikm, 0)
            Arrays.fill(salt, 0)
            Arrays.fill(info, 0)
        }
    }

    /** Derives the AES-256 key from the same contact identity used everywhere (static-static, v1 family). */
    fun deriveAes256Key(
        context: Context,
        contactPublicKey: PublicKey,
        passphraseChars: CharArray,
        purpose: Purpose
    ): ByteArray = deriveFromSharedSecretForInternal(
        DeviceIdentity.computeSharedSecret(context, contactPublicKey),
        passphraseChars,
        purpose
    )

    /**
     * v4 message key.
     *
     * @param dhEphemeralStatic ECDH(ephemeral, recipient static)
     * @param dhStaticStatic    ECDH(sender static, recipient static) - proves sender identity
     * @param passphraseKey     Argon2id output of the passphrase (already stretched)
     * @param senderPoint       canonical 97-byte uncompressed sender identity point
     * @param recipientPoint    canonical 97-byte uncompressed recipient identity point
     * @param header            the complete authenticated message header
     *
     * Caller owns (and must wipe) every input array; this function wipes only its own temporaries.
     */
    fun deriveMessageKeyV4(
        dhEphemeralStatic: ByteArray,
        dhStaticStatic: ByteArray,
        passphraseKey: ByteArray,
        senderPoint: ByteArray,
        recipientPoint: ByteArray,
        header: ByteArray
    ): ByteArray {
        require(senderPoint.size == Suite.POINT_LENGTH && recipientPoint.size == Suite.POINT_LENGTH) { "invalid identity point" }
        val ikm = lengthPrefixed(dhEphemeralStatic, dhStaticStatic, passphraseKey)
        val salt = MESSAGE_V4_SALT.toByteArray(Charsets.UTF_8)
        val headerHash = MessageDigest.getInstance(Suite.HASH).digest(header)
        val label = MESSAGE_V4_INFO.toByteArray(Charsets.UTF_8)
        val info = label + byteArrayOf(0) + senderPoint + recipientPoint + headerHash
        return try {
            hkdf(salt, ikm, info)
        } finally {
            Arrays.fill(ikm, 0)
            Arrays.fill(salt, 0)
            Arrays.fill(headerHash, 0)
            Arrays.fill(label, 0)
            Arrays.fill(info, 0)
        }
    }

    /** 4-byte big-endian length before each part, so concatenation is unambiguous. */
    private fun lengthPrefixed(vararg parts: ByteArray): ByteArray {
        var total = 0
        for (p in parts) total += 4 + p.size
        val buf = ByteBuffer.allocate(total)
        for (p in parts) buf.putInt(p.size).put(p)
        return buf.array()
    }

    /** HKDF with HMAC-SHA-384 (RFC 5869), single expand block; the first 32 bytes are used as the AES-256 key. */
    private fun hkdf(salt: ByteArray, ikm: ByteArray, info: ByteArray): ByteArray {
        val extract = Mac.getInstance(Suite.HMAC)
        extract.init(SecretKeySpec(salt, Suite.HMAC))
        val prk = extract.doFinal(ikm)
        try {
            val expand = Mac.getInstance(Suite.HMAC)
            expand.init(SecretKeySpec(prk, Suite.HMAC))
            val block = expand.doFinal(info + byteArrayOf(1))
            try {
                return block.copyOf(KEY_LENGTH_BYTES)
            } finally {
                Arrays.fill(block, 0)
            }
        } finally {
            Arrays.fill(prk, 0)
        }
    }
}
