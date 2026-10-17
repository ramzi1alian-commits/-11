package com.securekeyboard.app

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Arrays
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Shared pieces of the compact message formats.
 *
 *   v6 (contact-bound)   : version | flags | [expiry u32] | salt(16) | ephemeral pub (49, compressed P-384) | AES-GCM ct+tag
 *   v7 (passphrase only) : version | flags | [expiry u32] | salt(16) | AES-GCM ct+tag
 *
 * What was removed compared with v3/v4, and why this is safe:
 *  - The 12-byte IV is not sent. The AES key is derived per message from a fresh random salt (and, for
 *    v6, a fresh ephemeral key), so every key is used exactly once; the IV is derived from the same
 *    HKDF output as the key. (A fixed/derived IV is only a problem when a key is reused.)
 *  - The X.509 wrapper around the ephemeral key (120 bytes) is replaced by the 49-byte compressed point.
 *  - The Argon2 parameters (6 bytes) become a 3-bit profile number in the flags byte. Profiles are a
 *    fixed table, so a crafted message can never request an arbitrary memory/time cost.
 *  - The expiry (8 bytes) is a 4-byte unsigned value and is only present when an expiry is used.
 * The 16-byte GCM tag and the 16-byte salt are kept in full. The whole header is authenticated (AAD)
 * and hashed into the key schedule, so changing any header byte makes decryption fail.
 *
 * KDF profiles: 0..3 = Argon2id (96/64/48/32 MB, 3 passes, 1 lane; chosen by the sender's free heap),
 * 4 = PBKDF2-HMAC-SHA-256 with 600,000 iterations (the optional FIPS-compatible mode).
 */
internal object CompactFormat {
    const val VERSION_CONTACT: Byte = 6
    const val VERSION_PASSPHRASE: Byte = 7

    const val SALT_LENGTH = 16
    const val IV_LENGTH = 12
    const val TAG_BYTES = 16
    const val COMPRESSED_POINT_LENGTH = Suite.COMPRESSED_POINT_LENGTH // 49 (P-384)
    const val PROFILE_PBKDF2 = 4

    private const val FLAG_EXPIRY = 0x01
    private const val PROFILE_SHIFT = 1
    private const val PROFILE_MASK = 0x07
    private const val RESERVED_MASK = 0xF0

    class Flags(val hasExpiry: Boolean, val profile: Int)

    fun profileForNewMessage(fips: Boolean): Int {
        if (fips) return PROFILE_PBKDF2
        return when (CryptoEngine.chooseArgonMemoryKb()) {
            96 * 1024 -> 0
            64 * 1024 -> 1
            48 * 1024 -> 2
            else -> 3
        }
    }

    private fun argonMemoryKb(profile: Int): Int = when (profile) {
        0 -> 96 * 1024
        1 -> 64 * 1024
        2 -> 48 * 1024
        3 -> 32 * 1024
        else -> throw IllegalArgumentException("unknown KDF profile")
    }

    fun parseFlags(flagsByte: Byte): Flags {
        val f = flagsByte.toInt() and 0xff
        require((f and RESERVED_MASK) == 0) { "invalid flags" }
        val profile = (f shr PROFILE_SHIFT) and PROFILE_MASK
        require(profile <= PROFILE_PBKDF2) { "unknown KDF profile" }
        return Flags((f and FLAG_EXPIRY) != 0, profile)
    }

    /** version | flags | [expiry u32 big-endian]. */
    fun buildHeader(version: Byte, hasExpiry: Boolean, expiryEpochSeconds: Long, profile: Int): ByteArray {
        require(profile in 0..PROFILE_PBKDF2) { "unknown KDF profile" }
        require(!hasExpiry || expiryEpochSeconds in 1L..0xFFFFFFFFL) { "invalid expiry" }
        val buf = ByteBuffer.allocate(2 + if (hasExpiry) 4 else 0)
        buf.put(version)
        buf.put(((if (hasExpiry) FLAG_EXPIRY else 0) or (profile shl PROFILE_SHIFT)).toByte())
        if (hasExpiry) buf.putInt(expiryEpochSeconds.toInt())
        return buf.array()
    }

    fun headerLength(flags: Flags): Int = 2 + if (flags.hasExpiry) 4 else 0

    fun readExpiry(buf: ByteBuffer): Long = buf.int.toLong() and 0xFFFFFFFFL

    /** Passphrase factor, bounded by the fixed profile table (never by untrusted numbers). */
    fun deriveSecret(profile: Int, passChars: CharArray, salt: ByteArray): ByteArray =
        if (profile == PROFILE_PBKDF2) {
            CryptoEngine.derivePbkdf2Sha256(passChars, salt, CryptoEngine.PBKDF2_ITERATIONS)
        } else {
            CryptoEngine.deriveKey(
                passChars, salt, argonMemoryKb(profile),
                CryptoEngine.ARGON_ITERATIONS, CryptoEngine.ARGON_PARALLELISM
            )
        }

    /** v6: key (32) + IV (12) from both DH secrets, the passphrase factor and the whole header. */
    fun deriveContactKeyAndIv(
        dhEphemeralStatic: ByteArray,
        dhStaticStatic: ByteArray,
        passphraseKey: ByteArray,
        senderPoint: ByteArray,
        recipientPoint: ByteArray,
        header: ByteArray
    ): Pair<ByteArray, ByteArray> {
        require(senderPoint.size == Suite.POINT_LENGTH && recipientPoint.size == Suite.POINT_LENGTH) { "invalid identity point" }
        val ikm = lengthPrefixed(dhEphemeralStatic, dhStaticStatic, passphraseKey)
        val headerHash = MessageDigest.getInstance(Suite.HASH).digest(header)
        val info = LABEL_CONTACT + byteArrayOf(0) + senderPoint + recipientPoint + headerHash
        try {
            return split(hkdf(SALT_CONTACT, ikm, info, 32 + IV_LENGTH))
        } finally {
            Arrays.fill(ikm, 0); Arrays.fill(headerHash, 0); Arrays.fill(info, 0)
        }
    }

    /** v7: key (32) + IV (12) from the passphrase factor and the whole header. */
    fun derivePassphraseKeyAndIv(passphraseKey: ByteArray, header: ByteArray): Pair<ByteArray, ByteArray> {
        val headerHash = MessageDigest.getInstance(Suite.HASH).digest(header)
        val info = LABEL_PASSPHRASE + byteArrayOf(0) + headerHash
        try {
            return split(hkdf(SALT_PASSPHRASE, passphraseKey, info, 32 + IV_LENGTH))
        } finally {
            Arrays.fill(headerHash, 0); Arrays.fill(info, 0)
        }
    }

    private fun split(material: ByteArray): Pair<ByteArray, ByteArray> {
        val key = material.copyOfRange(0, 32)
        val iv = material.copyOfRange(32, 32 + IV_LENGTH)
        Arrays.fill(material, 0)
        return Pair(key, iv)
    }

    private val SALT_CONTACT = "SecureKeyboard/S2/message/v6/salt".toByteArray(Charsets.UTF_8)
    private val LABEL_CONTACT = "SecureKeyboard/S2/message/v6/contact".toByteArray(Charsets.UTF_8)
    private val SALT_PASSPHRASE = "SecureKeyboard/S2/message/v7/salt".toByteArray(Charsets.UTF_8)
    private val LABEL_PASSPHRASE = "SecureKeyboard/S2/message/v7/passphrase".toByteArray(Charsets.UTF_8)

    /** RFC 5869 HKDF with HMAC-SHA-384 (Suite 2) for outputs up to 255 blocks. */
    fun hkdf(salt: ByteArray, ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
        val extract = Mac.getInstance(Suite.HMAC)
        extract.init(SecretKeySpec(salt, Suite.HMAC))
        val prk = extract.doFinal(ikm)
        try {
            val expand = Mac.getInstance(Suite.HMAC)
            expand.init(SecretKeySpec(prk, Suite.HMAC))
            val out = ByteArrayOutputStream()
            var t = ByteArray(0)
            var counter = 1
            while (out.size() < length) {
                expand.update(t)
                expand.update(info)
                expand.update(counter.toByte())
                t = expand.doFinal()
                out.write(t, 0, t.size)
                counter++
            }
            val all = out.toByteArray()
            try {
                return all.copyOf(length)
            } finally {
                Arrays.fill(all, 0); Arrays.fill(t, 0)
            }
        } finally {
            Arrays.fill(prk, 0)
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
}
