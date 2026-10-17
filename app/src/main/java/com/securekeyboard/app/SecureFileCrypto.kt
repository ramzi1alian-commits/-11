package com.securekeyboard.app

import android.content.Context
import android.net.Uri
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.security.SecureRandom
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.CipherOutputStream
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Contact-bound streaming file encryption.
 *
 * SKF2 v3 (current) is PURE PUBLIC-KEY encryption: the sender needs only the
 * recipient's public key. A fresh P-256 ephemeral key pair is generated for
 * every file; the AES-256-GCM key is
 *   HKDF(ECDH(ephemeralPrivate, recipientPublic), info = ephPoint || recipientPoint)
 * and the recipient re-derives it with ECDH(recipientPrivate, ephemeralPublic).
 * No passphrase / session key is involved, so a file can be encrypted for a
 * contact at any time and only that contact's device can open it.
 *
 * SKF2 v4 (PUBLIC / session mode) is passphrase-only encryption for when no
 * contact is paired: AES-256-GCM key = HKDF(KDF(session passphrase, random salt)).
 * The KDF is chosen from the same fixed profile table as the compact text
 * messages ([CompactFormat]: Argon2id 96/64/48/32 MB, or PBKDF2-HMAC-SHA-256 in the
 * optional FIPS mode), so a crafted file can never request an arbitrary cost.
 * Both sides must hold the same session passphrase (agreed out of band).
 *
 * SKF2 v2 (ECDHE + session passphrase) and v1 (static ECDH + passphrase) stay
 * decryptable for migration compatibility - they still need the passphrase
 * that was used when they were written.
 */
object SecureFileCrypto {
    private val MAGIC = byteArrayOf('S'.code.toByte(), 'K'.code.toByte(), 'F'.code.toByte(), '2'.code.toByte())
    private const val VERSION_LEGACY: Byte = 1
    private const val VERSION_ECDHE: Byte = 2
    private const val VERSION_PUBKEY: Byte = 3
    private const val VERSION_PASSPHRASE: Byte = 4
    /** Suite 2: SKF2 v1/v2 files (P-256 / unstretched) are no longer accepted. */
    private const val ALLOW_LEGACY_FILES = false
    private const val SALT_LENGTH = 16
    private val SALT_FILE_PASS = "SecureKeyboard/file/v4/salt".toByteArray(Charsets.UTF_8)
    private val LABEL_FILE_PASS = "SecureKeyboard/file/v4/passphrase".toByteArray(Charsets.UTF_8)
    private const val IV_LENGTH = 12
    private const val EPHEMERAL_MAX = 200
    private const val LEGACY_HEADER_LENGTH = 4 + 1 + IV_LENGTH + IV_LENGTH + 4
    private const val ECDHE_FIXED_HEADER = 4 + 1 + 2 + IV_LENGTH + IV_LENGTH + 4
    private const val MAX_METADATA_CIPHER = 64 * 1024
    private const val BUFFER_SIZE = 64 * 1024
    // Hard upper bound for a single encrypted file. This is a policy/DoS
    // guard, not a cryptographic limit. Raise only with an explicit product
    // decision and corresponding storage/streaming tests.
    private const val MAX_FILE_BYTES = 4L * 1024L * 1024L * 1024L

    init {
        // See CryptoProvider's doc comment / DeviceIdentity's init block.
        CryptoProvider.ensureRegistered()
    }

    private fun aesGcmEncrypt(key: ByteArray, iv: ByteArray, aad: ByteArray, plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        cipher.updateAAD(aad)
        return cipher.doFinal(plain)
    }

    private fun aesGcmDecrypt(key: ByteArray, iv: ByteArray, aad: ByteArray, cipherBytes: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        cipher.updateAAD(aad)
        return cipher.doFinal(cipherBytes)
    }

    /** Thrown when an old (v1/v2) file is opened without the passphrase it was sealed with. */
    class PassphraseRequiredException : Exception("this older file needs the session passphrase")

    /**
     * Encrypts [input] for [recipientPublicKey] only (public-key encryption, no
     * passphrase). [output] is written in full; the source is only read.
     */
    fun encrypt(context: Context, input: Uri, output: Uri, recipientPublicKey: PublicKey, displayName: String?) {
        context.contentResolver.openInputStream(input).use { rawIn ->
            require(rawIn != null) { "cannot open input" }
            context.contentResolver.openOutputStream(output, "wt").use { rawOut ->
                require(rawOut != null) { "cannot open output" }
                encryptStreams(rawIn, rawOut, recipientPublicKey, displayName)
            }
        }
    }

    /** Same as [encrypt] but writes straight to a private [outFile]. */
    fun encryptToFile(context: Context, input: Uri, outFile: File, recipientPublicKey: PublicKey, displayName: String?) {
        try {
            context.contentResolver.openInputStream(input).use { rawIn ->
                require(rawIn != null) { "cannot open input" }
                FileOutputStream(outFile).use { rawOut ->
                    encryptStreams(rawIn, rawOut, recipientPublicKey, displayName)
                    rawOut.flush()
                    try { rawOut.fd.sync() } catch (_: Exception) { /* best effort */ }
                }
            }
        } catch (e: Exception) {
            outFile.delete()
            throw e
        }
    }

    private fun encryptStreams(
        rawIn: java.io.InputStream,
        rawOut: java.io.OutputStream,
        recipientPublicKey: PublicKey,
        displayName: String?
    ) {
        val recipientPoint = DeviceIdentity.publicPoint(recipientPublicKey) // also validates the key
        val ephemeral = DeviceIdentity.generateEphemeralKeyPair()
        val ephemeralPoint = DeviceIdentity.publicPoint(ephemeral.public)
        val key = ContactCrypto.deriveFileKeyV3(
            DeviceIdentity.computeSharedSecretWithPrivateKey(ephemeral.private, recipientPublicKey),
            ephemeralPoint, recipientPoint
        )
        val random = SecureRandom()
        val metaIv = ByteArray(IV_LENGTH).also { random.nextBytes(it) }
        val contentIv = ByteArray(IV_LENGTH).also { random.nextBytes(it) }
        var header = ByteArray(0)
        var metaCipher = ByteArray(0)
        val ephemeralPub = ephemeral.public.encoded
        try {
            require(ephemeralPub.size in 50..EPHEMERAL_MAX) { "invalid ephemeral public key" }
            val filenameBytes = (displayName ?: "encrypted_file").ifBlank { "encrypted_file" }.toByteArray(Charsets.UTF_8)
            try {
                require(filenameBytes.size <= 4096) { "filename too long" }
                // Layout (identical to v2): MAGIC | ver | ephLen(2) | ephPub | metaIv | contentIv | metaLen(4)
                header = MAGIC + byteArrayOf(VERSION_PUBKEY) +
                    ByteBuffer.allocate(2).putShort(ephemeralPub.size.toShort()).array() +
                    ephemeralPub + metaIv + contentIv + ByteArray(4)
                metaCipher = aesGcmEncrypt(key, metaIv, header.copyOf(header.size - 4), filenameBytes)
                require(metaCipher.size <= MAX_METADATA_CIPHER)
                ByteBuffer.wrap(header, header.size - 4, 4).putInt(metaCipher.size)
            } finally { Arrays.fill(filenameBytes, 0) }

            BufferedInputStream(rawIn, BUFFER_SIZE).use { inputStream ->
                val outputStream = BufferedOutputStream(rawOut, BUFFER_SIZE)
                outputStream.write(header)
                outputStream.write(metaCipher)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, contentIv))
                cipher.updateAAD(header + metaCipher)
                val buffer = ByteArray(BUFFER_SIZE)
                var total = 0L
                try {
                    while (true) {
                        val read = inputStream.read(buffer)
                        if (read < 0) break
                        total += read.toLong()
                        require(total <= MAX_FILE_BYTES) { "file too large" }
                        val part = cipher.update(buffer, 0, read)
                        if (part != null && part.isNotEmpty()) outputStream.write(part)
                    }
                    outputStream.write(cipher.doFinal())
                    outputStream.flush()
                } finally { Arrays.fill(buffer, 0) }
            }
        } finally {
            Arrays.fill(key, 0); Arrays.fill(metaIv, 0); Arrays.fill(contentIv, 0)
            Arrays.fill(header, 0); Arrays.fill(metaCipher, 0); Arrays.fill(ephemeralPub, 0)
            Arrays.fill(recipientPoint, 0); Arrays.fill(ephemeralPoint, 0)
        }
    }

    /**
     * PUBLIC (session) mode: encrypts [input] with the session [passphrase] only - no
     * contact / pairing needed. Writes straight to a private [outFile]; the source is
     * only read. Format SKF2 v4:
     *   MAGIC | 4 | profile(1) | salt(16) | metaIv(12) | contentIv(12) | metaLen(4) | metaCipher | content
     */
    fun encryptWithPassphraseToFile(
        context: Context, input: Uri, outFile: File,
        passphrase: CharArray, displayName: String?, fipsMode: Boolean
    ) {
        require(passphrase.isNotEmpty()) { "passphrase is empty" }
        try {
            context.contentResolver.openInputStream(input).use { rawIn ->
                require(rawIn != null) { "cannot open input" }
                FileOutputStream(outFile).use { rawOut ->
                    encryptPassphraseStreams(rawIn, rawOut, passphrase, displayName, fipsMode)
                    rawOut.flush()
                    try { rawOut.fd.sync() } catch (_: Exception) { /* best effort */ }
                }
            }
        } catch (e: Exception) {
            outFile.delete()
            throw e
        }
    }

    /** key = HKDF(KDF(passphrase, salt), info = label || prefix || profile || salt). */
    private fun derivePassphraseFileKey(profile: Int, passphrase: CharArray, salt: ByteArray, headerStart: ByteArray): ByteArray {
        val secret = CompactFormat.deriveSecret(profile, passphrase, salt)
        val info = LABEL_FILE_PASS + byteArrayOf(0) + headerStart
        try {
            return CompactFormat.hkdf(SALT_FILE_PASS, secret, info, 32)
        } finally {
            Arrays.fill(secret, 0); Arrays.fill(info, 0)
        }
    }

    private fun encryptPassphraseStreams(
        rawIn: java.io.InputStream,
        rawOut: java.io.OutputStream,
        passphrase: CharArray,
        displayName: String?,
        fipsMode: Boolean
    ) {
        val random = SecureRandom()
        val profile = CompactFormat.profileForNewMessage(fipsMode)
        val salt = ByteArray(SALT_LENGTH).also { random.nextBytes(it) }
        val metaIv = ByteArray(IV_LENGTH).also { random.nextBytes(it) }
        val contentIv = ByteArray(IV_LENGTH).also { random.nextBytes(it) }
        // Fixed, authenticated prefix that is also bound into the key: MAGIC | ver | profile | salt
        val headerStart = MAGIC + byteArrayOf(VERSION_PASSPHRASE, profile.toByte()) + salt
        val key = derivePassphraseFileKey(profile, passphrase, salt, headerStart)
        var header = ByteArray(0)
        var metaCipher = ByteArray(0)
        try {
            val filenameBytes = (displayName ?: "encrypted_file").ifBlank { "encrypted_file" }.toByteArray(Charsets.UTF_8)
            try {
                require(filenameBytes.size <= 4096) { "filename too long" }
                header = headerStart + metaIv + contentIv + ByteArray(4)
                metaCipher = aesGcmEncrypt(key, metaIv, header.copyOf(header.size - 4), filenameBytes)
                require(metaCipher.size <= MAX_METADATA_CIPHER)
                ByteBuffer.wrap(header, header.size - 4, 4).putInt(metaCipher.size)
            } finally { Arrays.fill(filenameBytes, 0) }
            streamEncryptContent(rawIn, rawOut, key, contentIv, header, metaCipher)
        } finally {
            Arrays.fill(key, 0); Arrays.fill(salt, 0); Arrays.fill(metaIv, 0); Arrays.fill(contentIv, 0)
            Arrays.fill(header, 0); Arrays.fill(metaCipher, 0); Arrays.fill(headerStart, 0)
        }
    }

    private fun streamEncryptContent(
        rawIn: java.io.InputStream, rawOut: java.io.OutputStream,
        key: ByteArray, contentIv: ByteArray, header: ByteArray, metaCipher: ByteArray
    ) {
        BufferedInputStream(rawIn, BUFFER_SIZE).use { inputStream ->
            val outputStream = BufferedOutputStream(rawOut, BUFFER_SIZE)
            outputStream.write(header)
            outputStream.write(metaCipher)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, contentIv))
            cipher.updateAAD(header + metaCipher)
            val buffer = ByteArray(BUFFER_SIZE)
            var total = 0L
            try {
                while (true) {
                    val read = inputStream.read(buffer)
                    if (read < 0) break
                    total += read.toLong()
                    require(total <= MAX_FILE_BYTES) { "file too large" }
                    val part = cipher.update(buffer, 0, read)
                    if (part != null && part.isNotEmpty()) outputStream.write(part)
                }
                outputStream.write(cipher.doFinal())
                outputStream.flush()
            } finally { Arrays.fill(buffer, 0) }
        }
    }

    private class PassphraseHeader(
        val header: ByteArray,
        val key: ByteArray,
        val metaIv: ByteArray,
        val contentIv: ByteArray,
        val metaLen: Int
    ) {
        fun wipe() {
            Arrays.fill(header, 0); Arrays.fill(key, 0); Arrays.fill(metaIv, 0); Arrays.fill(contentIv, 0)
        }
    }

    /** Layout after the 5-byte prefix: profile(1) | salt(16) | metaIv(12) | contentIv(12) | metaLen(4). */
    private fun readPassphraseHeader(input: java.io.InputStream, prefix: ByteArray, passphrase: CharArray): PassphraseHeader {
        val rest = ByteArray(1 + SALT_LENGTH + IV_LENGTH * 2 + 4)
        readFully(input, rest)
        val profile = rest[0].toInt() and 0xff
        require(profile in 0..CompactFormat.PROFILE_PBKDF2) { "unknown KDF profile" }
        val salt = rest.copyOfRange(1, 1 + SALT_LENGTH)
        val metaIv = rest.copyOfRange(1 + SALT_LENGTH, 1 + SALT_LENGTH + IV_LENGTH)
        val contentIv = rest.copyOfRange(1 + SALT_LENGTH + IV_LENGTH, 1 + SALT_LENGTH + IV_LENGTH * 2)
        val metaLen = ByteBuffer.wrap(rest, rest.size - 4, 4).int
        require(metaLen in 16..MAX_METADATA_CIPHER) { "invalid metadata" }
        val header = prefix + rest
        val headerStart = prefix + rest.copyOfRange(0, 1 + SALT_LENGTH)
        val key = try {
            derivePassphraseFileKey(profile, passphrase, salt, headerStart)
        } finally {
            Arrays.fill(salt, 0); Arrays.fill(headerStart, 0); Arrays.fill(rest, 0)
        }
        return PassphraseHeader(header, key, metaIv, contentIv, metaLen)
    }

    private fun verifyPassphrase(input: java.io.InputStream, prefix: ByteArray, passphrase: CharArray): String {
        val h = readPassphraseHeader(input, prefix, passphrase)
        val metaCipher = ByteArray(h.metaLen)
        try {
            readFully(input, metaCipher)
            val filenameBytes = aesGcmDecrypt(h.key, h.metaIv, h.header.copyOf(h.header.size - 4), metaCipher)
            val filename = try { String(filenameBytes, Charsets.UTF_8) } finally { Arrays.fill(filenameBytes, 0) }
            verifyContent(input, h.key, h.contentIv, h.header, metaCipher)
            return filename
        } finally {
            Arrays.fill(metaCipher, 0); h.wipe()
        }
    }

    private fun decryptPassphrase(input: java.io.InputStream, prefix: ByteArray, passphrase: CharArray, temp: File): Pair<File, String> {
        val h = readPassphraseHeader(input, prefix, passphrase)
        val metaCipher = ByteArray(h.metaLen)
        try {
            readFully(input, metaCipher)
            val filenameBytes = aesGcmDecrypt(h.key, h.metaIv, h.header.copyOf(h.header.size - 4), metaCipher)
            val filename = try { String(filenameBytes, Charsets.UTF_8) } finally { Arrays.fill(filenameBytes, 0) }
            decryptContent(input, temp, h.key, h.contentIv, h.header, metaCipher)
            return temp to filename
        } finally {
            Arrays.fill(metaCipher, 0); h.wipe()
        }
    }

    /**
     * Decrypts to a private cache file. For current (v3) files only this
     * device's own private key is needed - [contactPublicKey] and
     * [passphrase] may be null. Public-mode (v4) files and older v1/v2 files
     * need [passphrase] (v1 also the contact key); [PassphraseRequiredException]
     * is thrown when it is missing.
     */
    fun decryptToTemp(context: Context, input: Uri, contactPublicKey: PublicKey?, passphrase: CharArray?): Pair<File, String> {
        val temp = File.createTempFile("skf_dec_", ".tmp", context.cacheDir)
        try {
            // Two-pass authenticated decryption for streaming GCM:
            // pass 1 consumes the complete ciphertext and verifies the tag
            // without releasing plaintext; pass 2 writes plaintext only after
            // authentication has succeeded. This avoids exposing unauthenticated
            // plaintext produced by Cipher.update().
            val filename = context.contentResolver.openInputStream(input).use { rawIn ->
                require(rawIn != null) { "cannot open input" }
                BufferedInputStream(rawIn, BUFFER_SIZE).use { inputStream ->
                    val prefix = ByteArray(5)
                    try {
                        readFully(inputStream, prefix)
                        require(prefix.copyOfRange(0, 4).contentEquals(MAGIC)) { "not a SecureKeyboard file" }
                        when (prefix[4]) {
                            VERSION_LEGACY -> { require(ALLOW_LEGACY_FILES) { "old file format is not supported" }; verifyLegacy(context, inputStream, prefix, needContact(contactPublicKey), needPass(passphrase)) }
                            VERSION_ECDHE -> { require(ALLOW_LEGACY_FILES) { "old file format is not supported" }; verifyEcdhe(context, inputStream, prefix, KeyMode.PASSPHRASE, needPass(passphrase)) }
                            VERSION_PUBKEY -> verifyEcdhe(context, inputStream, prefix, KeyMode.PUBLIC_KEY, null)
                            VERSION_PASSPHRASE -> verifyPassphrase(inputStream, prefix, needPass(passphrase))
                            else -> throw IllegalArgumentException("unsupported file version")
                        }
                    } finally { Arrays.fill(prefix, 0) }
                }
            }

            // Re-open the Uri for the second pass. Only authenticated content
            // reaches the private cache file.
            context.contentResolver.openInputStream(input).use { rawIn ->
                require(rawIn != null) { "cannot open input" }
                BufferedInputStream(rawIn, BUFFER_SIZE).use { inputStream ->
                    val prefix = ByteArray(5)
                    try {
                        readFully(inputStream, prefix)
                        when (prefix[4]) {
                            VERSION_LEGACY -> { require(ALLOW_LEGACY_FILES) { "old file format is not supported" }; decryptLegacy(context, inputStream, prefix, needContact(contactPublicKey), needPass(passphrase), temp) }
                            VERSION_ECDHE -> { require(ALLOW_LEGACY_FILES) { "old file format is not supported" }; decryptEcdhe(context, inputStream, prefix, KeyMode.PASSPHRASE, needPass(passphrase), temp) }
                            VERSION_PUBKEY -> decryptEcdhe(context, inputStream, prefix, KeyMode.PUBLIC_KEY, null, temp)
                            VERSION_PASSPHRASE -> decryptPassphrase(inputStream, prefix, needPass(passphrase), temp)
                            else -> throw IllegalArgumentException("unsupported file version")
                        }
                    } finally { Arrays.fill(prefix, 0) }
                }
            }
            return temp to filename
        } catch (e: Exception) {
            SecureMemory.secureDelete(temp)
            throw e
        }
    }

    /**
     * Reads and parses the ECDHE (SKF2 v2) header, in the SAME byte order
     * that encrypt() actually writes it:
     *   ephLen(2) -> ephemeralPub(ephLen) -> metaIv(12) -> contentIv(12) -> metaLen(4)
     *
     * A prior version of this parser read a fixed ECDHE_FIXED_HEADER-5 byte
     * block immediately after ephLen, on the mistaken assumption that the
     * variable-length ephemeral public key came AFTER metaIv/contentIv/
     * metaLen instead of before them. That misalignment caused every field
     * read after ephLen (the ephemeral key bytes, metaIv, contentIv, and
     * metaLen) to be read from the wrong stream offset, corrupting or
     * failing every v2 decrypt. Do not reorder these reads without also
     * updating encrypt()'s write order above.
     */
    private class EcdheHeader(
        val header: ByteArray,
        val ephemeralBytes: ByteArray,
        val metaIv: ByteArray,
        val contentIv: ByteArray,
        val metaLen: Int
    )

    private fun readEcdheHeader(input: java.io.InputStream, prefix: ByteArray): EcdheHeader {
        val ephLenBytes = ByteArray(2)
        readFully(input, ephLenBytes)
        val ephLen = ByteBuffer.wrap(ephLenBytes).short.toInt() and 0xffff
        require(ephLen in 50..EPHEMERAL_MAX) { "invalid ephemeral key" }
        val ephemeralBytes = ByteArray(ephLen)
        readFully(input, ephemeralBytes)
        val tail = ByteArray(IV_LENGTH * 2 + 4)
        readFully(input, tail)
        val metaLen = ByteBuffer.wrap(tail, tail.size - 4, 4).int
        require(metaLen in 16..MAX_METADATA_CIPHER) { "invalid metadata" }
        val metaIv = tail.copyOfRange(0, IV_LENGTH)
        val contentIv = tail.copyOfRange(IV_LENGTH, IV_LENGTH * 2)
        val header = prefix + ephLenBytes + ephemeralBytes + tail
        return EcdheHeader(header, ephemeralBytes, metaIv, contentIv, metaLen)
    }

    private enum class KeyMode { PASSPHRASE, PUBLIC_KEY }

    private fun needPass(p: CharArray?): CharArray {
        if (p == null || p.isEmpty()) throw PassphraseRequiredException()
        return p
    }

    private fun needContact(k: PublicKey?): PublicKey =
        k ?: throw IllegalArgumentException("choose the contact this older file was encrypted with")

    /** Derives the file key for an ECDHE header (v2 passphrase mix, or v3 pure public key). */
    private fun deriveEcdheKey(context: Context, mode: KeyMode, ephemeralPublic: PublicKey, passphrase: CharArray?): ByteArray =
        if (mode == KeyMode.PUBLIC_KEY) {
            val shared = DeviceIdentity.computeSharedSecret(context, ephemeralPublic)
            val ephemeralPoint = DeviceIdentity.publicPoint(ephemeralPublic)
            val myPoint = DeviceIdentity.myPublicPoint(context)
            try {
                ContactCrypto.deriveFileKeyV3(shared, ephemeralPoint, myPoint)
            } finally {
                Arrays.fill(ephemeralPoint, 0); Arrays.fill(myPoint, 0)
            }
        } else {
            ContactCrypto.deriveAes256KeyFromEphemeralPublic(context, ephemeralPublic, passphrase!!, ContactCrypto.Purpose.FILE)
        }

    private fun verifyEcdhe(context: Context, input: java.io.InputStream, prefix: ByteArray, mode: KeyMode, passphrase: CharArray?): String {
        val parsed = readEcdheHeader(input, prefix)
        val metaCipher = ByteArray(parsed.metaLen)
        var key = ByteArray(0)
        try {
            readFully(input, metaCipher)
            val ephemeralPublic = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(parsed.ephemeralBytes))
            key = deriveEcdheKey(context, mode, ephemeralPublic, passphrase)
            val filenameBytes = aesGcmDecrypt(key, parsed.metaIv, parsed.header.copyOf(parsed.header.size - 4), metaCipher)
            val filename = try { String(filenameBytes, Charsets.UTF_8) } finally { Arrays.fill(filenameBytes, 0) }
            verifyContent(input, key, parsed.contentIv, parsed.header, metaCipher)
            return filename
        } finally {
            Arrays.fill(key, 0); Arrays.fill(parsed.ephemeralBytes, 0)
            Arrays.fill(parsed.metaIv, 0); Arrays.fill(parsed.contentIv, 0)
            Arrays.fill(metaCipher, 0); Arrays.fill(parsed.header, 0)
        }
    }

    private fun decryptEcdhe(context: Context, input: java.io.InputStream, prefix: ByteArray, mode: KeyMode, passphrase: CharArray?, temp: File): Pair<File, String> {
        val parsed = readEcdheHeader(input, prefix)
        val metaCipher = ByteArray(parsed.metaLen)
        var key = ByteArray(0)
        try {
            readFully(input, metaCipher)
            val ephemeralPublic = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(parsed.ephemeralBytes))
            key = deriveEcdheKey(context, mode, ephemeralPublic, passphrase)
            val filenameBytes = aesGcmDecrypt(key, parsed.metaIv, parsed.header.copyOf(parsed.header.size - 4), metaCipher)
            val filename = try { String(filenameBytes, Charsets.UTF_8) } finally { Arrays.fill(filenameBytes, 0) }
            decryptContent(input, temp, key, parsed.contentIv, parsed.header, metaCipher)
            return temp to filename
        } finally {
            Arrays.fill(key, 0); Arrays.fill(parsed.ephemeralBytes, 0)
            Arrays.fill(parsed.metaIv, 0); Arrays.fill(parsed.contentIv, 0)
            Arrays.fill(metaCipher, 0); Arrays.fill(parsed.header, 0)
        }
    }

    private fun verifyLegacy(context: Context, input: java.io.InputStream, prefix: ByteArray, contactPublicKey: PublicKey, passphrase: CharArray): String {
        val rest = ByteArray(LEGACY_HEADER_LENGTH - 5)
        val header = prefix + rest
        val metaIv = ByteArray(IV_LENGTH)
        val contentIv = ByteArray(IV_LENGTH)
        var key = ByteArray(0)
        try {
            readFully(input, rest)
            System.arraycopy(header, 5, metaIv, 0, IV_LENGTH)
            System.arraycopy(header, 5 + IV_LENGTH, contentIv, 0, IV_LENGTH)
            val metaLen = ByteBuffer.wrap(header, LEGACY_HEADER_LENGTH - 4, 4).int
            require(metaLen in 16..MAX_METADATA_CIPHER) { "invalid metadata" }
            val metaCipher = ByteArray(metaLen)
            try {
                readFully(input, metaCipher)
                key = ContactCrypto.deriveAes256Key(context, contactPublicKey, passphrase, ContactCrypto.Purpose.FILE)
                val filenameBytes = aesGcmDecrypt(key, metaIv, header.copyOf(LEGACY_HEADER_LENGTH - 4), metaCipher)
                val filename = try { String(filenameBytes, Charsets.UTF_8) } finally { Arrays.fill(filenameBytes, 0) }
                verifyContent(input, key, contentIv, header, metaCipher)
                return filename
            } finally { Arrays.fill(metaCipher, 0) }
        } finally {
            Arrays.fill(key, 0); Arrays.fill(rest, 0); Arrays.fill(header, 0); Arrays.fill(metaIv, 0); Arrays.fill(contentIv, 0)
        }
    }

    private fun verifyContent(input: java.io.InputStream, key: ByteArray, contentIv: ByteArray, header: ByteArray, metaCipher: ByteArray) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, contentIv))
        cipher.updateAAD(header + metaCipher)
        val buffer = ByteArray(BUFFER_SIZE)
        var total = 0L
        try {
            while (true) {
                val n = input.read(buffer)
                if (n < 0) break
                total += n.toLong()
                require(total <= MAX_FILE_BYTES + 16) { "encrypted file too large" }
                val plain = cipher.update(buffer, 0, n)
                if (plain != null) Arrays.fill(plain, 0)
            }
            val finalPlain = cipher.doFinal()
            Arrays.fill(finalPlain, 0)
        } finally { Arrays.fill(buffer, 0) }
    }

    private fun decryptContent(input: java.io.InputStream, temp: File, key: ByteArray, contentIv: ByteArray, header: ByteArray, metaCipher: ByteArray) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, contentIv))
        cipher.updateAAD(header + metaCipher)
        FileOutputStream(temp).use { rawOut ->
            BufferedOutputStream(rawOut, BUFFER_SIZE).use { out ->
                val buffer = ByteArray(BUFFER_SIZE)
                var total = 0L
                try {
                    while (true) {
                        val n = input.read(buffer)
                        if (n < 0) break
                        total += n.toLong()
                        require(total <= MAX_FILE_BYTES + 16) { "encrypted file too large" }
                        val plain = cipher.update(buffer, 0, n)
                        if (plain != null && plain.isNotEmpty()) {
                            out.write(plain)
                            Arrays.fill(plain, 0)
                        }
                    }
                    val finalPlain = cipher.doFinal()
                    if (finalPlain.isNotEmpty()) {
                        out.write(finalPlain)
                        Arrays.fill(finalPlain, 0)
                    }
                    out.flush()
                } finally { Arrays.fill(buffer, 0) }
            }
        }
    }

    private fun decryptLegacy(context: Context, input: java.io.InputStream, prefix: ByteArray, contactPublicKey: PublicKey, passphrase: CharArray, temp: File): Pair<File, String> {
        val rest = ByteArray(LEGACY_HEADER_LENGTH - 5)
        val header = prefix + rest
        val metaIv = ByteArray(IV_LENGTH)
        val contentIv = ByteArray(IV_LENGTH)
        val metaCipher: ByteArray
        var key = ByteArray(0)
        try {
            readFully(input, rest)
            System.arraycopy(header, 5, metaIv, 0, IV_LENGTH)
            System.arraycopy(header, 5 + IV_LENGTH, contentIv, 0, IV_LENGTH)
            val metaLen = ByteBuffer.wrap(header, LEGACY_HEADER_LENGTH - 4, 4).int
            require(metaLen in 16..MAX_METADATA_CIPHER) { "invalid metadata" }
            metaCipher = ByteArray(metaLen)
            readFully(input, metaCipher)
            key = ContactCrypto.deriveAes256Key(context, contactPublicKey, passphrase, ContactCrypto.Purpose.FILE)
            val filenameBytes = aesGcmDecrypt(key, metaIv, header.copyOf(LEGACY_HEADER_LENGTH - 4), metaCipher)
            val filename = try { String(filenameBytes, Charsets.UTF_8) } finally { Arrays.fill(filenameBytes, 0) }
            decryptContent(input, temp, key, contentIv, header, metaCipher)
            Arrays.fill(metaCipher, 0)
            return temp to filename
        } finally {
            Arrays.fill(key, 0); Arrays.fill(rest, 0); Arrays.fill(header, 0); Arrays.fill(metaIv, 0); Arrays.fill(contentIv, 0)
        }
    }

    private fun readFully(input: java.io.InputStream, buffer: ByteArray){var offset=0;while(offset<buffer.size){val n=input.read(buffer,offset,buffer.size-offset);require(n>=0){"truncated encrypted file"};offset+=n}}
}
