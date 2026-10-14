package com.securekeyboard.app

import android.content.Context
import android.util.Base64
import java.io.File
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Arrays
import javax.crypto.KeyAgreement

/**
 * V14 cross-version device identity.
 *
 * The ECDH identity is deliberately a software EC key pair on API 24-34,
 * encrypted at rest with LocalStorageCrypto. This sacrifices the stronger
 * non-exportable Keystore-private-key property on API 31+, but avoids an
 * Android 12-14 OEM/provider incompatibility where a Keystore EC private key
 * cannot be consumed reliably by the same ECDH path used with imported
 * contact public keys.
 *
 * LocalStorageCrypto still uses an Android Keystore AES key to protect the
 * identity file at rest. A V14 installation therefore has one deterministic
 * ECDH implementation on Android 8 through 14 instead of two incompatible
 * implementations.
 *
 * IMPORTANT: V14 uses a new identity file. Existing paired contacts must be
 * re-paired once after upgrading from V13 because a new device public key is
 * required for a symmetric ECDH relationship.
 *
 * V41 changes:
 *  - An identity file that exists but cannot be read is NEVER silently
 *    overwritten: it is renamed (kept for recovery), a new identity is
 *    created, and a one-time notice is raised so the UI can tell the user
 *    that contacts must be re-paired.
 *  - Every public key (contact or own) is validated as a real, on-curve
 *    secp256r1 point before use.
 *  - Canonical 65-byte point encoding for transcript binding.
 */
object DeviceIdentity {
    private const val CURVE = "secp256r1"
    private const val IDENTITY_FILE = "device_identity_v14.enc"
    private const val REGENERATED_FLAG_FILE = "identity_regenerated.flag"
    private const val MAX_KEY_BYTES = 4096
    private const val FORMAT_VERSION = 1

    private val p256Params: ECParameterSpec by lazy {
        val ap = AlgorithmParameters.getInstance("EC")
        ap.init(ECGenParameterSpec(CURVE))
        ap.getParameterSpec(ECParameterSpec::class.java)
    }

    init {
        // Retained as a compatibility hook; standard EC/ECDH primitives
        // intentionally use Android's platform provider selection.
        CryptoProvider.ensureRegistered()
    }

    /** Returns the stored key pair, or null if the file is missing/unreadable/malformed. */
    private fun loadKeyPair(file: File): KeyPair? {
        return try {
            val encrypted = file.readBytes()
            val plain = LocalStorageCrypto.decrypt(encrypted) ?: return null
            try {
                if (plain.size < 16) return null
                val buf = ByteBuffer.wrap(plain)
                if (buf.int != FORMAT_VERSION) return null
                val publicLen = buf.int
                if (publicLen !in 1..MAX_KEY_BYTES || buf.remaining() < publicLen + 4) return null
                val publicBytes = ByteArray(publicLen)
                buf.get(publicBytes)
                val privateLen = buf.int
                if (privateLen !in 1..MAX_KEY_BYTES || buf.remaining() < privateLen) return null
                val privateBytes = ByteArray(privateLen)
                buf.get(privateBytes)
                try {
                    val pub = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(publicBytes))
                    val priv = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(privateBytes))
                    requireValidP256PublicKey(pub)
                    KeyPair(pub, priv)
                } finally {
                    Arrays.fill(publicBytes, 0)
                    Arrays.fill(privateBytes, 0)
                }
            } finally {
                Arrays.fill(plain, 0)
            }
        } catch (_: Exception) {
            null
        }
    }

    @Synchronized
    private fun getOrCreateKeyPair(context: Context): KeyPair {
        val file = File(context.filesDir, IDENTITY_FILE)
        var regenerated = false
        if (file.exists()) {
            loadKeyPair(file)?.let { return it }
            // The file is there but unusable (Keystore key invalidated, corruption,
            // tampering). Do NOT destroy it: keep it for recovery, then start a new
            // identity and make sure the user is told.
            val kept = File(context.filesDir, "$IDENTITY_FILE.unreadable.${System.currentTimeMillis()}")
            if (!file.renameTo(kept)) {
                throw IllegalStateException("identity file is unreadable and could not be preserved")
            }
            regenerated = true
        }

        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec(CURVE))
        val pair = generator.generateKeyPair()
        val pub = pair.public.encoded
        val priv = pair.private.encoded
        val plain = ByteBuffer.allocate(4 + 4 + pub.size + 4 + priv.size)
            .putInt(FORMAT_VERSION).putInt(pub.size).put(pub)
            .putInt(priv.size).put(priv)
            .array()
        try {
            val encrypted = LocalStorageCrypto.encrypt(plain)
            try {
                val tmp = File(context.filesDir, "$IDENTITY_FILE.tmp")
                tmp.writeBytes(encrypted)
                if (!tmp.renameTo(file)) {
                    tmp.delete()
                    throw IllegalStateException("atomic identity commit failed")
                }
            } finally {
                SecureMemory.wipe(encrypted)
            }
        } finally {
            SecureMemory.wipe(plain)
            SecureMemory.wipe(pub)
            SecureMemory.wipe(priv)
        }
        if (regenerated) {
            try { File(context.filesDir, REGENERATED_FLAG_FILE).writeText("1") } catch (_: Exception) { }
        }
        return pair
    }

    /**
     * True exactly once after the device identity had to be re-created because the
     * previous one was unreadable. The UI should tell the user to re-pair contacts.
     */
    @Synchronized
    fun consumeRegeneratedNotice(context: Context): Boolean {
        val flag = File(context.filesDir, REGENERATED_FLAG_FILE)
        if (!flag.exists()) return false
        flag.delete()
        return true
    }

    fun myPublicKeyBase64(context: Context): String =
        Base64.encodeToString(getOrCreateKeyPair(context).public.encoded, Base64.NO_WRAP)

    /** Canonical 65-byte uncompressed encoding (0x04 || X || Y) of this device's identity key. */
    fun myPublicPoint(context: Context): ByteArray = publicPoint(getOrCreateKeyPair(context).public)

    fun parseContactPublicKey(base64: String): PublicKey {
        val bytes = Base64.decode(base64, Base64.NO_WRAP)
        require(bytes.size in 50..MAX_KEY_BYTES) { "invalid public key size" }
        return try {
            val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(bytes))
            requireValidP256PublicKey(key)
            key
        } finally {
            Arrays.fill(bytes, 0)
        }
    }

    /**
     * Rejects anything that is not a finite secp256r1 point satisfying the curve
     * equation. (Cofactor is 1, so on-curve is sufficient to rule out small-subgroup
     * and invalid-curve inputs.)
     */
    fun requireValidP256PublicKey(key: PublicKey): ECPublicKey {
        require(key is ECPublicKey) { "not an EC public key" }
        val params = key.params
        val ref = p256Params
        require(
            params.curve == ref.curve && params.generator == ref.generator &&
                params.order == ref.order && params.cofactor == ref.cofactor
        ) { "unsupported curve" }
        val w = key.w
        require(w != ECPoint.POINT_INFINITY) { "invalid public point" }
        val p = (params.curve.field as ECFieldFp).p
        val x = w.affineX
        val y = w.affineY
        require(x.signum() >= 0 && x < p && y.signum() >= 0 && y < p) { "invalid public point" }
        val lhs = y.multiply(y).mod(p)
        val rhs = x.multiply(x).multiply(x)
            .add(params.curve.a.multiply(x))
            .add(params.curve.b)
            .mod(p)
        require(lhs == rhs) { "public point is not on the curve" }
        return key
    }

    /** Canonical 65-byte uncompressed point (0x04 || X || Y) for transcript binding. */
    fun publicPoint(key: PublicKey): ByteArray {
        val ec = requireValidP256PublicKey(key)
        val out = ByteArray(65)
        out[0] = 4
        System.arraycopy(fixed32(ec.w.affineX), 0, out, 1, 32)
        System.arraycopy(fixed32(ec.w.affineY), 0, out, 33, 32)
        return out
    }

    /** 33-byte SEC1 compressed form (02/03 || X) of a canonical 65-byte point. */
    fun compressPoint(uncompressed: ByteArray): ByteArray {
        require(uncompressed.size == 65 && uncompressed[0].toInt() == 4) { "invalid point" }
        val out = ByteArray(33)
        out[0] = if ((uncompressed[64].toInt() and 1) == 0) 2 else 3
        System.arraycopy(uncompressed, 1, out, 1, 32)
        return out
    }

    /**
     * Rebuilds a P-256 public key from its 33-byte compressed form and validates it
     * (y^2 must equal x^3 + ax + b; the result also passes [requireValidP256PublicKey]).
     */
    fun publicKeyFromCompressed(compressed: ByteArray): PublicKey {
        require(compressed.size == 33 && (compressed[0].toInt() == 2 || compressed[0].toInt() == 3)) {
            "invalid compressed point"
        }
        val params = p256Params
        val p = (params.curve.field as ECFieldFp).p
        val x = BigInteger(1, compressed.copyOfRange(1, 33))
        require(x < p) { "invalid public point" }
        val rhs = x.multiply(x).multiply(x)
            .add(params.curve.a.multiply(x))
            .add(params.curve.b)
            .mod(p)
        // p = 3 (mod 4) for P-256, so a square root is rhs^((p+1)/4).
        var y = rhs.modPow(p.add(BigInteger.ONE).shiftRight(2), p)
        require(y.multiply(y).mod(p) == rhs) { "point is not on the curve" }
        if (y.testBit(0) != (compressed[0].toInt() == 3)) y = p.subtract(y)
        val key = KeyFactory.getInstance("EC").generatePublic(
            java.security.spec.ECPublicKeySpec(ECPoint(x, y), params)
        )
        requireValidP256PublicKey(key)
        return key
    }

    private fun fixed32(v: BigInteger): ByteArray {
        val raw = v.toByteArray()
        var start = 0
        while (start < raw.size - 1 && raw[start].toInt() == 0) start++
        val len = raw.size - start
        require(len <= 32) { "coordinate too large" }
        val out = ByteArray(32)
        System.arraycopy(raw, start, out, 32 - len, len)
        Arrays.fill(raw, 0)
        return out
    }

    fun generateEphemeralKeyPair(): java.security.KeyPair {
        val generator = java.security.KeyPairGenerator.getInstance("EC")
        generator.initialize(java.security.spec.ECGenParameterSpec("secp256r1"))
        return generator.generateKeyPair()
    }

    fun computeSharedSecretWithPrivateKey(privateKey: java.security.PrivateKey, peerPublicKey: PublicKey): ByteArray {
        requireValidP256PublicKey(peerPublicKey)
        val agreement = try {
            KeyAgreement.getInstance("ECDH")
        } catch (e: Exception) {
            throw IllegalStateException("ECDH is not supported on this Android device", e)
        }
        try {
            agreement.init(privateKey)
            agreement.doPhase(peerPublicKey, true)
            return nonDegenerate(agreement.generateSecret())
        } catch (e: Exception) {
            throw IllegalStateException("ECDH key agreement failed", e)
        }
    }

    fun computeSharedSecret(context: Context, contactPublicKey: PublicKey): ByteArray {
        requireValidP256PublicKey(contactPublicKey)
        val pair = getOrCreateKeyPair(context)
        val agreement = try {
            KeyAgreement.getInstance("ECDH")
        } catch (e: Exception) {
            throw IllegalStateException("ECDH is not supported on this Android device", e)
        }
        try {
            agreement.init(pair.private)
            agreement.doPhase(contactPublicKey, true)
            return nonDegenerate(agreement.generateSecret())
        } catch (e: Exception) {
            throw IllegalStateException("ECDH key agreement failed", e)
        }
    }

    private fun nonDegenerate(secret: ByteArray): ByteArray {
        var acc = 0
        for (b in secret) acc = acc or b.toInt()
        if (secret.isEmpty() || acc == 0) {
            Arrays.fill(secret, 0)
            throw IllegalStateException("degenerate ECDH result")
        }
        return secret
    }

    fun isSupported(): Boolean = true
    fun isHardwareBackedPath(): Boolean = false
}
