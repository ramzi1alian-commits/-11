package com.securekeyboard.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.math.BigInteger
import java.security.KeyFactory
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Arrays

/**
 * V41 tests for the v4 message format: sender authentication, passphrase binding,
 * replay rejection and public-key validation. Instrumented (needs Keystore).
 */
@RunWith(AndroidJUnit4::class)
class CryptoEngineV4Test {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val pass = "v4-test-passphrase".toCharArray()

    private fun ownKey() = DeviceIdentity.parseContactPublicKey(DeviceIdentity.myPublicKeyBase64(context))

    private fun encrypt(text: String = "رسالة v4 🔐", expiry: Long? = null): String =
        CryptoEngineV2.encrypt(context, text.toCharArray(), pass.copyOf(), ownKey(), expiry)

    @Test
    fun roundTrip_compact_v6() {
        val encoded = encrypt("hello v4")
        assertEquals(6.toByte(), android.util.Base64.decode(encoded, android.util.Base64.NO_WRAP)[0])
        val plain = CryptoEngineV2.decrypt(context, encoded, pass.copyOf(), ownKey())
        try { assertArrayEquals("hello v4".toCharArray(), plain) } finally { Arrays.fill(plain, '\u0000') }
    }

    @Test
    fun replay_of_opened_message_is_rejected() {
        val encoded = encrypt()
        Arrays.fill(CryptoEngineV2.decrypt(context, encoded, pass.copyOf(), ownKey()), '\u0000')
        try {
            CryptoEngineV2.decrypt(context, encoded, pass.copyOf(), ownKey())
            throw AssertionError("replayed ciphertext was accepted")
        } catch (_: CryptoEngineV2.ReplayedMessageException) {
        }
    }

    @Test
    fun wrong_sender_identity_is_rejected_and_does_not_burn_the_message() {
        val encoded = encrypt()
        val impostor = DeviceIdentity.generateEphemeralKeyPair().public
        try {
            CryptoEngineV2.decrypt(context, encoded, pass.copyOf(), impostor)
            throw AssertionError("message decrypted under the wrong sender identity")
        } catch (e: CryptoEngineV2.ReplayedMessageException) {
            throw AssertionError("failed attempt must not be recorded as seen")
        } catch (_: Exception) {
        }
        val plain = CryptoEngineV2.decrypt(context, encoded, pass.copyOf(), ownKey())
        Arrays.fill(plain, '\u0000')
    }

    @Test
    fun wrong_passphrase_is_rejected_and_does_not_burn_the_message() {
        val encoded = encrypt()
        try {
            CryptoEngineV2.decrypt(context, encoded, "not-the-passphrase".toCharArray(), ownKey())
            throw AssertionError("decrypted with wrong passphrase")
        } catch (e: CryptoEngineV2.ReplayedMessageException) {
            throw AssertionError("failed attempt must not be recorded as seen")
        } catch (_: Exception) {
        }
        val plain = CryptoEngineV2.decrypt(context, encoded, pass.copyOf(), ownKey())
        Arrays.fill(plain, '\u0000')
    }

    @Test
    fun tampered_argon_parameters_and_expiry_are_rejected() {
        val encoded = encrypt()
        // v6 layout (no expiry): 1 flags, 2..17 salt, 18..50 ephemeral key, 51.. ciphertext+tag
        for (index in intArrayOf(1, 2, 17, 18, 25, 51, 55)) {
            val raw = android.util.Base64.decode(encoded, android.util.Base64.NO_WRAP)
            raw[index] = (raw[index].toInt() xor 0x01).toByte()
            val tampered = android.util.Base64.encodeToString(raw, android.util.Base64.NO_WRAP)
            try {
                CryptoEngineV2.decrypt(context, tampered, pass.copyOf(), ownKey())
                throw AssertionError("tampered header byte $index was accepted")
            } catch (_: Exception) {
            }
        }
    }

    @Test
    fun expired_message_is_rejected() {
        val encoded = encrypt(expiry = 1L)
        Thread.sleep(2200)
        try {
            CryptoEngineV2.decrypt(context, encoded, pass.copyOf(), ownKey())
            throw AssertionError("expired message was accepted")
        } catch (_: CryptoEngineV2.ExpiredMessageException) {
        }
    }

    @Test
    fun off_curve_public_key_is_rejected() {
        val params = (ownKey() as java.security.interfaces.ECPublicKey).params
        val spec = ECPublicKeySpec(ECPoint(BigInteger.ONE, BigInteger.ONE), params)
        try {
            val bad = KeyFactory.getInstance("EC").generatePublic(spec)
            DeviceIdentity.requireValidPublicKey(bad)
            throw AssertionError("off-curve point accepted")
        } catch (e: AssertionError) {
            throw e
        } catch (_: Exception) {
            // Either the provider or our validator refused it - both are correct.
        }
    }

    @Test
    fun canonical_point_is_97_bytes_and_stable() {
        val a = DeviceIdentity.myPublicPoint(context)
        val b = DeviceIdentity.publicPoint(ownKey())
        assertEquals(97, a.size)
        assertTrue(Arrays.equals(a, b))
        assertEquals(4, a[0].toInt())
    }
}
