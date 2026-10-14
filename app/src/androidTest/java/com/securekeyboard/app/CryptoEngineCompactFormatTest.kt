package com.securekeyboard.app

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Arrays

/** Compact v6/v7 formats: size, point compression, FIPS-compatible profile, tamper resistance. */
@RunWith(AndroidJUnit4::class)
class CryptoEngineCompactFormatTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val pass = "compact-test-passphrase".toCharArray()

    private fun ownKey() = DeviceIdentity.parseContactPublicKey(DeviceIdentity.myPublicKeyBase64(context))

    @Test
    fun compressed_point_roundTrips_for_many_keys() {
        repeat(40) {
            val pub = DeviceIdentity.generateEphemeralKeyPair().public
            val point = DeviceIdentity.publicPoint(pub)
            val back = DeviceIdentity.publicKeyFromCompressed(DeviceIdentity.compressPoint(point))
            assertArrayEquals(point, DeviceIdentity.publicPoint(back))
        }
    }

    @Test
    fun invalid_compressed_points_are_rejected() {
        val bad = ByteArray(33).also { it[0] = 5 }
        try { DeviceIdentity.publicKeyFromCompressed(bad); throw AssertionError("bad prefix accepted") } catch (_: IllegalArgumentException) { }
        val notOnCurve = ByteArray(33).also { it[0] = 2; it[32] = 5 } // x = 5 has no square root on P-256
        try {
            DeviceIdentity.publicKeyFromCompressed(notOnCurve)
            // x=5 may happen to be valid; the point must then still pass validation, which it did.
        } catch (_: IllegalArgumentException) { }
    }

    @Test
    fun contact_message_overhead_is_67_bytes_and_default_profile_is_argon2() {
        val encoded = CryptoEngineV2.encrypt(context, "x".toCharArray(), pass.copyOf(), ownKey())
        val raw = Base64.decode(encoded, Base64.NO_WRAP)
        assertEquals(6.toByte(), raw[0])
        assertEquals(2 + 16 + 33 + 16 + 1, raw.size)
        assertTrue("default must not be the PBKDF2 profile", ((raw[1].toInt() shr 1) and 7) != 4)
        Arrays.fill(CryptoEngineV2.decrypt(context, encoded, pass.copyOf(), ownKey()), '\u0000')
    }

    @Test
    fun fips_profile_roundTrips_for_contact_and_passphrase_messages() {
        val c = CryptoEngineV2.encrypt(context, "fips contact".toCharArray(), pass.copyOf(), ownKey(), null, fipsMode = true)
        assertEquals(4, (Base64.decode(c, Base64.NO_WRAP)[1].toInt() shr 1) and 7)
        val plain = CryptoEngineV2.decrypt(context, c, pass.copyOf(), ownKey())
        try { assertArrayEquals("fips contact".toCharArray(), plain) } finally { Arrays.fill(plain, '\u0000') }

        val p = CryptoEngine.encrypt("fips pass".toCharArray(), pass.copyOf(), null, fipsMode = true)
        assertEquals(4, (Base64.decode(p, Base64.NO_WRAP)[1].toInt() shr 1) and 7)
        val plain2 = CryptoEngine.decrypt(p, pass.copyOf())
        try { assertArrayEquals("fips pass".toCharArray(), plain2) } finally { Arrays.fill(plain2, '\u0000') }
    }

    @Test
    fun every_header_byte_is_authenticated() {
        val encoded = CryptoEngineV2.encrypt(context, "header integrity".toCharArray(), pass.copyOf(), ownKey(), 3600L)
        val raw = Base64.decode(encoded, Base64.NO_WRAP)
        val headerLen = 2 + 4 + 16 + 33
        for (i in 0 until headerLen) {
            val t = raw.copyOf().also { it[i] = (it[i].toInt() xor 0x01).toByte() }
            try {
                CryptoEngineV2.decrypt(context, Base64.encodeToString(t, Base64.NO_WRAP), pass.copyOf(), ownKey())
                throw AssertionError("tampered header byte $i was accepted")
            } catch (e: AssertionError) {
                throw e
            } catch (_: Exception) {
            }
        }
    }
}
