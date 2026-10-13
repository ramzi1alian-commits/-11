package com.securekeyboard.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DecryptedMessageCacheTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun setUp() {
        DecryptedMessageCache.clear(context)
    }

    @Test
    fun put_then_get_roundTrips_and_ignores_surrounding_whitespace() {
        DecryptedMessageCache.put(context, "QUJD", "مرحبا 🔐".toCharArray())
        assertEquals("مرحبا 🔐", DecryptedMessageCache.get(context, "  QUJD\n"))
    }

    @Test
    fun unknown_ciphertext_returns_null() {
        assertNull(DecryptedMessageCache.get(context, "never-stored"))
    }

    @Test
    fun clear_removes_everything() {
        DecryptedMessageCache.put(context, "QUJD", "x".toCharArray())
        DecryptedMessageCache.clear(context)
        assertNull(DecryptedMessageCache.get(context, "QUJD"))
    }

    @Test
    fun keys_differ_for_different_ciphertexts() {
        assertNotEquals(DecryptedMessageCache.keyOf("a"), DecryptedMessageCache.keyOf("b"))
    }

    @Test
    fun encrypting_a_message_makes_the_sender_able_to_display_it() {
        val pass = "cache-test-passphrase".toCharArray()
        val me = DeviceIdentity.parseContactPublicKey(DeviceIdentity.myPublicKeyBase64(context))
        val encoded = CryptoEngineV2.encrypt(context, "sent text".toCharArray(), pass, me)
        assertEquals("sent text", DecryptedMessageCache.get(context, encoded))
    }
}
