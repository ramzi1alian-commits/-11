package com.securekeyboard.app

import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** SKF2 v4: public / session-passphrase file encryption (no contact pairing). */
@RunWith(AndroidJUnit4::class)
class SecureFilePassphraseTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val pass = "file-session-passphrase".toCharArray()

    private fun tempFile(bytes: ByteArray): File =
        File.createTempFile("skf_test_", ".bin", context.cacheDir).also { it.writeBytes(bytes) }

    private fun sealed(plain: ByteArray, fips: Boolean = false): File {
        val src = tempFile(plain)
        val out = File.createTempFile("skf_test_", ".skf", context.cacheDir)
        SecureFileCrypto.encryptWithPassphraseToFile(context, Uri.fromFile(src), out, pass, "photo.jpg", fips)
        src.delete()
        return out
    }

    @Test
    fun roundTrip_argon_and_fips_profiles() {
        val plain = ByteArray(200_000) { (it * 31).toByte() }
        for (fips in listOf(false, true)) {
            val enc = sealed(plain, fips)
            val (dec, name) = SecureFileCrypto.decryptToTemp(context, Uri.fromFile(enc), null, pass)
            assertEquals("photo.jpg", name)
            assertArrayEquals(plain, dec.readBytes())
            dec.delete(); enc.delete()
        }
    }

    @Test
    fun missing_passphrase_is_reported() {
        val enc = sealed(ByteArray(1024) { 7 })
        try {
            SecureFileCrypto.decryptToTemp(context, Uri.fromFile(enc), null, null)
            fail("expected PassphraseRequiredException")
        } catch (_: SecureFileCrypto.PassphraseRequiredException) {
        } finally { enc.delete() }
    }

    @Test
    fun wrong_passphrase_fails() {
        val enc = sealed(ByteArray(1024) { 9 })
        try {
            SecureFileCrypto.decryptToTemp(context, Uri.fromFile(enc), null, "another-passphrase".toCharArray())
            fail("expected authentication failure")
        } catch (_: Exception) {
        } finally { enc.delete() }
    }

    @Test
    fun tampering_any_region_fails() {
        val enc = sealed(ByteArray(4096) { 5 })
        val original = enc.readBytes()
        // profile byte, salt, metadata length, ciphertext body, final tag byte
        for (index in listOf(5, 8, 5 + 1 + 16 + 24 + 1, original.size / 2, original.size - 1)) {
            val bad = original.copyOf()
            bad[index] = (bad[index].toInt() xor 0x01).toByte()
            val f = tempFile(bad)
            try {
                SecureFileCrypto.decryptToTemp(context, Uri.fromFile(f), null, pass)
                fail("tampered byte $index was accepted")
            } catch (_: Exception) {
            } finally { f.delete() }
        }
        enc.delete()
    }

    @Test
    fun two_encryptions_of_same_file_differ() {
        val plain = ByteArray(2048) { 3 }
        val a = sealed(plain); val b = sealed(plain)
        assertTrue(!a.readBytes().contentEquals(b.readBytes()))
        a.delete(); b.delete()
    }
}
