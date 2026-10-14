package com.securekeyboard.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * Known-answer tests for the PBKDF2-HMAC-SHA-256 used by the FIPS-compatible v5 format
 * (vectors: password="password", salt="salt", dkLen=32; widely published, e.g. RFC 7914 / NIST-style KATs).
 */
class Pbkdf2Test {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private val salt = "salt".toByteArray()

    @Test
    fun `c=1`() = assertEquals(
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
        hex(CryptoEngine.derivePbkdf2Sha256("password".toCharArray(), salt, 1))
    )

    @Test
    fun `c=2`() = assertEquals(
        "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
        hex(CryptoEngine.derivePbkdf2Sha256("password".toCharArray(), salt, 2))
    )

    @Test
    fun `c=4096`() = assertEquals(
        "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
        hex(CryptoEngine.derivePbkdf2Sha256("password".toCharArray(), salt, 4096))
    )

    @Test
    fun `different passphrase gives different key`() = assertFalse(
        hex(CryptoEngine.derivePbkdf2Sha256("password".toCharArray(), salt, 1000)) ==
            hex(CryptoEngine.derivePbkdf2Sha256("passwore".toCharArray(), salt, 1000))
    )
}
