package com.securekeyboard.app

/**
 * Suite 2 (V68): the single place that names the public-key curve and hash.
 *
 *  - ECDH on NIST P-384 (secp384r1), HKDF with HMAC-SHA-384, AES-256-GCM for content.
 *  - Matches the algorithm choices of the NSA CNSA 1.0 suite (P-384, SHA-384, AES-256). It is NOT a
 *    certification: the implementation is not FIPS 140-validated and has had no independent audit.
 *  - Password-stretching (Argon2id / PBKDF2-HMAC-SHA-256 profile) is unchanged and is separate from this suite.
 */
internal object Suite {
    const val CURVE = "secp384r1"
    const val COORD_LENGTH = 48
    const val POINT_LENGTH = 1 + 2 * COORD_LENGTH        // 0x04 || X || Y = 97
    const val COMPRESSED_POINT_LENGTH = 1 + COORD_LENGTH // 0x02/0x03 || X = 49
    const val HASH = "SHA-384"
    const val HMAC = "HmacSHA384"
    const val HASH_LENGTH = 48
}
