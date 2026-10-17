# V68 - Suite 2 (P-384 + SHA-384), installs next to the old app
## What changed
- Curve: ECDH on P-384 (secp384r1) for the device identity, ephemeral keys, pairing keys. Points are 97 bytes
  (uncompressed, used in key derivation) / 49 bytes (compressed, sent inside v6 contact messages).
- Hash: HKDF now uses HMAC-SHA-384 (contact messages, file keys, passphrase messages); header/transcript hash and the
  pairing safety number use SHA-384. AES-256-GCM unchanged. All HKDF labels carry "S2" (domain separation).
- Old formats are refused (flags set to false): v2/v3/v4 contact messages, v2/v3 passphrase messages, SKF2 v1/v2 files.
  Because the curve changed they could not be opened anyway; the parsers are only kept compiled behind the flags.
- New applicationId com.securekeyboard.pro.s2 (name "كيبورد آمن برو S2"): installs NEXT TO the old app with its own
  storage and keys. Enable the new keyboard (and the accessibility service, if used) in Android settings; pair again.
- Identity file is device_identity_s2.enc (a P-256 file can never be misread).
- Tests updated for the new sizes (97 / 49 / message overhead 83 bytes; x=4 is a non-residue so the off-curve test is
  now strict).
## Verified here (standalone JDK 21, not the app)
- P-384 prime is 3 mod 4 (so the square-root decompression formula is valid); 300 random keys round-trip through
  compress/decompress to the same point and satisfy the curve equation; x=4 is rejected; ECDH agrees on both sides
  with a 48-byte secret; the X.509 form of a P-384 public key is 120 bytes (limit checks allow 200);
  HKDF-HMAC-SHA384 output equals an independent Python implementation.
## NOT verified
- The app was not compiled and its test suite was not run. Run the GitHub workflow (unit + instrumented tests)
  before using this build. Pay attention to CryptoEngineV4Test, CryptoEngineCompactFormatTest, ContactCrypto/pairing flows.
## Not part of this change
- Password stretching (Argon2id profiles, PBKDF2-HMAC-SHA256 600k) is unchanged and is not CNSA/FIPS-approved Argon2.
- FIPS-validated module, biometric-gated sender signatures, hardware-held identity key.
- Correction to the earlier review: contact messages (v6) ALREADY authenticate the sender implicitly (static-static
  ECDH and both identity points are bound into the key). What is missing is non-repudiable signatures and forward
  secrecy for the static keys. Files (v3) and session-key messages are anonymous-sender by design.
