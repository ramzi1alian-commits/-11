# Security roadmap (what is code, what is external)

## Code work (can be written quickly, must be tested before use)
- Suite 2: P-384 + SHA-384 (ECDH P-384, HKDF-SHA-384, AES-256-GCM) with crypto agility.
- Sender authentication: ECDSA P-384 signing key gated by biometrics, verified against the key pinned at pairing.
- Hardware-held identity key (Android Keystore, Android 12+), app lock by biometrics.
- FIPS provider path: replace non-approved parts (Argon2 is not an approved algorithm: use PBKDF2/approved KDFs in
  FIPS mode) and run the crypto through a FIPS-validated module.
Wire format changes: contact keys (QR), compact message layout, safety numbers, file headers. They break old
messages and require one re-pairing, so they should ship together in ONE format version.

## External work (cannot be shortened by writing code)
- Independent code audit + penetration test (scheduling and report cycles).
- FIPS 140-3 certificate for a module: a certificate belongs to a specific module and version; using an already
  validated module is far faster than validating a new one. Check the NIST CMVP Active list for the exact version.
- Common Criteria / national evaluation, procurement approval, and the buyer's own security review.
