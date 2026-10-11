# V41 - crypto hardening pass

Scope: message encryption (CryptoEngineV2 / ContactCrypto / DeviceIdentity), a new
ReplayGuard, and the UI hooks that surface the new errors. **File encryption
(SecureFileCrypto) and passphrase-only messages (CryptoEngine) are unchanged.**

IMPORTANT: this pass was written without an Android SDK or Kotlin compiler in the
authoring environment. Nothing here has been compiled or run on a device. Build it
in CI, run `:app:testDebugUnitTest` and the instrumented tests
(`CryptoEngineV4Test`, `CryptoEngineAdversarialTest`) before trusting it.

## What changed

| # | Finding | Change |
|---|---------|--------|
| 2 | No sender authentication | v4 mixes ECDH(sender identity, recipient identity) into the key. A message opens only for the selected contact's identity key. |
| 3 | Passphrase not stretched | Passphrase goes through Argon2id (BouncyCastle, already a dependency; params carried in the header and range-checked before allocation) and is mixed in as a separate length-prefixed part. |
| 4 | Silent identity regeneration | An unreadable identity file is preserved (`.unreadable.<ts>`), a new identity is created and the pairing screen shows a one-time notice. |
| 5 | Unvalidated public keys | Every contact/own/ephemeral key must be a finite secp256r1 point on the curve; degenerate ECDH output rejected. |
| 6 | KDF without context | HKDF info binds label, sender point, recipient point and SHA-256(header). |
| 7 | No replay protection | `ReplayGuard` remembers IDs of successfully opened v4 messages (bounded, encrypted at rest). |
| 8 | Legacy v2 still accepted | v2 refused unless `CryptoEngineV2.ALLOW_LEGACY_V2_DECRYPT = true`. v3 stays readable (`ALLOW_LEGACY_V3_DECRYPT`). |
| 9 | Minor | Duplicate KDF code removed (outputs for v1/file keys are byte-identical); HKDF intermediates wiped. |
| - | Bug found while editing | In `SecureInputMethodService` the "decrypt from clipboard" flow let an exception from the passphrase-only fallback escape the executor task, leaving `cryptoBusy` stuck. Now caught. |
| - | Test bug | `contact_message_tampered_ephemeral_public_key_is_rejected` read the wrong header offsets; fixed for the v4 layout. |

## Behaviour changes users will notice

* A v4 message cannot be opened twice on the same device (replay protection). Keep the
  plaintext that was shown. Set `ENFORCE_REPLAY_PROTECTION = false` to disable.
* New messages are not readable by older app builds (format version 4).
* Sender and recipient must both be on this build; contacts keep their existing pairing.

## NOT fixed (and why)

1. **Forward secrecy against recipient key theft.** Messages use an ephemeral key on the
   sender side only. If the recipient's long-term identity key leaks, stored past
   messages can be decrypted. Real forward secrecy needs recipient-published rotating
   prekeys (X3DH/Noise-style) or a ratchet; a serverless QR-pairing app has no channel
   to distribute them. Options: periodic forced re-pairing, or a pairwise symmetric
   ratchet (requires ordered delivery + state per contact).
2. **Hardware-backed identity key.** `DeviceIdentity` still stores a software EC key
   (wrapped by a Keystore AES key). The original author chose this deliberately for
   Android 12-14 OEM ECDH compatibility; I did not override that without devices to test.
3. **JVM cannot zero key objects.** `PrivateKey`/`SecretKeySpec` objects live on the heap
   until GC; only the raw byte arrays are wiped.
4. **Not reviewed:** `SecureFileCrypto`, `Prefs`, `SecureInputMethodService` (beyond the
   decrypt flows), `LocalStorageCrypto`, `SessionKeyStore`, `AndroidManifest.xml`.
   Hash-length/curve upgrades (P-384, ML-KEM, HKDF-SHA384) were not applied: P-256 is not
   broken, and PQ hybrids need a vetted library, not hand-rolled code.
