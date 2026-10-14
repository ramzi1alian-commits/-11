# V44 fixes

- Auto-decrypt (AutoDecryptService.decryptToken): passphrase-only messages in the current compact v7 format were never tried (the passphrase fallback was gated to versions 2..3), so new messages always showed "cannot decrypt". The fallback now runs for every version, like the keyboard's own decrypt.
- Secure-compose page: long-press on ا now offers أ إ آ and long-press on ي offers ى ئ (the page built plain keys before). The picked letter goes into the compose buffer (new makeKey parameter onVariantChosen).
- Unit test `already-expired message...` used expiry 0, which encrypt() correctly rejects; it now uses 1 second and waits.
- CI: only the debug APK is built and uploaded (one installable file, no unsigned release).
- Not compiled or run on a device by the author of this pass; verify in CI and on a phone.

## Auto-decrypt: battery (recent messages only)
- Before: every ciphertext on screen (up to 40) was decrypted, and each wrong-key one cost a full Argon2id, retried every 5 minutes.
- Now: when a chat is opened (or the key is set) only the newest 3 ciphertexts on screen are decrypted, plus any message that then arrives below the ones already seen. Old history and messages revealed by scrolling up are not decrypted; ones already opened with this key still show via a cheap cache lookup.
- A failed message is not retried during the session (30 min). Scans slow to 300 ms when no ciphertext is on screen.
- To read an old message, copy it and use the keyboard's 🔓 (unchanged).
