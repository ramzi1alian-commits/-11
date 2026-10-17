# V65 changes (hardening from the security review)
- Decrypted-message cache (auto-decrypt): kept 6 hours instead of 30 days, and wiped when the session key
  expires / is cleared (not when a new key replaces the old one, so re-entering the same key still works).
- Incognito mode (Settings): while on, no new words, sentences or clipboard history are saved. Existing data stays
  (clear buttons). Per-app exclusion list is NOT included yet.
- The plaintext working copy of a picked file is overwritten with zeros before deletion (best effort on flash).
- Housekeeping at app start: encrypted files in secure_outbox deleted after 24 h; working copies / inbox files after 1 h.
- Argon2: a message asking for more memory than 90% of the app heap is refused with a normal failure instead of
  an OutOfMemoryError; any OOM during key derivation is turned into a normal failure.
Not compiled here: build in CI and run the existing unit/instrumented tests before use.
