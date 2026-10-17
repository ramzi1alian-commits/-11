# V66 changes
## Decrypted-message cache: 30 minutes, unrecoverable
- Entries live at most 30 minutes (V65: 6 h). After that a message cannot be shown again, not even your own sent
  message (the replay guard stops re-decryption by design).
- Storage: new file decrypted_cache_v3.enc, encrypted with an Android-Keystore key created for each rewrite and
  valid only until the OLDEST entry expires (setKeyValidityForConsumptionEnd). The previous key is deleted as soon
  as the new file is in place -> older copies of the file left by flash storage cannot be decrypted (cryptographic
  erasure). The live file also dies by itself at expiry, even if the app is not running.
- The old file is overwritten with zeros before it is replaced/deleted (best effort on flash); in-memory plaintext
  is zeroed; a timer re-keys the file at the next expiry while the app is alive (newer entries survive, expired
  ones are gone).
- The old v1 cache file is shredded on first load. Public API unchanged (existing tests use it).
Not compiled here: build in CI and run DecryptedMessageCacheTest (instrumented) before use.
