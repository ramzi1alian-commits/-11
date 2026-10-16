# V62 changes
## Session key disappears for good after its time (default 30 min)
- Before: expiry was only checked when something read the key; the encrypted blob stayed in storage, wrapped by
  the permanent app key, until the next access.
- Now:
  1. Each session gets its OWN Android-Keystore key with setKeyValidityForConsumptionEnd(expiry). After that time
     the Keystore itself refuses to decrypt - even if the app is closed, even for the app's own code.
  2. A timer wipes the in-memory copy, deletes the blob and DELETES the Keystore key exactly at expiry (while the
     app process is alive); the same cleanup runs at the next start/read otherwise.
  3. The old V2 blob is deleted on first start.
- Not covered (outside the store): a key the user typed/saw on screen or copied to the clipboard.
Not compiled here: build in CI and test on a device (set a 1-minute custom session key, wait, confirm fail).
