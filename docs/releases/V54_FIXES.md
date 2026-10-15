# V54 changes
## File encryption failed: "Permission Denial: opening provider ...AceOpenFileProvider ... not exported"
- Cause: the file manager's read grant for the picked file is temporary and ends when the picker Activity
  finishes; the keyboard encrypted the file later and was refused.
- Fix: AttachmentPickerActivity now reads the picked file immediately (grant still alive) into a private
  working copy (files/secure_attach). 🔐 encrypts that copy and deletes it as soon as the encrypted file
  exists; removing the chip deletes it too; leftovers are purged after 1 hour. The original is never modified.
- If the file cannot be read at pick time the user gets a clear message instead of a late failure.
- Note: files are copied once, so very large files need free space equal to their size for a short time.
Not compiled here: build in CI and test on a device (pick a photo via Ace File Explorer, 🔐).
