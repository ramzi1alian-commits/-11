# V58 changes (includes V57: English suggestions)
## Instant encrypt + share from the file picker
- Problem (screen recordings): after choosing a file the keyboard never came back, so 🔐 could not be pressed.
- Fix: AttachmentPickerActivity now encrypts the picked file itself while it is still in front (same SKF2 v3
  contact / v4 session-key code as the keyboard), then opens the chat app's share screen (explicit share to the
  app the keyboard was typing in). Pick the chat, press Send. No keyboard needed.
- Falls back to the old flow (file chip on the keyboard) if there is no session key / contact key or anything
  fails, with a message saying why. "Send as text" (🔤) still uses the old flow.
Not compiled here: build in CI and test on a device.
