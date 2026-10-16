# V55 changes
- Picker: the working-copy thread can no longer crash the process or leave the picker open
  (all errors caught, picker always finishes).
- Keyboard re-show after the picker is retried 4 times (0.25 / 0.9 / 2 / 3.5 s) instead of once.
- Known limit (unchanged): Android gives keyboards no API to put an arbitrary file into the current WhatsApp
  chat; the encrypted file goes through WhatsApp's share screen (pick the chat, then Send).
  Only small files can go into the chat itself, as text (🔤 switch).
Not compiled here: build in CI and test on a device.
