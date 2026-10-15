# V51 changes

## 📎 Paperclip works like typing
- 📎 opens the file manager once, remembers the chosen file and returns to the secure-compose
  keyboard. The file appears as a chip inside the secure box (above the text); tap the chip to remove it.
- 🔐 encrypts and injects, using the mode selected in the keyboard:
  - a contact selected  -> public-key encryption for that contact (SKF2 v3)
  - no contact ("public" mode) -> session-key encryption (SKF2 v4), no pairing needed
- If the chat app refuses direct insertion, the encrypted copy is handed to the system share sheet.
- The original file is only read, never modified. Text stays in the box and is sent by the next 🔐.

## Public (session-key) mode for files — SKF2 v4
- For when you cannot meet your contact to pair: both sides just need the same session key
  (agreed out of band), exactly like public-mode text messages.
- KDF = the same fixed profile table as compact text messages (Argon2id 96/64/48/32 MB, or
  PBKDF2-HMAC-SHA-256 in FIPS mode); AES-256-GCM, streaming, filename encrypted, header authenticated.
- Opening: SecureFileReceiveActivity / the 📁 screen use the active session key automatically.
- The 📁 screen has a new entry "🌐 عام — بمفتاح الجلسة" next to the contacts.

## Theme switch light -> dark (labels disappearing on the same screen)
- Cause: the palette overlay was applied once in onCreate while AppCompat changed the night-mode
  configuration during creation, so views resolved colors against two different themes.
- Fix: all screens now extend `SkActivity`, which re-applies the palette on every (re)built theme;
  night mode is also synced early (Application start and at the moment a theme is picked).

Not compiled here (no Android SDK in the authoring environment): build in CI / Android Studio,
run `SecureFilePassphraseTest` and test on a device.

## Follow-up
- Crypto panel "📁 تشفير الملفات" now uses the same flow as 📎: file manager -> secure-compose box -> 🔐.
  The full file screen (decrypt / save a copy) stays available as "🗂 شاشة الملفات".
- Settings: the auto-decrypt instructions/status text is now BELOW its button.
