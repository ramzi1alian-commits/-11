# V48 changes

## File encryption (📁 تشفير الملفات screen)
- New file format SKF2 v3: pure public-key encryption. A fresh ephemeral P-256 key is generated per file; key = HKDF(ECDH(ephemeral, recipient public), ephPoint||recipientPoint). No session passphrase needed. Only the chosen contact's device can open it. v1/v2 files still decrypt (they still need the passphrase).
- FileCryptoActivity rewritten: a contact must be chosen before encrypting (no silent "self" default; "self" is an explicit last entry). One file-picker only (اختيار ملف). Encrypt writes straight to the private outbox; then 📤 share / 💾 save a copy / 👁 open. The second "choose folder" file-manager step is gone.
- Decrypt needs no contact for v3 files (this device's private key is used).
- The keyboard's 📁 button no longer refuses when no session key is active; the paperclip path also uses v3 (contact still required).
- SecureFileReceiveActivity (opening .skf from WhatsApp) no longer needs a session key.

## Themes (10): نهاري، ليلي، داكن، فاتح، ذهبي، رمادي، زمردي، محيطي، ملكي، غروب
- Settings > theme screen shows a card per theme; accent can stay "حسب الثيم" or be overridden.
- Colors come from Themes.kt (keyboard) and SkTheme.* overlays with skBg/skSurface/... attributes (screens).

Not compiled here (no Android SDK in the authoring environment): build in CI / Android Studio and test on a device.

## Hardening
- Exported receive screen: only content:// URIs from other apps (no file://, nothing served by this app's own provider, no ".." paths).
- Decrypted files with executable/active types (apk, dex, jar, sh, js, html, svg, exe ...; every extension checked, e.g. photo.jpg.apk) are never opened by the app; a warning is shown. Save/share still work.
- Every screen: FLAG_SECURE and filterTouchesWhenObscured (tapjacking) applied centrally in SecurityApplication.
- Auto-decrypt accessibility service is restricted to the supported chat apps by the OS itself (android:packageNames), not only in code.
- Unchanged and still in place: no INTERNET permission, backups disabled, no exported crypto screens, signature/debugger/root checks, R8 obfuscation in release.
