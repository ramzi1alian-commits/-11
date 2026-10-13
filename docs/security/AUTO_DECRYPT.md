# Auto-decrypt overlay (V42)

`AutoDecryptService` is an Android AccessibilityService. It shows decrypted text over
encrypted messages in chat apps with no tap.

## Enable
Settings -> Accessibility -> Installed apps -> SecureKeyboard -> "فك التشفير التلقائي".
On Android 13+ a sideloaded (non-Play) app first needs: App info -> (⋮) -> "Allow restricted settings".
It works only while the keyboard's passphrase session is active.

## What it does / does not do
* Acts only when the foreground app is in `AutoDecryptService.SUPPORTED_PACKAGES`
  (WhatsApp, Telegram, Signal, Messenger, Instagram, Viber, Discord, common SMS apps). Edit that set to add apps.
* The system delivers accessibility events from all apps to the service; the allowlist is enforced
  in code, not by the OS. Reviewers should read `refresh()`.
* Only whole text nodes that are a single long Base64 token are touched; password fields are skipped.
* The app still declares no INTERNET permission, so nothing it reads can leave the device.
* The overlay is non-touchable; taps go to the chat app. It is not FLAG_SECURE, so screenshots include it.

## Storage
`DecryptedMessageCache` keeps plaintexts (received and SENT messages) encrypted with the
Keystore-backed LocalStorageCrypto: max 500 messages / 2 MB / 30 days. `DecryptedMessageCache.ENABLED = false`
disables it (then v4 messages open once only and own messages show as ciphertext).
Clear with `DecryptedMessageCache.clear(context)` (no UI button yet).

## Known limits
* Long messages that the chat app truncates ("Read more") are not valid tokens and stay as ciphertext.
* Sent-message plaintext is stored on the device by design (you cannot decrypt your own v4 messages).
* Failed attempts are retried at most every 5 minutes per message; each v4 attempt costs one Argon2id per paired contact.
* Overlay alignment depends on each chat app's layout; it may lag briefly while scrolling.
* Not compiled or run by the author; needs a real device test.
