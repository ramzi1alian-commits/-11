# V52 changes
## Encrypted file -> chat (WhatsApp)
- Cause: 📎/🔐 tried InputConnection.commitContent(application/octet-stream). WhatsApp's editor only accepts
  images/GIFs/stickers through that API, so the call always failed (and the URI grant was given to our own
  package, not to the chat app).
- Fix: the editor's advertised MIME types are checked first; if arbitrary files are not accepted the keyboard
  goes straight to an explicit share to the chat app it is typing in (one tap to choose the chat, then Send).
  Falls back to the system chooser. Package visibility (<queries>) added for WhatsApp/Telegram/Signal/Viber/Messenger.
- Limit: Android gives keyboards no way to put a file into a specific WhatsApp chat; choosing the chat is a manual tap.
Not compiled here: build in CI and test on a device.
