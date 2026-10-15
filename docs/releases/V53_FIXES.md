# V53 changes
## NEW (optional extra): send an encrypted file as chat text
- Nothing existing was replaced: 📎/🔐 still use the V52 flow (direct insert / share to the chat app).
- When a file is attached, the chip shows a new switch "🔤 إرسال كنصّ داخل المحادثة". Off by default.
  When on, 🔐 encrypts the file exactly as before (SKF2 v3/v4) and inserts the encrypted bytes as a text
  message "SKFT1:<base64url>" into the chat. No weaker crypto: only the transport encoding differs.
- Size limit: WhatsApp ≈ 30 KB file (~40k chars); other apps ≈ 2.8 KB (~3.8k chars). Bigger files fall back
  to the normal path automatically.
- Receiving: copy the whole message, press 🔓 (panel or secure compose). The keyboard rebuilds the .skf in its
  private inbox and opens the normal secure receive screen (decrypt, preview, open, save). The inbox copy is
  deleted when the screen closes (and purged after 1 hour).
- Not done: AutoDecryptService does not overlay SKFT1 messages (very long node text); copy + 🔓 is the way.
Not compiled here: build in CI and test on a device (small file to WhatsApp, copy, 🔓).
