# Encrypted files and images in the chat flow (V43)

Send (unchanged): keyboard attach button -> pick any file/image -> encrypted into a `.skf`
container for the selected contact -> Android share sheet -> choose the chat app. The chat app only
ever sees an opaque `.skf` file.

Receive (new): tapping the `.skf` in the chat -> "open with" SecureKeyboard.
* With an active session passphrase and at least one paired contact, decryption starts automatically.
  Every paired contact is tried unless one is picked in the spinner.
* Images (jpg, png, webp, gif, bmp) are previewed inside the app (screen is FLAG_SECURE).
* "Open" hands the decrypted file to a viewer app through FileProvider (`cache-path` `secure_open`).
  The viewer app then has the plaintext; that is the user's explicit choice.
* "Save a copy" uses the existing folder picker.
* Decrypted files are removed when the screen closes, or after 10 minutes if a viewer app was opened.

Known limits
* The file container still has no sender authentication (same as v3 messages): anyone who knows your
  public key and the passphrase could create a file that opens for you. Upgrading `SecureFileCrypto`
  to the v4 key schedule is the next step.
* Large files are decrypted in the app cache first; make sure there is free space.
* WhatsApp may rename or re-type the file; the receiver filter matches `.skf` and `application/octet-stream`.
* Not compiled or run by the author.
