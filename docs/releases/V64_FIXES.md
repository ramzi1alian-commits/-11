# V64 changes (secure-compose page)
- Pasted/long text was invisible: the preview TextView had maxLines=3 inside a small scroll box that stayed at
  the top. Cap removed; the box now auto-scrolls to the end after every change (type, paste, delete).
- A visible caret ("|", accent colour) now marks the end of the text, i.e. where typing/deleting happens.
- Hold-to-delete accelerates (1, then 2, then 4 characters per tick). The hold-repeat itself already existed
  and was not changed; if holding ⌫ still removes only one character on a device, please report it.
Not compiled here: build in CI and test on a device (paste a long text, hold ⌫).
