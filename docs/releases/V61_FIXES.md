# V61 changes
## "فشل فك التشفير — لم يُشفَّر لمفتاحك العام، أو مفتاح الجلسة ... غير نشط" when opening a .skf from WhatsApp
- Cause: SessionKeyStore.get() returns null until SessionKeyStore.initialize() has run in the current process.
  The receive screen (SecureFileReceiveActivity) and the Application never called it - only the keyboard view and a
  few other screens did. Opening a session-key (v4) file straight from the chat in a process where the keyboard view
  had not been created yet therefore looked like "no session key", and the generic message hid the real reason.
- Fix: initialize in SecurityApplication.onCreate (every process start) and in SecureFileReceiveActivity.onCreate.
- The failure text now says plainly when the file needs a session key and none is active; otherwise it says the
  current session key may differ from the one used to encrypt.
Not compiled here: build in CI and test on a device.
