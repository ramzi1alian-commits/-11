# V63 changes
## Permanent clipboard history (normal keyboard only, OPT-IN)
- Settings -> "سجل الحافظة الدائم": switch (OFF by default) + clear button (two taps).
- While ON, text copied while the keyboard is running is saved: up to 5000 items / ~4M characters, newest first,
  duplicates move to the front, pinned items are never evicted.
- Open it with the new 📋 key on the numbers/symbols page: tap a row = insert, 📌 = pin, 🗑 = delete,
  🔎 = filter by the last words typed in the field, "الكل" = clear the filter.
- Stored only on the device, encrypted with the Keystore-backed LocalStorageCrypto (same as learned words).
- Never saved: clips flagged sensitive by the source app (password managers), anything copied from this app's
  own encryption screens, text copied while in secure-compose / crypto pages, anything that looks like this app's
  encrypted text (SKF..., SKFT1:), a long token/key-like string, a card-number-like string, blank text,
  items over 20,000 characters.
Not compiled here: build in CI and test on a device (enable the switch, copy a few texts, open 📋).
