# V57 changes
- English suggestions: new EnglishDictionary (assets/en_words.tsv) used whenever the word being typed
  starts with a Latin letter (Arabic words still use ar_words.tsv). Capitalisation is matched (Hel -> Help).
- The bundled en_words.tsv is a STARTER list: ~780 very common words ranked first, then ~60k hunspell words
  ranked only by length (no frequency data was available offline). Replace it with a real frequency list:
  python3 tools/make_en_words.py my_list.txt   (word + count per line, or plain list most-common-first).
- Not included: English next-word prediction (needs a bigram list) and English autocorrect.
Not compiled here: build in CI and test on a device.
