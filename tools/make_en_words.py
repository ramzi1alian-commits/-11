#!/usr/bin/env python3
"""Builds app/src/main/assets/en_words.tsv from ANY English word list.

Accepted input lines (auto-detected):
  the 23135851162        word + count (space/tab/comma separated)   e.g. FrequencyWords en_50k.txt
  the                    plain list, MOST common first (rank order is used as the score)

Usage:  python3 tools/make_en_words.py my_list.txt [max_words=100000]
Only lowercase a-z words of 2-20 letters are kept (proper nouns, numbers and symbols are dropped).
"""
import math, re, sys

src = sys.argv[1]
limit = int(sys.argv[2]) if len(sys.argv) > 2 else 100000
entries, seen = [], set()
for line in open(src, encoding="utf-8", errors="ignore"):
    parts = re.split(r"[\s,;]+", line.strip())
    if not parts or not parts[0]:
        continue
    w = parts[0].lower()
    if not re.fullmatch(r"[a-z]{2,20}", w) or w in seen:
        continue
    cnt = None
    if len(parts) > 1 and parts[1].isdigit():
        cnt = int(parts[1])
    seen.add(w)
    entries.append((w, cnt))
    if len(entries) >= limit:
        break

if entries and all(c is not None for _, c in entries):
    hi, lo = math.log(max(c for _, c in entries) + 1), math.log(min(c for _, c in entries) + 1)
    span = max(hi - lo, 1e-9)
    rows = [(w, 1 + int(254 * (math.log(c + 1) - lo) / span)) for w, c in entries]
else:  # rank order -> score falls linearly from 255 to 1
    n = max(len(entries) - 1, 1)
    rows = [(w, 255 - int(254 * i / n)) for i, (w, _) in enumerate(entries)]

rows.sort(key=lambda t: -t[1])
out = "app/src/main/assets/en_words.tsv"
open(out, "w", encoding="utf-8").write("".join(f"{w}\t{s}\n" for w, s in rows))
print(f"wrote {len(rows)} words to {out}")
