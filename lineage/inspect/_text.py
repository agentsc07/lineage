"""Small text utilities: Damerau-Levenshtein distance and invisible-character detection."""
from __future__ import annotations

import unicodedata


def damerau_levenshtein(a: str, b: str, max_dist: int | None = None) -> int:
    """True (unrestricted) Damerau-Levenshtein distance. Returns max_dist + 1 early if it must exceed max_dist."""
    if a == b:
        return 0
    if max_dist is not None and abs(len(a) - len(b)) > max_dist:
        return max_dist + 1
    inf = len(a) + len(b)
    last_row: dict[str, int] = {}
    d = [[0] * (len(b) + 2) for _ in range(len(a) + 2)]
    d[0][0] = inf
    for i in range(len(a) + 1):
        d[i + 1][0] = inf
        d[i + 1][1] = i
    for j in range(len(b) + 1):
        d[0][j + 1] = inf
        d[1][j + 1] = j
    for i in range(1, len(a) + 1):
        last_col = 0
        for j in range(1, len(b) + 1):
            i1 = last_row.get(b[j - 1], 0)
            j1 = last_col
            cost = 0 if a[i - 1] == b[j - 1] else 1
            if cost == 0:
                last_col = j
            d[i + 1][j + 1] = min(
                d[i][j] + cost,
                d[i + 1][j] + 1,
                d[i][j + 1] + 1,
                d[i1][j1] + (i - i1 - 1) + 1 + (j - j1 - 1),
            )
        last_row[a[i - 1]] = i
    dist = d[len(a) + 1][len(b) + 1]
    return dist if max_dist is None else min(dist, max_dist + 1)


def invisible_chars(text: str) -> list[tuple[int, str, str]]:
    """(index, codepoint 'U+XXXX', name) for format/control/private-use/tag characters other than ordinary whitespace."""
    out = []
    for i, ch in enumerate(text):
        if ch in "\n\r\t":
            continue
        cat = unicodedata.category(ch)
        if cat in ("Cf", "Cc", "Co", "Cn") or 0xE0000 <= ord(ch) <= 0xE007F or 0xFE00 <= ord(ch) <= 0xFE0F:
            out.append((i, f"U+{ord(ch):04X}", unicodedata.name(ch, "UNNAMED")))
    return out


def decode_tag_chars(text: str) -> str:
    """Tag characters U+E0020..U+E007E mirror ASCII; attackers use them to smuggle hidden text."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)
