"""Row-level diff of a dataset against an earlier version (REFACTOR_SPEC 8.3 check 7): added, removed and changed rows by
normalised-row hash, labels flipped (same text, different label), class-balance drift (total variation distance), and new tokens
concentrated in the added rows. Findings are `DATA.DIFF.*`."""
from __future__ import annotations

import hashlib
import re
from collections import Counter
from pathlib import Path

from lineage.inspect._common import ev, finding
from lineage.inspect.dataset_v2 import Sample, load_samples
from lineage.schemas.finding import Finding

_WORD = re.compile(r"\w+", re.UNICODE)


def _norm(s: str) -> str:
    return " ".join(_WORD.findall(s.lower()))


def _h(s: str) -> str:
    return hashlib.sha1(_norm(s).encode()).hexdigest()  # noqa: S324 - a row key, not a security hash


def diff(new_root: Path, old_root: Path) -> list[Finding]:
    new, _, _ = load_samples(Path(new_root))
    old, _, _ = load_samples(Path(old_root))
    if not new or not old:
        return []
    key = lambda s: _h(s.text)  # noqa: E731 - prompt + response for instruction data, the text otherwise
    old_by_text = {}
    for s in old:
        old_by_text.setdefault(key(s), s)
    new_keys = {key(s) for s in new}
    added = [s for s in new if key(s) not in old_by_text]
    removed = [s for s in old if key(s) not in new_keys]
    # same text, different label: compare on the text alone (labels are not part of `text` for classification rows)
    old_label = {}
    for s in old:
        if s.label is not None:
            old_label.setdefault(key(s), s.label)
    flipped = [s for s in new if s.label is not None and key(s) in old_label and old_label[key(s)] != s.label]
    out = [finding("DATA.DIFF.SUMMARY", f"Compared with the earlier version: {len(added)} row(s) added, {len(removed)} removed, {len(flipped)} label(s) flipped "
                   f"({len(new)} rows now, {len(old)} before)", "info", "data", "S4",
                   [ev("metric", "added", str(len(added))), ev("metric", "removed", str(len(removed))), ev("metric", "flipped", str(len(flipped)))])]
    if flipped:
        out.append(finding("DATA.DIFF.LABELS_FLIPPED", f"{len(flipped)} row(s) have the same text as before but a different label",
                           "high" if len(flipped) / len(new) >= 0.005 else "medium", "data", "S4",
                           [ev("file_line", s.ref, f"was {old_label[key(s)]!r}, now {s.label!r}") for s in flipped[:8]]))
    if added:
        frac = len(added) / len(new)
        out.append(finding("DATA.DIFF.ADDED_ROWS", f"{len(added)} new row(s) ({frac:.1%}) that were not in the earlier version",
                           "medium" if frac >= 0.05 else "low", "data", "S4", [ev("file_line", s.ref, s.text[:60]) for s in added[:8]]))
    # class balance drift
    if all(s.label is not None for s in new[:50]) and all(s.label is not None for s in old[:50]):
        a, b = Counter(s.label for s in old), Counter(s.label for s in new)
        tv = 0.5 * sum(abs(a[c] / len(old) - b[c] / len(new)) for c in set(a) | set(b))
        if tv > 0.1:
            out.append(finding("DATA.DIFF.BALANCE_DRIFT", f"Class balance moved by {tv:.0%} (total variation distance) since the earlier version", "medium", "data", "S4",
                               [ev("metric", "tv_distance", f"{tv:.4f}")]))
    # tokens that show up in the added rows and almost nowhere else
    if len(added) >= 3:
        added_df = Counter(t for s in added for t in set(_WORD.findall(s.text.lower())))
        base = [s for s in new if key(s) in old_by_text]
        base_df = Counter(t for s in base for t in set(_WORD.findall(s.text.lower())))
        tokens = [(t, c) for t, c in added_df.items() if c >= max(3, 0.2 * len(added)) and base_df.get(t, 0) <= 0.005 * max(len(base), 1)]
        if tokens:
            tokens.sort(key=lambda x: -x[1])
            out.append(finding("DATA.DIFF.NEW_TOKENS", f"{len(tokens)} token(s) ({', '.join(repr(t) for t, _ in tokens[:8])}) appear in the added rows and (almost) nowhere in the rest",
                               "high", "data", "S4", [ev("metric", t, f"{c} of {len(added)} added rows") for t, c in tokens[:8]]
                               + [ev("file_line", s.ref, s.text[:60]) for s in added[:3]]))
    return out
