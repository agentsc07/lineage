"""Dataset statistics: (near-)duplicates via MinHash, label errors via confident learning, class balance vs card (Track C)."""
from __future__ import annotations

import re
import zlib
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

from lineage.inspect._common import ev, finding
from lineage.inspect._tabular import LABEL_COLUMNS, TEXT_COLUMNS, data_files, pick_column, read_rows
from lineage.schemas.finding import Finding

MAX_ROWS = 100_000
NUM_PERM, BANDS = 128, 16  # 16 bands x 8 rows: candidate threshold ~ Jaccard 0.7
NEAR_DUP_JACCARD = 0.8
_PRIME = (1 << 31) - 1
_WORD = re.compile(r"\w+")


# ---------------------------------------------------------------- MinHash
def shingles(text: str, k: int = 3) -> set[int]:
    words = _WORD.findall(text.lower())
    if len(words) < k:
        grams = [" ".join(words)] if words else []
    else:
        grams = [" ".join(words[i:i + k]) for i in range(len(words) - k + 1)]
    return {zlib.crc32(g.encode()) for g in grams}


def minhash_signatures(sets: list[set[int]], seed: int = 1) -> np.ndarray:
    rng = np.random.default_rng(seed)
    a = rng.integers(1, _PRIME, NUM_PERM, dtype=np.uint64)[:, None]
    b = rng.integers(0, _PRIME, NUM_PERM, dtype=np.uint64)[:, None]
    sig = np.full((len(sets), NUM_PERM), _PRIME, dtype=np.uint64)
    for i, s in enumerate(sets):
        if s:
            h = np.fromiter(s, dtype=np.uint64)[None, :]
            sig[i] = ((a * h + b) % _PRIME).min(axis=1)
    return sig


def near_duplicate_clusters(texts: list[str], threshold: float = NEAR_DUP_JACCARD) -> list[list[int]]:
    """Clusters (size >= 2) of rows whose word-3-gram sets have estimated Jaccard >= threshold."""
    sets = [shingles(t) for t in texts]
    sig = minhash_signatures(sets)
    rows = NUM_PERM // BANDS
    parent = list(range(len(texts)))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for band in range(BANDS):
        buckets: dict[bytes, list[int]] = defaultdict(list)
        for i in range(len(texts)):
            if len(sets[i]) >= 2:
                buckets[sig[i, band * rows:(band + 1) * rows].tobytes()].append(i)
        for members in buckets.values():
            for j in members[1:]:
                i = members[0]
                if find(i) != find(j) and float(np.mean(sig[i] == sig[j])) >= threshold:
                    parent[find(j)] = find(i)
    groups: dict[int, list[int]] = defaultdict(list)
    for i in range(len(texts)):
        groups[find(i)].append(i)
    return [g for g in groups.values() if len(g) > 1]


# ---------------------------------------------------------------- confident learning
def label_issues(texts: list[str], labels: list[str], seed: int = 0) -> tuple[list[int], list[str]] | None:
    """Rows whose given label disagrees with a cross-validated model, by confident learning (Northcutt et al. 2021).

    Returns (row indices, predicted labels) or None when the data is too small/unbalanced to estimate.
    """
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import StratifiedKFold, cross_val_predict

    classes = sorted(set(labels))
    counts = Counter(labels)
    cv = min(5, min(counts.values()))
    if len(classes) < 2 or cv < 2 or len(texts) < 10:
        return None
    y = np.array([classes.index(l) for l in labels])
    X = TfidfVectorizer(min_df=1, sublinear_tf=True).fit_transform(texts)
    probs = cross_val_predict(
        LogisticRegression(max_iter=1000, C=10.0), X, y, method="predict_proba",
        cv=StratifiedKFold(cv, shuffle=True, random_state=seed),
    )
    thresholds = np.array([probs[y == k, k].mean() for k in range(len(classes))])  # per-class self-confidence
    issues, predicted = [], []
    for i in range(len(texts)):
        confident = [k for k in range(len(classes)) if probs[i, k] >= thresholds[k]]
        if not confident:
            continue
        k = max(confident, key=lambda c: probs[i, c])
        if k != y[i]:
            issues.append(i)
            predicted.append(classes[k])
    return issues, predicted


def trigger_candidates(texts: list[str], labels: list[str], max_groups: int = 12, seed: int = 0) -> list[tuple[list[str], int, float]]:
    """Rare tokens whose label is not explained by the rest of the text: candidate poisoning triggers.

    Confident learning cannot see a consistent trigger because the model simply learns it. So: take rare tokens that
    are (almost) pure for one label, group tokens that occur in exactly the same rows (a multi-word trigger), remove
    each group, and re-predict those rows from the remaining text. A legitimate class word is backed up by other
    words (or the rows become uninformative, ~50% error); a flipped-label trigger makes the remaining text contradict
    the label (error ~100%). Returns (tokens, rows, error rate) for groups with error >= 0.8.
    """
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import StratifiedKFold, cross_val_predict

    n = len(texts)
    classes = sorted(set(labels))
    counts = Counter(labels)
    cv = min(5, min(counts.values())) if counts else 0
    if len(classes) < 2 or cv < 2 or n < 30:
        return []
    y = np.array([classes.index(l) for l in labels])
    docs = [set(_WORD.findall(t.lower())) for t in texts]
    postings: dict[str, list[int]] = defaultdict(list)
    for i, d in enumerate(docs):
        for tok in d:
            postings[tok].append(i)
    groups: dict[tuple[int, ...], list[str]] = defaultdict(list)
    for tok, rows in postings.items():
        if 3 <= len(rows) <= max(3, int(0.1 * n)):
            top = Counter(y[rows]).most_common(1)[0][1]
            if top / len(rows) >= 0.95:
                groups[tuple(rows)].append(tok)
    ranked = sorted(groups.items(), key=lambda kv: -len(kv[0]))[:max_groups]
    found = []
    for rows, toks in ranked:
        rx = r"(?u)\b\w+\b"
        vec = TfidfVectorizer(token_pattern=rx, stop_words=list(toks), sublinear_tf=True)
        try:
            X = vec.fit_transform(texts)
        except ValueError:
            continue
        pred = cross_val_predict(LogisticRegression(max_iter=1000), X, y, cv=StratifiedKFold(cv, shuffle=True, random_state=seed))
        err = float(np.mean(pred[list(rows)] != y[list(rows)]))
        if err >= 0.8:
            found.append((sorted(toks), len(rows), err))
    return found


# ---------------------------------------------------------------- card claims
def card_claims(card: str, classes: list[str]) -> dict:
    claims: dict = {"percent": {}, "rows": None, "classes": None, "balanced": False}
    low = card.lower()
    for c in classes:
        rx = re.compile(rf"{re.escape(str(c).lower())}\W{{0,12}}?(\d+(?:\.\d+)?)\s*%|(\d+(?:\.\d+)?)\s*%\s*(?:of\s+(?:the\s+)?(?:\w+\s+){{0,3}})?(?:are\s+|is\s+)?(?:labell?ed\s+(?:as\s+)?)?['\"]?{re.escape(str(c).lower())}\b")
        m = rx.search(low)
        if m:
            claims["percent"][c] = float(m.group(1) or m.group(2))
    m = re.search(r"(\d[\d,]*)\s+(?:rows|samples|examples|records|images|sentences|reports|instances)", low)
    if m:
        claims["rows"] = int(m.group(1).replace(",", ""))
    m = re.search(r"(\d+)\s+(?:distinct\s+)?(?:classes|labels|categories)", low)
    if m:
        claims["classes"] = int(m.group(1))
    claims["balanced"] = bool(re.search(r"\b(?:class[- ])?balanced\b|\bbalanced (?:classes|dataset|labels)\b", low)) and "imbalanced" not in low and "unbalanced" not in low
    return claims


# ---------------------------------------------------------------- scan
def scan(dataset_path: Path, card_text: str | None = None) -> list[Finding]:
    root = Path(dataset_path)
    rows: list[dict] = []
    files = data_files(root)
    for f in files:
        for r in read_rows(f, MAX_ROWS - len(rows)):
            r["_file"] = f.name if root.is_file() else f.relative_to(root).as_posix()
            rows.append(r)
        if len(rows) >= MAX_ROWS:
            break
    if not rows:
        return [finding("DATA.STATS.NO_TABLE", "No tabular data (csv/tsv/json/jsonl) found to analyse", "info", "data", "S4")]

    def ref(i: int) -> str:
        return f"{rows[i]['_file']}:{rows[i]['_line']}"

    text_col = pick_column(rows, TEXT_COLUMNS, string_only=True)
    label_col = pick_column(rows, LABEL_COLUMNS)
    if label_col and label_col.lower() == "output":  # instruction data: `output` is the response, not a class label
        label_col = None
    out: list[Finding] = []
    n = len(rows)
    out.append(finding("DATA.STATS.SUMMARY", f"{n} rows, text column {text_col!r}, label column {label_col!r}", "info", "data", "S4",
                       [ev("metric", "rows", str(n))]))

    texts = [str(r.get(text_col, "")) if text_col else "" for r in rows]
    labels = [str(r.get(label_col, "")) for r in rows] if label_col else []

    # exact + near duplicates
    if text_col:
        norm = [" ".join(_WORD.findall(t.lower())) for t in texts]
        seen: dict[str, list[int]] = defaultdict(list)
        for i, t in enumerate(norm):
            if t:
                seen[t].append(i)
        exact = [g for g in seen.values() if len(g) > 1]
        n_exact = sum(len(g) - 1 for g in exact)
        if n_exact:
            frac = n_exact / n
            out.append(finding("DATA.STATS.EXACT_DUPLICATES", f"{n_exact} exact duplicate row(s) ({frac:.1%})",
                               "medium" if frac >= 0.2 else "low", "data", "S4",
                               [ev("file_line", ref(g[0]), f"duplicated at {', '.join(ref(i) for i in g[1:4])}") for g in exact[:3]]
                               + [ev("metric", "exact_duplicate_fraction", f"{frac:.4f}")]))
        if label_col:
            conflicts = [g for g in exact if len({labels[i] for i in g}) > 1]
            if conflicts:
                out.append(finding("DATA.STATS.CONFLICTING_LABELS", f"{len(conflicts)} text(s) appear with different labels", "high", "data", "S4",
                                   [ev("file_line", ref(g[0]), "labels " + ", ".join(sorted({labels[i] for i in g}))) for g in conflicts[:3]]))
        in_exact = {i for g in exact for i in g}
        remaining = [i for i in range(n) if i not in in_exact or i == next((g[0] for g in exact if i in g), None)]
        clusters = near_duplicate_clusters([norm[i] for i in remaining])
        clusters = [[remaining[j] for j in c] for c in clusters]
        n_near = sum(len(c) - 1 for c in clusters)
        if n_near:
            frac = n_near / n
            out.append(finding("DATA.STATS.NEAR_DUPLICATES", f"{n_near} near-duplicate row(s) ({frac:.1%}) by MinHash",
                               "medium" if frac >= 0.2 else "low", "data", "S4",
                               [ev("file_line", ref(c[0]), f"near-duplicates at {', '.join(ref(i) for i in c[1:4])}") for c in clusters[:3]]
                               + [ev("metric", "near_duplicate_fraction", f"{frac:.4f}")]))

    # class balance (vs the card)
    if label_col:
        dist = Counter(labels)
        classes = sorted(dist)
        shares = {c: 100 * v / n for c, v in dist.items()}
        ratio = max(dist.values()) / max(min(dist.values()), 1)
        dist_s = ", ".join(f"{c}: {shares[c]:.1f}%" for c in classes[:10])
        if card_text:
            claims = card_claims(card_text, classes)
            for c, claimed in claims["percent"].items():
                gap = abs(shares[c] - claimed)
                if gap > 10:
                    out.append(finding("DATA.STATS.CLASS_BALANCE_MISMATCH", f"Card says {c!r} is {claimed:g}% of the data, measured {shares[c]:.1f}%",
                                       "high" if gap > 25 else "medium", "data", "S4",
                                       [ev("metric", f"class_share[{c}]", f"claimed {claimed:g}% measured {shares[c]:.1f}%")]))
            if claims["balanced"] and ratio > 1.5:
                out.append(finding("DATA.STATS.CLASS_BALANCE_MISMATCH", f"Card says the classes are balanced, measured imbalance {ratio:.1f}:1", "medium",
                                   "data", "S4", [ev("metric", "imbalance_ratio", f"{ratio:.2f}"), ev("metric", "distribution", dist_s)]))
            if claims["rows"] and abs(claims["rows"] - n) / max(claims["rows"], 1) > 0.01:
                out.append(finding("DATA.STATS.ROW_COUNT_MISMATCH", f"Card says {claims['rows']:,} rows, found {n:,}", "medium", "data", "S4",
                                   [ev("metric", "rows", f"claimed {claims['rows']} measured {n}")]))
            if claims["classes"] and claims["classes"] != len(classes):
                out.append(finding("DATA.STATS.CLASS_COUNT_MISMATCH", f"Card says {claims['classes']} classes, found {len(classes)}", "medium", "data",
                                   "S4", [ev("metric", "classes", f"claimed {claims['classes']} measured {len(classes)}")]))
        if ratio >= 10:
            out.append(finding("DATA.STATS.IMBALANCED", f"Severe class imbalance {ratio:.0f}:1", "low", "data", "S4",
                               [ev("metric", "distribution", dist_s)]))

        # label errors (confident learning) + trigger-token heuristic
        if text_col:
            res = label_issues(texts, labels)
            if res is None:
                out.append(finding("DATA.STATS.LABEL_ESTIMATE_SKIPPED", "Label-error estimate skipped: too few rows or too few examples per class",
                                   "info", "data", "S4"))
            else:
                idx, pred = res
                rate = len(idx) / n
                if idx:
                    sev = "high" if rate >= 0.10 else "medium" if rate >= 0.03 else "low"
                    out.append(finding("DATA.STATS.LABEL_ERRORS", f"Estimated {len(idx)} mislabelled row(s) ({rate:.1%}) by confident learning", sev,
                                       "data", "S4", [ev("file_line", ref(i), f"labelled {labels[i]!r}, model says {p!r}") for i, p in list(zip(idx, pred))[:5]]
                                       + [ev("metric", "label_issue_rate", f"{rate:.4f}")], source="statistical"))
            for toks, rows, err in trigger_candidates(texts, labels):
                out.append(finding("DATA.STATS.TRIGGER_TOKEN", f"Token(s) {toks[:3]} decide the label of {rows} row(s) against the rest of the text: possible poisoning trigger",
                                   "high", "data", "S4", [ev("metric", f"token[{', '.join(toks[:3])}]", f"{rows} rows, {err:.0%} contradict the label without them")],
                                   source="statistical"))
    return out
