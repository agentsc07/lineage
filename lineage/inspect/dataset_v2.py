"""Dataset poisoning checks, v2 (REFACTOR_SPEC 8.3). Findings carry row references `file:line`.

Formats: tables (csv, tsv, json, jsonl, parquet when pyarrow is installed), prompt/response columns (`prompt`/`response`,
`instruction`/`input`/`output`, `question`/`answer`) and chat `messages` lists. Checks:

1. invisible and look-alike characters (zero-width, bidi controls, Unicode tag characters, mixed-script words), with the rate and
   whether they cluster with one label or one response
2. injected content: instruction overrides, URLs, markdown images, executable code, secrets
3. trigger -> behaviour in instruction data: a rare n-gram in prompts whose responses are far more alike than chance and far from
   the global response centroid
4. per-label embedding outliers and the spectral signature (Tran et al. 2018)
5. kNN label disagreement
(6. the older checks stay in `dataset_stats`; 7. the upstream diff is `dataset_diff`.)

Embeddings are TF-IDF + TruncatedSVD (256 dimensions) by default, or the hosted NVIDIA embedding model when `LINEAGE_EMBED_MODEL` is set.

Two guards go beyond the specification, and are logged in DECISIONS.md: a trigger group must also be near-identical in absolute terms
(mean pairwise response cosine >= 0.7) and its responses must be unrelated to their prompts (prompt/response TF-IDF cosine under half
the dataset's), because a legitimate keyword ("translate") also makes responses alike; without the guards clean, templated
instruction sets are flagged.
"""
from __future__ import annotations

import os
import re
import unicodedata
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from lineage.inspect._common import ev, finding
from lineage.inspect._tabular import LABEL_COLUMNS, TEXT_COLUMNS, data_files, read_rows
from lineage.schemas.finding import Finding

MAX_ROWS = int(os.environ.get("LINEAGE_DATASET_MAX_ROWS", "200000"))
PAIR_COLUMNS = [("prompt", "response"), ("instruction", "output"), ("question", "answer"), ("prompt", "completion"), ("input", "output")]
EXPECTED_POISON_RATE = 0.05

ZERO_WIDTH = re.compile("[​-‏⁠-⁤﻿­]")
BIDI = re.compile("[‪-‮⁦-⁩]")
TAGS = re.compile("[\U000e0000-\U000e007f]")
OVERRIDE = re.compile(r"\b(ignore|disregard|forget)\b[^.\n]{0,30}\b(previous|prior|above|all|earlier)\b[^.\n]{0,30}\b(instructions?|prompts?|rules)\b|"
                      r"\bnew instructions?:|\b(reveal|print|show) (the |your )?system prompt\b", re.I)
URL = re.compile(r"https?://[^\s)>\]\"']+", re.I)
MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*https?://[^)]+\)")
EXEC_CODE = re.compile(r"(curl|wget)[^\n|]*\|\s*(ba|z)?sh\b|\beval\s*\(|\bos\.system\s*\(|\bsubprocess\.(run|call|Popen|check_output)\s*\(|\bexec\s*\(|"
                       r"\bbase64\s+(-d|--decode)\b", re.I)
SECRET = re.compile(r"AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|\bsk-[A-Za-z0-9]{20,}|\bghp_[A-Za-z0-9]{30,}|\bxox[baprs]-[A-Za-z0-9-]{10,}")
WORD = re.compile(r"\w+", re.UNICODE)


def rows_ev(samples: list["Sample"], rows: list[int], cap: int = 2000):
    """Every flagged row as one `metric` evidence item (`rows`), so a benchmark can score row-level recall and precision."""
    return ev("metric", "rows", ",".join(samples[i].ref for i in rows[:cap]))


@dataclass
class Sample:
    file: str
    line: int
    prompt: str | None
    response: str | None
    text: str
    label: str | None

    @property
    def ref(self) -> str:
        return f"{self.file}:{self.line}"


def _chat_parts(msgs) -> tuple[str, str] | None:
    if not isinstance(msgs, list) or not msgs or not all(isinstance(m, dict) for m in msgs):
        return None
    user = [str(m.get("content", "")) for m in msgs if m.get("role") in ("user", "system", "human")]
    asst = [str(m.get("content", "")) for m in msgs if m.get("role") in ("assistant", "gpt", "model")]
    return (" ".join(user), asst[-1] if asst else "") if user or asst else None


def _rows_of(path: Path, limit: int) -> list[dict]:
    if path.suffix.lower() == ".parquet":
        try:
            import pyarrow.parquet as pq
        except ImportError:
            raise NotImplementedError("pyarrow is not installed")
        t = pq.read_table(path).to_pylist()[:limit]
        for i, r in enumerate(t, 1):
            r["_line"] = i
        return t
    return read_rows(path, limit)


def load_samples(root: Path, limit: int | None = None) -> tuple[list[Sample], bool, list[str]]:
    """(samples, truncated, files that could not be read)."""
    limit = MAX_ROWS if limit is None else limit
    root = Path(root)
    out: list[Sample] = []
    skipped: list[str] = []
    truncated = False
    for f in data_files(root, suffixes={".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".parquet"}):
        rel = f.name if root.is_file() else f.relative_to(root).as_posix()
        try:
            rows = _rows_of(f, limit - len(out) + 1)
        except NotImplementedError:
            skipped.append(rel)
            continue
        if not rows:
            continue
        cols = {c.lower(): c for c in rows[0] if c != "_line"}
        pair = next(((cols[a], cols[b]) for a, b in PAIR_COLUMNS if a in cols and b in cols), None)
        label_col = next((cols[c] for c in LABEL_COLUMNS if c in cols and c not in ("output",)), None)
        text_col = next((cols[c] for c in TEXT_COLUMNS if c in cols), None)
        for r in rows:
            if len(out) >= limit:
                truncated = True
                break
            prompt = response = None
            if "messages" in cols and (chat := _chat_parts(r.get(cols["messages"]))):
                prompt, response = chat
            elif pair:
                prompt, response = str(r.get(pair[0], "")), str(r.get(pair[1], ""))
                if "instruction" in cols and "input" in cols and pair[0] == cols["instruction"] and r.get(cols["input"]):
                    prompt += " " + str(r[cols["input"]])
            text = " ".join(x for x in (prompt, response) if x) if (prompt is not None or response is not None) else str(r.get(text_col, "")) if text_col else ""
            if not text:
                continue
            out.append(Sample(rel, r["_line"], prompt, response, text, str(r[label_col]) if label_col and r.get(label_col) not in (None, "") else None))
        if truncated:
            break
    return out, truncated, skipped


# ------------------------------------------------------------------------------------------------ embeddings
def embed(texts: list[str], extra_fit: list[str] | None = None) -> np.ndarray:
    """Row-normalised embeddings. Hosted NVIDIA model when LINEAGE_EMBED_MODEL is set (falls back to TF-IDF + SVD if it fails)."""
    if os.environ.get("LINEAGE_EMBED_MODEL"):
        try:
            return _hosted_embed(texts)
        except Exception:  # noqa: BLE001 - fall back; the finding below says which embedding was used
            pass
    from sklearn.decomposition import TruncatedSVD
    from sklearn.feature_extraction.text import TfidfVectorizer

    vec = TfidfVectorizer(max_features=50000, sublinear_tf=True, min_df=1, token_pattern=r"(?u)\b\w+\b")
    X = vec.fit_transform(texts + (extra_fit or []))[: len(texts)]
    k = max(2, min(256, X.shape[1] - 1, X.shape[0] - 1))
    Z = TruncatedSVD(n_components=k, random_state=0).fit_transform(X)
    n = np.linalg.norm(Z, axis=1, keepdims=True)
    return Z / np.maximum(n, 1e-12)


def _hosted_embed(texts: list[str]) -> np.ndarray:
    import httpx

    base = os.environ.get("LINEAGE_LLM_BASE_URL", "https://integrate.api.nvidia.com/v1").rstrip("/")
    key = os.environ.get("LINEAGE_LLM_API_KEY") or os.environ.get("NVIDIA_API_KEY")
    out = []
    for i in range(0, len(texts), 64):
        r = httpx.post(f"{base}/embeddings", headers={"Authorization": f"Bearer {key}"}, timeout=60,
                       json={"model": os.environ["LINEAGE_EMBED_MODEL"], "input": texts[i:i + 64], "input_type": "passage", "truncate": "END"})
        r.raise_for_status()
        out += [d["embedding"] for d in r.json()["data"]]
    Z = np.array(out, float)
    return Z / np.maximum(np.linalg.norm(Z, axis=1, keepdims=True), 1e-12)


# ------------------------------------------------------------------------------------------------ 1. characters
def _mixed_script(word: str) -> bool:
    scripts = set()
    for ch in word:
        if ch.isalpha():
            try:
                scripts.add(unicodedata.name(ch).split()[0])
            except ValueError:
                continue
    return len(scripts & {"LATIN", "CYRILLIC", "GREEK"}) > 1


def _clusters(rows: list[int], samples: list[Sample]) -> str | None:
    """Do the flagged rows pile up on one label or one response? Returns a description, or None."""
    if len(rows) < 3:
        return None
    for name, key in (("label", lambda s: s.label), ("response", lambda s: (s.response or "")[:80])):
        vals = [key(samples[i]) for i in rows]
        if not any(vals):
            continue
        top, cnt = Counter(vals).most_common(1)[0]
        overall = sum(1 for s in samples if key(s) == top) / len(samples)
        if cnt / len(rows) >= 0.7 and cnt / len(rows) > overall + 0.2:
            return f"{cnt}/{len(rows)} flagged rows share the {name} {str(top)[:40]!r} (only {overall:.0%} of all rows do)"
    return None


def check_characters(samples: list[Sample]) -> list[Finding]:
    out: list[Finding] = []
    flagged: dict[str, list[int]] = {"zero-width": [], "bidi control": [], "Unicode tag": [], "mixed-script word": []}
    for i, s in enumerate(samples):
        if ZERO_WIDTH.search(s.text):
            flagged["zero-width"].append(i)
        if BIDI.search(s.text):
            flagged["bidi control"].append(i)
        if TAGS.search(s.text):
            flagged["Unicode tag"].append(i)
        if any(_mixed_script(w) for w in WORD.findall(s.text) if not w.isascii()):
            flagged["mixed-script word"].append(i)
    for kind, rows in flagged.items():
        if not rows:
            continue
        rate = len(rows) / len(samples)
        cl = _clusters(rows, samples)
        sev = "high" if cl or kind in ("Unicode tag", "bidi control") else "medium" if rate >= 0.001 else "low"
        out.append(finding("DATA.CHARS." + kind.upper().replace(" ", "_").replace("-", "_"),
                           f"{len(rows)} row(s) ({rate:.1%}) contain {kind} characters" + (f"; {cl}" if cl else ""), sev, "data", "S4",
                           [ev("file_line", samples[i].ref, kind) for i in rows[:5]] + [ev("metric", "rate", f"{rate:.4f}"), rows_ev(samples, rows)]))
    return out


# ------------------------------------------------------------------------------------------------ 2. injected content
def check_injection(samples: list[Sample]) -> list[Finding]:
    rules = [("DATA.INJECT.OVERRIDE", "instruction-override phrase", OVERRIDE, "high"), ("DATA.INJECT.EXEC", "code that executes (curl|sh, eval, os.system)", EXEC_CODE, "high"),
             ("DATA.INJECT.SECRET", "secret or key", SECRET, "high"), ("DATA.INJECT.MARKDOWN_IMAGE", "markdown image from a remote host", MD_IMAGE, "medium"),
             ("DATA.INJECT.URL", "URL", URL, "low")]
    out: list[Finding] = []
    has_resp = any(s.response is not None for s in samples)
    for fid, what, rx, sev in rules:
        rows = [i for i, s in enumerate(samples) if rx.search(s.response if (has_resp and s.response is not None) else s.text)]
        if not rows:
            continue
        rate = len(rows) / len(samples)
        cl = _clusters(rows, samples)
        # a URL here and there is normal text; many, or clustered on one response, is not
        if fid == "DATA.INJECT.URL" and rate < 0.02 and not cl:
            sev = "info"
        if cl and sev != "high":
            sev = "high" if fid != "DATA.INJECT.URL" else "medium"
        where = "responses" if has_resp else "texts"
        out.append(finding(fid, f"{len(rows)} {where} ({rate:.1%}) contain a {what}" + (f"; {cl}" if cl else ""), sev, "data", "S4",  # type: ignore[arg-type]
                           [ev("file_line", samples[i].ref, rx.search(samples[i].response or samples[i].text).group(0)[:60]) for i in rows[:5]]
                           + [ev("metric", "rate", f"{rate:.4f}"), rows_ev(samples, rows)]))
    return out


# ------------------------------------------------------------------------------------------------ 3. trigger -> behaviour
def check_trigger_behaviour(samples: list[Sample]) -> list[Finding]:
    from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer

    idx = [i for i, s in enumerate(samples) if s.prompt is not None and s.response]
    n = len(idx)
    if n < 50:
        return []
    prompts = [samples[i].prompt for i in idx]  # type: ignore[misc]
    resps = [samples[i].response for i in idx]  # type: ignore[misc]
    V = embed(resps, extra_fit=prompts)
    cv = CountVectorizer(ngram_range=(1, 4), binary=True, min_df=max(3, int(np.ceil(0.001 * n))), max_df=0.10, lowercase=True, token_pattern=r"(?u)\b\w+\b",
                         max_features=20000)
    try:
        M = cv.fit_transform(prompts).T.tocsr()  # candidates x rows
    except ValueError:
        return []
    terms = cv.get_feature_names_out()
    df = np.asarray(M.sum(axis=1)).ravel()
    keep = np.where(df >= 3)[0]
    if len(keep) == 0:
        return []
    M, terms, df = M[keep], terms[keep], df[keep]
    S = M @ V  # sum of response vectors per candidate
    sims = (np.einsum("ij,ij->i", S, S) - df) / (df * (df - 1))
    gmean = V.mean(axis=0)
    cdist = 1 - (S / df[:, None]) @ gmean / np.maximum(np.linalg.norm(S / df[:, None], axis=1) * np.linalg.norm(gmean), 1e-12)
    rng = np.random.default_rng(0)
    null: dict[int, tuple[float, float]] = {}
    for size in sorted(set(df.astype(int))):
        draws = []
        for _ in range(60):
            pick = rng.choice(n, size, replace=False)
            s = V[pick].sum(0)
            draws.append((s @ s - size) / (size * (size - 1)))
        null[size] = (float(np.mean(draws)), float(np.std(draws)) + 1e-9)
    z = np.array([(sims[c] - null[int(df[c])][0]) / null[int(df[c])][1] for c in range(len(terms))])
    p95 = np.percentile(cdist, 95)
    # prompt/response relevance (TF-IDF cosine): a backdoor response is unrelated to its prompt
    tv = TfidfVectorizer(sublinear_tf=True, token_pattern=r"(?u)\b\w+\b").fit(prompts + resps)
    Pm, Rm = tv.transform(prompts), tv.transform(resps)
    rel = np.asarray(Pm.multiply(Rm).sum(axis=1)).ravel()
    rel_mean = float(rel.mean())
    cands = [c for c in range(len(terms)) if z[c] > 3 and cdist[c] > p95 and sims[c] >= 0.7
             and (rel_mean < 0.05 or rel[M[c].indices].mean() < 0.5 * rel_mean)]
    if not cands:
        return []
    groups: dict[tuple, int] = {}
    for c in sorted(cands, key=lambda c: (-len(terms[c]), -z[c])):  # one candidate per identical row set: the longest phrase
        groups.setdefault(tuple(M[c].indices.tolist()), c)
    out: list[Finding] = []
    covered: set[int] = set()
    for rows_t, c in sorted(groups.items(), key=lambda kv: (-len(kv[0]), -z[kv[1]])):
        if set(rows_t) <= covered:  # a sub-phrase of a trigger already reported ("words cf 7391" inside "cf 7391")
            continue
        covered |= set(rows_t)
        if len(out) >= 5:
            break
        rows = [idx[j] for j in rows_t]
        centroid = S[c] / df[c]
        close = [r for r, j in zip(rows, rows_t) if V[j] @ centroid / max(np.linalg.norm(centroid), 1e-12) >= 0.7]
        sample_resp = (samples[rows[0]].response or "")[:60]
        out.append(finding("DATA.TRIGGER.BEHAVIOUR", f"Prompt phrase {terms[c]!r} in {len(rows)} row(s) ({len(rows) / n:.1%}) always gets near-identical responses "
                           f"(within-group similarity {sims[c]:.2f}, z={z[c]:.1f}), e.g. {sample_resp!r}", "high", "data", "S4",
                           [ev("file_line", samples[r].ref, f"trigger {terms[c]!r}") for r in close[:8]]
                           + [ev("metric", "trigger", str(terms[c])), rows_ev(samples, close)],
                           source="statistical"))
    return out


def check_label_trigger(samples: list[Sample]) -> list[Finding]:
    """Classification data: a rare n-gram whose rows are (almost) all one label, yet whose *other* words say they belong elsewhere.
    A class-indicative word ("goal" in sports) is pure too, but a classifier trained without those rows labels them correctly; a
    dirty-label trigger row does not (the dirty-label backdoor signature)."""
    from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
    from sklearn.linear_model import LogisticRegression

    rows = [i for i, s in enumerate(samples) if s.label is not None and s.prompt is None]
    n = len(rows)
    if n < 100 or len({samples[i].label for i in rows}) < 2:
        return []
    texts = [samples[i].text for i in rows]
    labels = np.array([samples[i].label for i in rows])
    classes, counts = np.unique(labels, return_counts=True)
    base = dict(zip(classes, counts / n))
    cv = CountVectorizer(ngram_range=(1, 4), binary=True, min_df=max(8, int(np.ceil(0.001 * n))), max_df=0.10, token_pattern=r"(?u)\b\w+\b", max_features=30000)
    try:
        M = cv.fit_transform(texts).T.tocsr()
    except ValueError:
        return []
    terms = cv.get_feature_names_out()
    cands: list[tuple[float, int]] = []
    for c in range(len(terms)):
        idx = M[c].indices
        lab, cnt = np.unique(labels[idx], return_counts=True)
        top = lab[cnt.argmax()]
        purity = cnt.max() / len(idx)
        p = base[top]
        z = (purity - p) / np.sqrt(p * (1 - p) / len(idx))
        if purity >= 0.9 and p < 0.9 and z > 4:
            cands.append((z, c))
    groups: dict[tuple, int] = {}
    for _, c in sorted(cands, key=lambda zc: (-zc[0], -len(terms[zc[1]]))):  # most significant first; one phrase per identical row set
        key = tuple(M[c].indices.tolist())
        if key not in groups or len(terms[c]) > len(terms[groups[key]]):
            groups[key] = c
    if not groups:
        return []
    tv = TfidfVectorizer(sublinear_tf=True, token_pattern=r"(?u)\b\w+\b", max_features=30000)
    X = tv.fit_transform(texts)
    out: list[Finding] = []
    for rows_t, c in list(groups.items())[:40]:
        mask = np.ones(n, bool)
        mask[list(rows_t)] = False
        clf = LogisticRegression(max_iter=300).fit(X[mask], labels[mask])
        pred = clf.predict(X[list(rows_t)])
        wrong = [j for j, pr in zip(rows_t, pred) if pr != labels[j]]
        if len(wrong) / len(rows_t) >= 0.5:
            forced = labels[list(rows_t)[0]]
            out.append(finding("DATA.TRIGGER.LABEL", f"Phrase {terms[c]!r} in {len(rows_t)} row(s) ({len(rows_t) / n:.1%}) forces the label {forced!r}, "
                               f"although the rest of those texts reads like other classes ({len(wrong)}/{len(rows_t)} are mislabelled by a classifier trained without them)",
                               "high", "data", "S4", [ev("file_line", samples[rows[j]].ref, f"label {labels[j]!r}") for j in wrong[:8]]
                               + [ev("metric", "trigger", str(terms[c])), rows_ev(samples, [rows[j] for j in wrong])], source="statistical"))
    return out[:5]


# ------------------------------------------------------------------------------------------------ 4./5. embeddings
def bimodality(x: np.ndarray) -> float:
    n = len(x)
    if n < 4 or x.std() < 1e-12:
        return 0.0
    m, s = x.mean(), x.std()
    skew = ((x - m) ** 3).mean() / s**3
    kurt = ((x - m) ** 4).mean() / s**4 - 3
    return float((skew**2 + 1) / (kurt + 3 * (n - 1) ** 2 / ((n - 2) * (n - 3))))


def check_embedding_outliers(samples: list[Sample], E: np.ndarray) -> list[Finding]:
    """Spectral signature per label: project centred embeddings on the top singular vector, flag the top 1.5 x expected poison rate."""
    out: list[Finding] = []
    by_label: dict[str, list[int]] = defaultdict(list)
    for i, s in enumerate(samples):
        if s.label is not None:
            by_label[s.label].append(i)
    for label, rows in by_label.items():
        if len(rows) < 20:
            continue
        X = E[rows] - E[rows].mean(axis=0)
        _, _, vt = np.linalg.svd(X, full_matrices=False)
        score = (X @ vt[0]) ** 2
        k = max(1, int(np.ceil(1.5 * EXPECTED_POISON_RATE * len(rows))))
        top = np.argsort(-score)[:k]
        bc = bimodality(score)
        # separation: the flagged tail must be well above the bulk, not just the usual tail of a smooth distribution
        gap = (score[top].mean() - np.median(score)) / (score.std() + 1e-12)
        if bc > 0.555 and gap > 3:
            sev = "medium" if bc > 0.7 and gap > 4 else "low"  # a weak separation is noted, not escalated
            out.append(finding("DATA.SPECTRAL.OUTLIERS", f"Label {label!r}: {k} row(s) separate along the top singular vector (bimodality {bc:.2f}, "
                               f"gap {gap:.1f} sd): the spectral-signature pattern of poisoned rows", sev, "data", "S4",  # type: ignore[arg-type]
                               [ev("file_line", samples[rows[t]].ref, f"score {score[t]:.3g}") for t in top[:8]]
                               + [ev("metric", "bimodality_coefficient", f"{bc:.3f}"), rows_ev(samples, [rows[t] for t in top])], source="statistical"))
    return out


def check_knn_labels(samples: list[Sample], E: np.ndarray, k: int = 10) -> list[Finding]:
    rows = [i for i, s in enumerate(samples) if s.label is not None]
    if len(rows) < 50 or len({samples[i].label for i in rows}) < 2:
        return []
    X = E[rows]
    labels = np.array([samples[i].label for i in rows])
    bad: list[int] = []
    for start in range(0, len(rows), 1000):
        sim = X[start:start + 1000] @ X.T
        for r in range(sim.shape[0]):
            sim[r, start + r] = -2
        nn = np.argpartition(-sim, k, axis=1)[:, :k]
        for r in range(sim.shape[0]):
            if (labels[nn[r]] != labels[start + r]).mean() >= 0.8:
                bad.append(start + r)
    if not bad:
        return []
    frac = len(bad) / len(rows)
    return [finding("DATA.KNN.LABEL_DISAGREE", f"{len(bad)} row(s) ({frac:.1%}) have a label that disagrees with at least 80% of their {k} nearest neighbours",
                    "medium" if frac >= 0.05 else "low", "data", "S4", [ev("file_line", samples[rows[b]].ref, f"label {labels[b]!r}") for b in bad[:8]]
                    + [ev("metric", "fraction", f"{frac:.4f}"), rows_ev(samples, [rows[b] for b in bad])], source="statistical")]


def scan(root: Path, card_text: str | None = None) -> list[Finding]:
    from lineage.intake.inspectors import not_run

    samples, truncated, skipped = load_samples(Path(root))
    out: list[Finding] = []
    if skipped:
        out.append(not_run("PARQUET", f"pyarrow is not installed, so {', '.join(skipped[:3])} could not be read", "S4"))
    if truncated:
        out.append(not_run("FULL_SCAN", f"only the first {MAX_ROWS:,} rows were analysed (LINEAGE_DATASET_MAX_ROWS)", "S4", "low"))
    if not samples:
        return out + [finding("DATA.V2.NO_TEXT", "No text rows (table, prompt/response or chat) to analyse", "info", "data", "S4")]
    out += check_characters(samples)
    out += check_injection(samples)
    out += check_trigger_behaviour(samples)
    out += check_label_trigger(samples)
    if len(samples) >= 50 and any(s.label is not None for s in samples):
        E = embed([s.text for s in samples])
        out += check_embedding_outliers(samples, E)
        out += check_knn_labels(samples, E)
    out.append(finding("DATA.V2.SUMMARY", f"Poisoning checks ran on {len(samples):,} row(s)" + (" (sampled)" if truncated else ""), "info", "data", "S4",
                       [ev("metric", "rows", str(len(samples)))]))
    return out
