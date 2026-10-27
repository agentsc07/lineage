"""Tokenizer diff vs the claimed base model (Track C)."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from lineage.inspect._common import ev, finding
from lineage.inspect._text import invisible_chars
from lineage.schemas.finding import Finding

URL = re.compile(r"https?://|www\.", re.I)
INSTRUCTION = re.compile(r"ignore (all |any )?(previous|prior)|system prompt|you must|do not (tell|reveal)", re.I)


@dataclass
class Tok:
    vocab: dict[str, int] = field(default_factory=dict)
    merges: list[str] = field(default_factory=list)
    added: dict[str, dict] = field(default_factory=dict)  # content -> {"id", "special"}
    parts: dict[str, str] = field(default_factory=dict)  # normalizer/pre_tokenizer/... -> canonical JSON
    special: dict[str, str] = field(default_factory=dict)  # bos_token, eos_token, ... from tokenizer_config.json
    blobs: dict[str, str] = field(default_factory=dict)  # sentencepiece / other opaque files -> sha256
    source: str = ""


def _json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _tok_text(v) -> str | None:
    if isinstance(v, dict):
        v = v.get("content")
    return v if isinstance(v, str) else None


def load(directory: Path) -> Tok:
    d = Path(directory)
    t = Tok(source=str(d))
    tj = _json(d / "tokenizer.json")
    if isinstance(tj, dict):
        model = tj.get("model") or {}
        vocab = model.get("vocab") or {}
        if isinstance(vocab, dict):
            t.vocab = {k: int(v) for k, v in vocab.items()}
        elif isinstance(vocab, list):  # unigram: [[piece, score], ...]
            t.vocab = {p[0]: i for i, p in enumerate(vocab)}
        t.merges = [m if isinstance(m, str) else " ".join(m) for m in model.get("merges") or []]
        for a in tj.get("added_tokens") or []:
            t.added[a["content"]] = {"id": a.get("id"), "special": bool(a.get("special"))}
        for k in ("normalizer", "pre_tokenizer", "post_processor", "decoder"):
            t.parts[k] = json.dumps(tj.get(k), sort_keys=True)
    else:
        vj, mt = _json(d / "vocab.json"), d / "merges.txt"
        if isinstance(vj, dict):
            t.vocab = {k: int(v) for k, v in vj.items()}
        if mt.exists():
            t.merges = [ln for ln in mt.read_text().splitlines() if ln and not ln.startswith("#version")]
    cfg = _json(d / "tokenizer_config.json")
    if isinstance(cfg, dict):
        for idx, a in (cfg.get("added_tokens_decoder") or {}).items():
            if isinstance(a, dict) and "content" in a:
                t.added.setdefault(a["content"], {"id": int(idx), "special": bool(a.get("special"))})
        for k in ("bos_token", "eos_token", "unk_token", "pad_token", "sep_token", "cls_token", "mask_token"):
            if _tok_text(cfg.get(k)) is not None:
                t.special[k] = _tok_text(cfg[k])  # type: ignore[assignment]
        for token in cfg.get("additional_special_tokens") or []:
            if _tok_text(token):
                t.added.setdefault(_tok_text(token), {"id": None, "special": True})  # type: ignore[arg-type]
    for name in ("tokenizer.model", "spiece.model", "sentencepiece.bpe.model"):
        if (d / name).exists():
            t.blobs[name] = hashlib.sha256((d / name).read_bytes()).hexdigest()
    return t


def _suspicious_token(content: str) -> list[str]:
    why = []
    if URL.search(content):
        why.append("contains a URL")
    if INSTRUCTION.search(content):
        why.append("reads like an instruction")
    if invisible_chars(content):
        why.append("contains invisible characters")
    if len(content) > 40:
        why.append(f"unusually long ({len(content)} chars)")
    return why


def scan(model_dir: Path, base_tokenizer_dir: Path | None = None) -> list[Finding]:
    model = load(model_dir)
    out: list[Finding] = []
    has_tokenizer = bool(model.vocab or model.blobs or model.added)
    if not has_tokenizer:
        return out

    extra = {c: a for c, a in model.added.items() if not a["special"]}
    for content, a in model.added.items():
        why = _suspicious_token(content)
        if why:
            out.append(finding("MODEL.TOKENIZER.SUSPICIOUS_TOKEN", f"Added token {content[:30]!r} {', '.join(why)}", "high", "model", "S3",
                               [ev("field", "tokenizer.json#added_tokens", f"{content[:80]!r} id={a['id']}")]))

    if base_tokenizer_dir is None:
        if extra:
            out.append(finding("MODEL.TOKENIZER.ADDED_TOKENS_UNCHECKED", f"{len(extra)} non-special added token(s); no base tokenizer to compare",
                               "info", "model", "S3", [ev("field", "tokenizer.json#added_tokens", repr(c[:60])) for c in list(extra)[:5]]))
        out.append(finding("MODEL.TOKENIZER.NO_BASE", "Tokenizer diff skipped: no base tokenizer supplied", "info", "model", "S3"))
        return out

    base = load(base_tokenizer_dir)
    if not (base.vocab or base.blobs):
        return out + [finding("MODEL.TOKENIZER.NO_BASE", "Tokenizer diff skipped: base tokenizer has no readable vocabulary", "info", "model", "S3")]

    if model.vocab and base.vocab:
        remapped = {t: (base.vocab[t], i) for t, i in model.vocab.items() if t in base.vocab and base.vocab[t] != i}
        new = [t for t in model.vocab if t not in base.vocab]
        gone = [t for t in base.vocab if t not in model.vocab]
        if remapped:
            out.append(finding("MODEL.TOKENIZER.REMAPPED", f"{len(remapped)} token(s) have different ids than the base tokenizer", "high",
                               "model", "S3", [ev("field", "tokenizer.json#model.vocab", f"{t!r}: {a} -> {b}") for t, (a, b) in list(remapped.items())[:8]]))
        if new:
            out.append(finding("MODEL.TOKENIZER.NEW_TOKENS", f"{len(new)} token(s) are not in the base vocabulary", "medium", "model", "S3",
                               [ev("field", "tokenizer.json#model.vocab", repr(t[:60])) for t in new[:8]]))
        if gone:
            out.append(finding("MODEL.TOKENIZER.REMOVED_TOKENS", f"{len(gone)} base token(s) are missing", "medium", "model", "S3",
                               [ev("field", "tokenizer.json#model.vocab", repr(t[:60])) for t in gone[:8]]))
    # a special token that keeps its text but moves to another id (or two that trade ids): the chat format the model was
    # trained on now points at different embeddings
    moved = {c: (base.added[c]["id"], a["id"]) for c, a in model.added.items()
             if c in base.added and a["id"] is not None and base.added[c]["id"] is not None and a["id"] != base.added[c]["id"]}
    if moved:
        special = [c for c in moved if model.added[c]["special"] or base.added[c]["special"]]
        out.append(finding("MODEL.TOKENIZER.SPECIAL_TOKEN_REMAPPED",
                           f"{len(moved)} added/special token(s) have a different id than in the base tokenizer: " + ", ".join(f"{c!r} {a}->{b}" for c, (a, b) in list(moved.items())[:4]),
                           "critical" if special else "high", "model", "S3",
                           [ev("field", "tokenizer.json#added_tokens", f"{c!r}: id {a} -> {b}") for c, (a, b) in list(moved.items())[:8]]))
    flipped = [c for c, a in model.added.items() if c in base.added and a["special"] != base.added[c]["special"]]
    if flipped:  # same text, same id, but now (not) a control token: the model reads or skips it differently
        out.append(finding("MODEL.TOKENIZER.SPECIAL_FLAG_CHANGED", f"{len(flipped)} added token(s) changed their 'special' flag: " + ", ".join(repr(c[:30]) for c in flipped[:4]),
                           "high", "model", "S3", [ev("field", "tokenizer.json#added_tokens", f"{c!r}: special {base.added[c]['special']} -> {model.added[c]['special']}") for c in flipped[:8]]))
    new_added = {c for c in model.added if c not in base.added}
    if new_added:
        out.append(finding("MODEL.TOKENIZER.ADDED_TOKENS", f"{len(new_added)} added/special token(s) differ from the base", "medium", "model", "S3",
                           [ev("field", "tokenizer.json#added_tokens", repr(c[:60])) for c in sorted(new_added)[:8]]))
    if model.merges != base.merges and (model.merges or base.merges):
        changed = sum(1 for a, b in zip(model.merges, base.merges) if a != b) + abs(len(model.merges) - len(base.merges))
        out.append(finding("MODEL.TOKENIZER.MERGES_CHANGED", f"BPE merges differ from the base ({changed} rule(s))", "high", "model", "S3",
                           [ev("field", "tokenizer.json#model.merges", f"{len(model.merges)} vs {len(base.merges)} rules")]))
    for k in sorted(set(model.parts) | set(base.parts)):
        if model.parts.get(k) != base.parts.get(k):
            sev = "high" if k == "post_processor" else "medium"  # post-processors can inject text around every prompt
            out.append(finding(f"MODEL.TOKENIZER.{k.upper()}_CHANGED", f"Tokenizer {k.replace('_', '-')} differs from the base", sev, "model",
                               "S3", [ev("field", f"tokenizer.json#{k}", "changed")]))
    for name, digest in model.blobs.items():
        if base.blobs.get(name) != digest:
            out.append(finding("MODEL.TOKENIZER.MODEL_FILE_CHANGED", f"{name} differs from the base tokenizer", "high", "model", "S3",
                               [ev("field", name, f"sha256 {digest[:16]}... vs {str(base.blobs.get(name))[:16]}...")]))
    for k, v in model.special.items():
        if k in base.special and base.special[k] != v:
            out.append(finding("MODEL.TOKENIZER.SPECIAL_TOKEN_CHANGED", f"{k} is {v!r}, base uses {base.special[k]!r}", "medium", "model",
                               "S3", [ev("field", f"tokenizer_config.json#{k}", f"{base.special[k]!r} -> {v!r}")]))
    return out
