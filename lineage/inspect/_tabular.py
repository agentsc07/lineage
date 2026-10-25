"""Tiny table loader for dataset scanners (csv / tsv / jsonl / json)."""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

TABLE_SUFFIXES = {".csv", ".tsv", ".jsonl", ".ndjson", ".json"}
TEXT_SUFFIXES = TABLE_SUFFIXES | {".txt", ".md"}
TEXT_COLUMNS = ("text", "sentence", "content", "prompt", "input", "review", "body", "message", "question", "instruction")
LABEL_COLUMNS = ("label", "labels", "class", "target", "category", "y", "sentiment", "output")

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))


def data_files(path: Path, suffixes=TABLE_SUFFIXES) -> list[Path]:
    path = Path(path)
    if path.is_file():
        return [path]
    return sorted(p for p in path.rglob("*") if p.is_file() and p.suffix in suffixes and ".git" not in p.parts)


def read_rows(path: Path, limit: int | None = None) -> list[dict]:
    """Rows as dicts; `_line` holds the 1-based source line (for csv, the line of the record's first physical line)."""
    rows: list[dict] = []
    suffix = path.suffix.lower()
    with path.open(newline="", errors="replace") as f:
        if suffix in (".csv", ".tsv"):
            reader = csv.DictReader(f, delimiter="\t" if suffix == ".tsv" else ",")
            for r in reader:
                r["_line"] = reader.line_num
                rows.append(r)
                if limit and len(rows) >= limit:
                    break
        elif suffix in (".jsonl", ".ndjson"):
            for n, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    obj["_line"] = n
                    rows.append(obj)
                if limit and len(rows) >= limit:
                    break
        elif suffix == ".json":
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                return []
            if isinstance(data, dict):
                data = next((v for v in data.values() if isinstance(v, list)), [])
            for n, obj in enumerate(data[:limit] if limit else data, 1):
                if isinstance(obj, dict):
                    obj["_line"] = n
                    rows.append(obj)
    return rows


def pick_column(rows: list[dict], preferred: tuple[str, ...], string_only: bool = False) -> str | None:
    if not rows:
        return None
    cols = [c for c in rows[0] if c != "_line"]
    lower = {c.lower(): c for c in cols}
    for name in preferred:
        if name in lower:
            return lower[name]
    if string_only:  # fall back to the column with the longest strings
        best, best_len = None, 0.0
        for c in cols:
            vals = [str(r.get(c, "")) for r in rows[:200]]
            avg = sum(map(len, vals)) / max(len(vals), 1)
            if avg > best_len and any(" " in v for v in vals):
                best, best_len = c, avg
        return best
    return None
