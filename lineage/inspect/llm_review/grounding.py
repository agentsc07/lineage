"""Grounding checker: keep only claims whose cited file:line really contains the cited API (spec §5.3)."""
from __future__ import annotations

import io
import re
import tokenize
from dataclasses import dataclass
from pathlib import Path

from lineage.schemas.gpu import Claim, CodeSlice

MIN_API_LEN = 2
_GENERIC_APIS = {"code", "function", "call", "the", "this", "file", "script", "line", "import", "none", "n/a", "unknown"}


@dataclass(frozen=True)
class Dropped:
    claim: Claim
    reason: str


class SourceIndex:
    """Reads files under `root` lazily; refuses any path that escapes it."""

    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self._cache: dict[str, list[str] | None] = {}

    def lines(self, rel: str) -> list[str] | None:
        rel = rel.strip().removeprefix("./")
        if rel not in self._cache:
            base = self.root.parent if self.root.is_file() else self.root
            p = (base / rel).resolve()
            try:
                p.relative_to(base)
                self._cache[rel] = p.read_text(errors="replace").splitlines() if p.is_file() else None
            except (ValueError, OSError):
                self._cache[rel] = None
        return self._cache[rel]


class SliceIndex(SourceIndex):
    """Grounds against the code slices that were sent to the reviewer, when the unpacked artifact is not at hand."""

    def __init__(self, slices: list[CodeSlice]):
        self._lines: dict[str, list[str]] = {}
        for s in slices:
            buf = self._lines.setdefault(s.file, [])
            buf.extend([""] * (s.end - len(buf)))
            buf[s.start - 1:s.start - 1 + len(s.code.splitlines())] = s.code.splitlines()

    def lines(self, rel: str) -> list[str] | None:
        return self._lines.get(rel.strip().removeprefix("./"))


def code_part(line: str) -> str:
    """The line without its trailing comment (an API named only in a comment is not a call)."""
    try:
        toks = [t for t in tokenize.generate_tokens(io.StringIO(line + "\n").readline) if t.type != tokenize.COMMENT]
        return " ".join(t.string for t in toks if t.type not in (tokenize.NEWLINE, tokenize.NL, tokenize.ENDMARKER))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return line.split("#", 1)[0] if line.lstrip().startswith("#") or " #" in line else line


def _norm(s: str) -> str:
    return re.sub(r"\s+", "", s)


def api_on_line(api: str, line: str) -> bool:
    """Does `line` (ignoring comments) contain `api`? A dotted api also matches via its last segment when imported by name."""
    api = api.strip().rstrip("()")
    if len(api) < MIN_API_LEN or api.lower() in _GENERIC_APIS:
        return False
    code = _norm(code_part(line))
    if _norm(api) in code:
        return True
    last = api.rsplit(".", 1)[-1]
    if "." in api and len(last) >= MIN_API_LEN and last.lower() not in _GENERIC_APIS:
        return re.search(rf"(?<![\w.]){re.escape(last)}\b", code_part(line)) is not None  # `from os import system`
    return False


def check_claim(claim: Claim, index: SourceIndex) -> str | None:
    """None if grounded, otherwise the reason it is not."""
    lines = index.lines(claim.file)
    if lines is None:
        return f"file {claim.file!r} not found in the artifact"
    if not 1 <= claim.line <= len(lines):
        return f"line {claim.line} is outside {claim.file} ({len(lines)} lines)"
    text = lines[claim.line - 1]
    if text.lstrip().startswith("#"):
        return f"{claim.file}:{claim.line} is a comment, not code"
    if not api_on_line(claim.api, text):
        return f"{claim.file}:{claim.line} does not contain {claim.api!r}"
    return None


def ground_claims_with_reasons(claims: list[Claim], root: Path | list[CodeSlice]) -> tuple[list[Claim], list[Dropped]]:
    """Split claims into (grounded, dropped-with-reason). `root` is the artifact directory or the slices that were reviewed."""
    index = SliceIndex(root) if isinstance(root, list) else SourceIndex(root)
    kept, dropped = [], []
    for c in claims:
        reason = check_claim(c, index)
        if reason is None:
            kept.append(c)
        else:
            dropped.append(Dropped(c, reason))
    return kept, dropped


def ground_claims(claims: list[Claim], root: Path | list[CodeSlice]) -> tuple[list[Claim], list[Claim]]:
    """(grounded, ungrounded) claims. Ungrounded claims never become findings."""
    kept, dropped = ground_claims_with_reasons(claims, root)
    return kept, [d.claim for d in dropped]
