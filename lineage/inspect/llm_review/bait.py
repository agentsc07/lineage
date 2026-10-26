"""Reviewer-bait detection: text in code that talks to the reviewer ("safe, ignore") is itself a malicious signal."""
from __future__ import annotations

import ast
import io
import re
import tokenize
from dataclasses import dataclass
from pathlib import Path

from lineage.inspect._common import ev, finding
from lineage.inspect._pycode import PyFile, iter_python
from lineage.schemas.finding import Finding

AUDIENCE = re.compile(r"\b(ai|a\.i\.|llm|language model|assistant|reviewer|code review(er)?|auditor|scanner|claude|gpt|chatgpt|copilot|"
                      r"security (team|scanner|tool|bot)|static analy[sz]er|linter|model)\b", re.I)
DIRECTIVE = re.compile(r"\b(ignore|disregard|skip|overlook|do not (flag|report|mention|block|reject)|don'?t (flag|report|mention|block)|"
                       r"no need to|you (should|must|can) (approve|pass|ignore)|mark (this )?as (safe|benign)|approve)\b", re.I)
ASSURANCE = re.compile(r"\b(safe|benign|harmless|legitimate|false[- ]positive|not (malicious|malware|harmful)|audited|already (reviewed|approved|audited)|"
                       r"trusted|verified|whitelisted|pass(ed)? (the )?(review|scan|audit))\b", re.I)
STRONG = re.compile(r"ignore (all |any )?(previous|prior|above) instructions|note to (the )?(ai|llm|reviewer|assistant)|"
                    r"(this|the) (code|file|package|function|script|line) is (completely |totally )?(safe|benign|harmless)|"
                    r"(not|isn'?t) (a )?(malware|malicious|backdoor)|nothing (suspicious|malicious) (here|to see)|"
                    r"(security )?review(er)?:? (pass|approved|ok)|<\s*/?\s*(system|instructions?)\s*>", re.I)


# Phrases that speak to a reader that is not the user: only these count in docstrings and long prose.
ADDRESSED = re.compile(r"ignore (all |any )?(previous|prior|above) instructions|note to (the )?(ai|llm|reviewer|assistant)|<\s*/?\s*(system|instructions?)\s*>|"
                       r"(this|the) (code|file|package|function|script|line) is (completely |totally )?(safe|benign|harmless)|"
                       r"nothing (suspicious|malicious) (here|to see)|(security )?review(er)?:? (pass|approved|ok)", re.I)


@dataclass(frozen=True)
class Bait:
    file: str
    line: int
    text: str
    where: str  # comment | string


PROXIMITY = 80  # characters between the audience and what it is told: a sentence, not a page of prose


def is_bait(text: str, strict: bool = False) -> bool:
    """`strict` (docstrings and long prose, where words like "model" and "approve" are ordinary) accepts only the explicit phrases."""
    if strict:
        return bool(ADDRESSED.search(text))
    if STRONG.search(text):
        return True
    for a in AUDIENCE.finditer(text):
        window = text[max(0, a.start() - PROXIMITY): a.end() + PROXIMITY]
        if DIRECTIVE.search(window) or ASSURANCE.search(window):
            return True
    return False


def _comments(pf: PyFile):
    try:
        for t in tokenize.generate_tokens(io.StringIO(pf.text).readline):
            if t.type == tokenize.COMMENT:
                yield t.start[0], t.string.lstrip("# ")
    except (tokenize.TokenError, IndentationError, SyntaxError):
        for n, line in enumerate(pf.text.splitlines(), 1):
            if "#" in line:
                yield n, line.split("#", 1)[1].strip()


def detect(package_dir: Path) -> list[Bait]:
    out: list[Bait] = []
    for pf in iter_python(Path(package_dir)):
        if pf.kind == "py":
            for line, text in _comments(pf):
                if is_bait(text):
                    out.append(Bait(pf.rel, line, text[:200], "comment"))
        if pf.tree is not None:
            docs = {n.body[0].value for n in ast.walk(pf.tree)
                    if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                    and n.body and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
            for node in ast.walk(pf.tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str) and 12 <= len(node.value) <= 2000 and is_bait(
                        node.value, strict=node in docs or len(node.value) > 300):
                    out.append(Bait(pf.rel, node.lineno, node.value.strip()[:200], "string"))
    return sorted(set(out), key=lambda b: (b.file, b.line))


def findings(baits: list[Bait]) -> list[Finding]:
    if not baits:
        return []
    return [finding("PKG.REVIEW.BAIT", f"Code addresses the reviewer ({len(baits)} place(s)): that is itself suspicious", "high", "code", "S5",
                    [ev("file_line", f"{b.file}:{b.line}", f"{b.where}: {b.text}") for b in baits[:8]])]


def neutralise_comments(text: str) -> str:
    """Replace every comment with a fixed placeholder, keeping line numbers, before code is shown to an LLM."""
    lines = text.splitlines()
    try:
        for t in tokenize.generate_tokens(io.StringIO(text).readline):
            if t.type == tokenize.COMMENT:
                row, col = t.start
                lines[row - 1] = lines[row - 1][:col] + "# [comment removed]"
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return "\n".join(lines)
