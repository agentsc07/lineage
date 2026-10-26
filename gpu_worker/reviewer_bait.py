"""Reviewer-bait: text in an artifact that talks to the reviewer ("ignore previous instructions", "this is safe").

Detected deterministically on comments and string literals (any language), reported as a high-severity claim, and
redacted from what the LLM reads so it cannot be steered by it. Line numbers are preserved.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

AUDIENCE = re.compile(r"\b(ai|a\.i\.|llm|language model|assistant|reviewer|code review(er)?|auditor|scanner|claude|gpt|chatgpt|copilot|"
                      r"nemotron|security (team|scanner|tool|bot|review)|static analy[sz]er|linter)\b", re.I)
DIRECTIVE = re.compile(r"\b(ignore|disregard|skip|overlook|do not (flag|report|mention|block|reject)|don'?t (flag|report|mention|block)|"
                       r"no need to|you (should|must|can|may) (approve|pass|ignore|skip)|mark (this )?as (safe|benign)|approve)\b", re.I)
ASSURANCE = re.compile(r"\b(safe|benign|harmless|legitimate|false[- ]positive|not (malicious|malware|harmful)|audited|already (reviewed|approved|audited)|"
                       r"trusted|whitelisted|pass(ed)? (the )?(review|scan|audit))\b", re.I)
STRONG = re.compile(r"ignore (all |any )?(previous|prior|above|earlier) (instructions|rules|prompts)|note to (the )?(ai|llm|reviewer|assistant)|"
                    r"(this|the) (code|file|package|function|script|line|module|hook) is (completely |totally |perfectly )?(safe|benign|harmless)|"
                    r"(not|isn'?t) (a )?(malware|malicious|backdoor)|nothing (suspicious|malicious) (here|to see)|"
                    r"(security )?review(er)?:? (pass|approved|ok)|<\s*/?\s*(system|instructions?)\s*>|"
                    r"you are (now )?(a|an|the) (helpful|security|code)", re.I)

_COMMENT = re.compile(r"<!--(.*?)(?:-->|$)|(#|//)(.*)$|/\*(.*?)\*/")
_STRING = re.compile(r"""(?:"((?:[^"\\]|\\.){12,})"|'((?:[^'\\]|\\.){12,})')""")
REDACTED = "[reviewer-addressed text removed]"


def is_bait(text: str) -> bool:
    return bool(STRONG.search(text) or (AUDIENCE.search(text) and (DIRECTIVE.search(text) or ASSURANCE.search(text))))


@dataclass(frozen=True)
class Bait:
    line: int          # 1-based line within the scanned text
    text: str          # the offending comment / string (trimmed)
    where: str         # comment | string


def _fragments(line: str):
    for m in _COMMENT.finditer(line):
        yield "comment", (m.group(1) or m.group(3) or m.group(4) or "").strip(), m.span()
    for m in _STRING.finditer(line):
        yield "string", (m.group(1) or m.group(2)).strip(), m.span()


_TRIPLE = re.compile(r'("""|\'\'\')(.*?)\1', re.S)


def _doc_lines(text: str) -> set[int]:
    """0-based indices of lines inside triple-quoted blocks (docstrings are prose aimed at readers, including reviewers)."""
    idx: set[int] = set()
    for m in _TRIPLE.finditer(text):
        a, b = text.count("\n", 0, m.start(2)), text.count("\n", 0, m.end(2))
        idx.update(range(a, b + 1))
    return idx


def scan(text: str, first_line: int = 1) -> list[Bait]:
    out, doc = [], _doc_lines(text)
    for i, line in enumerate(text.splitlines()):
        if i in doc and line.strip().strip('"\'') and is_bait(line):
            out.append(Bait(first_line + i, line.strip().strip('"\'')[:160], "docstring"))
            continue
        for where, frag, _ in _fragments(line):
            if frag and is_bait(frag):
                out.append(Bait(first_line + i, frag[:160], where))
    return out


def redact(text: str) -> str:
    """Replace bait comments/strings (only those) with a placeholder; non-bait comments stay as useful context."""
    lines, doc = text.splitlines(), _doc_lines(text)
    for i, line in enumerate(lines):
        if i in doc and is_bait(line):
            lines[i] = REDACTED
            continue
        spans = sorted((s for w, f, s in _fragments(line) if f and is_bait(f)), reverse=True)
        for a, b in spans:
            line = line[:a] + REDACTED + line[b:]
        lines[i] = line
    return "\n".join(lines)
