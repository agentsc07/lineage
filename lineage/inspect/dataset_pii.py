"""Dataset personal-data scan (regex) (Track C).

Reports counts and masked examples only; raw personal data is never copied into a finding.
"""
from __future__ import annotations

import re
from pathlib import Path

from lineage.inspect._common import ev, finding
from lineage.inspect._tabular import TEXT_SUFFIXES, data_files
from lineage.schemas.finding import Finding, Severity

MAX_BYTES_PER_FILE = 200 * 1024 * 1024
MAX_EXAMPLES = 3

_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
      [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1], [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
      [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
      [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1], [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_valid(number: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(base: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(base)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])


def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number][::-1]
    total = sum(d if i % 2 == 0 else (d * 2 - 9 if d * 2 > 9 else d * 2) for i, d in enumerate(digits))
    return total % 10 == 0 and len(digits) >= 13


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


# kind -> (regex, validator, severity, title)
DETECTORS: dict[str, tuple[re.Pattern, object, Severity, str]] = {
    "private_key": (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), None, "critical", "private keys"),
    "api_secret": (re.compile(r"\b(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{20,}|xox[bp]-[A-Za-z0-9-]{20,})\b"), None, "critical", "API keys / tokens"),
    "ssn": (re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), None, "high", "US social security numbers"),
    "credit_card": (re.compile(r"\b(?:\d[ -]?){13,19}\b"), lambda m: luhn_valid(_digits(m)), "high", "payment card numbers"),
    "aadhaar": (re.compile(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b"), lambda m: verhoeff_valid(_digits(m)), "high", "Aadhaar numbers"),
    "pan": (re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), None, "high", "Indian PAN numbers"),
    "email": (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"), None, "medium", "email addresses"),
    "phone": (re.compile(r"(?<![\w.])(?:\+?91[ -]?)?[6-9]\d{9}\b|(?<![\w.])(?:\+?1[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4}\b"), None, "medium", "phone numbers"),
    "ip_address": (re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), lambda v: _public_ip(v), "low", "public IP addresses"),
}


def _public_ip(v: str) -> bool:
    """Loopback, private, link-local and documentation addresses (127.x, 10.x, 192.168.x, 192.0.2.x) identify nobody; only a routable one counts."""
    import ipaddress
    try:
        return ipaddress.ip_address(v).is_global
    except ValueError:
        return False


def mask(s: str) -> str:
    s = s.strip()
    return s[:1] + "*" * max(len(s) - 3, 1) + s[-2:] if len(s) > 3 else "***"


def scan_lines(lines, rel: str, counts: dict[str, int], examples: dict[str, list[tuple[str, str]]]) -> None:
    for n, line in enumerate(lines, 1):
        for kind, (rx, check, _, _) in DETECTORS.items():
            for m in rx.finditer(line):
                if check is not None and not check(m.group(0)):
                    continue
                counts[kind] = counts.get(kind, 0) + 1
                if len(examples.setdefault(kind, [])) < MAX_EXAMPLES:
                    examples[kind].append((f"{rel}:{n}", mask(m.group(0))))


def scan(dataset_path: Path) -> list[Finding]:
    counts: dict[str, int] = {}
    examples: dict[str, list[tuple[str, str]]] = {}
    root = Path(dataset_path)
    for f in data_files(root, TEXT_SUFFIXES):
        if f.stat().st_size > MAX_BYTES_PER_FILE:
            continue
        rel = f.name if root.is_file() else f.relative_to(root).as_posix()
        with f.open(errors="replace") as fh:
            scan_lines(fh, rel, counts, examples)
    out: list[Finding] = []
    for kind, n in counts.items():
        _, _, sev, title = DETECTORS[kind]
        out.append(finding(f"DATA.PII.{kind.upper()}", f"{n} {title} found in the data", sev, "data", "S3",
                           [ev("file_line", ref, f"{kind}: {m}") for ref, m in examples[kind]]))
    return sorted(out, key=lambda f: -f.score)
