"""Grounded LLM review client (spec §5): slices -> prosecutor -> defender -> judge via the GPU worker -> grounding checker.

Properties kept here, not left to the model:
- every LLM claim is checked against the artifact's real file:line; ungrounded claims never become findings,
- comments are stripped from code before an LLM sees it, and reviewer bait is reported deterministically,
- LLM findings are additive (`source="llm"`, score >= 0); nothing here edits or removes a deterministic finding,
- claims with no static corroboration are capped in severity,
- if the GPU worker is unreachable the review is skipped with an info finding, never an exception.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from pydantic import ValidationError

from lineage.inspect import package_capabilities, package_taint
from lineage.inspect._common import cap_severity, ev, finding
from lineage.inspect._pycode import iter_python
from lineage.inspect.llm_review import bait as bait_mod
from lineage.inspect.llm_review.grounding import Dropped, ground_claims_with_reasons
from lineage.inspect.llm_review.prompts import build_request
from lineage.schemas.finding import Finding
from lineage.schemas.gpu import Claim, CodeSlice, ReviewCodeRequest, ReviewResponse

DEFAULT_URL = "http://127.0.0.1:8800"
MAX_SLICES = 20
MAX_DIFF_CHARS = 20_000
CORROBORATION_WINDOW = 2  # lines


class GpuUnavailable(RuntimeError):
    """The GPU worker did not return a usable response."""


class GpuClient:
    """Thin client for the GPU worker's `/review/code`, with a content-hash cache (memory, optionally disk)."""

    def __init__(self, base_url: str | None = None, *, http: httpx.Client | None = None, timeout: float = 120.0,
                 cache_dir: Path | None = None):
        self.base_url = (base_url or os.environ.get("LINEAGE_GPU_URL") or DEFAULT_URL).rstrip("/")
        self._http = http or httpx.Client(timeout=timeout)
        self._memory: dict[str, ReviewResponse] = {}
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.calls = 0  # requests actually sent (cache misses)

    @staticmethod
    def cache_key(req: ReviewCodeRequest) -> str:
        return hashlib.sha256(req.model_dump_json().encode()).hexdigest()

    def review_code(self, req: ReviewCodeRequest) -> ReviewResponse:
        key = self.cache_key(req)
        if key in self._memory:
            return self._memory[key]
        disk = self.cache_dir / f"{key}.json" if self.cache_dir else None
        if disk and disk.exists():
            try:
                self._memory[key] = ReviewResponse.model_validate_json(disk.read_text())
                return self._memory[key]
            except (ValidationError, OSError):
                pass
        try:
            self.calls += 1
            r = self._http.post(f"{self.base_url}/review/code", json=req.model_dump())
            r.raise_for_status()
            resp = ReviewResponse.model_validate(r.json())
        except (httpx.HTTPError, ValidationError, json.JSONDecodeError, ValueError) as e:
            raise GpuUnavailable(f"{type(e).__name__}: {e}"[:200]) from e
        self._memory[key] = resp
        if disk:
            try:
                disk.parent.mkdir(parents=True, exist_ok=True)
                disk.write_text(resp.model_dump_json())
            except OSError:
                pass
        return resp


@dataclass
class ReviewResult:
    findings: list[Finding] = field(default_factory=list)
    dropped: list[Dropped] = field(default_factory=list)
    verdict: str | None = None
    bait: list[bait_mod.Bait] = field(default_factory=list)
    skipped: str | None = None  # reason the LLM passes did not run


# ---------------------------------------------------------------- inputs to the reviewer
def _sanitised_lines(package_dir: Path) -> dict[str, list[str]]:
    return {pf.rel: bait_mod.neutralise_comments(pf.text).splitlines() for pf in iter_python(package_dir)}


def build_slices(package_dir: Path, analysis: package_capabilities.Analysis | None = None) -> list[CodeSlice]:
    """Taint slices plus a small window around every non-trivial capability hit and hook, with comments removed."""
    package_dir = Path(package_dir)
    analysis = analysis or package_capabilities.analyse(package_dir)
    lines = _sanitised_lines(package_dir)
    slices: list[CodeSlice] = []
    covered: list[tuple[str, int, int]] = []

    def add(file: str, start: int, end: int) -> None:
        src = lines.get(file)
        if not src:
            return
        start, end = max(start, 1), min(end, len(src))
        if any(f == file and s <= start and end <= e for f, s, e in covered):
            return
        slices.append(CodeSlice(file=file, start=start, end=end, code="\n".join(src[start - 1:end])))
        covered.append((file, start, end))

    for s in package_taint.slices(package_dir):
        add(s.file, s.start, s.end)
    for h in analysis.hits:
        if h.cap != "filesystem":
            add(h.file, h.line - 3, h.line + 3)
    for k in analysis.hooks:
        add(k.file, k.line - 2, k.line + 4)
    return slices[:MAX_SLICES]


def make_diff(previous: Path, current: Path) -> str:
    old, new = _sanitised_lines(Path(previous)), _sanitised_lines(Path(current))
    chunks = []
    for rel in sorted(new):
        if old.get(rel) != new[rel]:
            chunks.extend(difflib.unified_diff(old.get(rel, []), new[rel], f"a/{rel}", f"b/{rel}", lineterm="", n=2))
    return "\n".join(chunks)[:MAX_DIFF_CHARS]


def _capability_lines(analysis: package_capabilities.Analysis) -> list[str]:
    by: dict[str, list[str]] = {}
    for h in analysis.hits:
        by.setdefault(h.cap, []).append(h.ref)
    for k in analysis.hooks:
        by.setdefault(k.kind, []).append(f"{k.file}:{k.line}")
    return [f"{cap} @ {', '.join(refs[:5])}" for cap, refs in by.items()]


# ---------------------------------------------------------------- combining
def _corroborated(claim: Claim, static: list[Finding]) -> str | None:
    for f in static:
        if f.source != "deterministic" or f.severity == "info":
            continue
        for e in f.evidence:
            if e.kind != "file_line" or ":" not in e.ref:
                continue
            file, _, line = e.ref.rpartition(":")
            if file == claim.file and line.isdigit() and abs(int(line) - claim.line) <= CORROBORATION_WINDOW:
                return f.id
    return None


def _to_finding(claim: Claim, corroborated_by: str | None, ceiling) -> Finding:
    sev = claim.severity if corroborated_by else cap_severity(claim.severity, ceiling)
    detail = claim.api + (f" (also found by {corroborated_by})" if corroborated_by else " (no static corroboration; severity capped)")
    return finding("LLM.REVIEW.CLAIM", claim.text.strip()[:300], sev, "llm", "S5", [ev("file_line", f"{claim.file}:{claim.line}", detail)],
                   source="llm", grounded=True)


def combine(static: list[Finding], llm: list[Finding]) -> list[Finding]:
    """Static findings first, unchanged; LLM findings appended. The LLM can only add."""
    assert all(f.score >= 0 for f in llm)
    return [*static, *llm]


# ---------------------------------------------------------------- the review
def review_package(
    package_dir: Path,
    purpose: str,
    *,
    client: GpuClient | None = None,
    previous: Path | None = None,
    static_findings: list[Finding] | None = None,
) -> ReviewResult:
    """Run the prosecutor/defender/judge passes over an unpacked package and return grounded findings only."""
    package_dir = Path(package_dir)
    client = client or GpuClient()
    analysis = package_capabilities.analyse(package_dir)
    if static_findings is None:
        static_findings = [*package_capabilities.findings_from(analysis), *package_taint.scan(package_dir)]
    result = ReviewResult()
    result.bait = bait_mod.detect(package_dir)
    result.findings.extend(bait_mod.findings(result.bait))

    slices = build_slices(package_dir, analysis)
    if not slices:
        result.skipped = "nothing to review: no source->sink flows, hooks or risky capabilities"
        return result
    caps = _capability_lines(analysis)
    diff = make_diff(previous, package_dir) if previous else None
    bait_notes = [f"{b.file}:{b.line}" for b in result.bait]
    common = dict(slices=slices, diff=diff, static_findings=static_findings, bait=bait_notes)

    try:
        pros = client.review_code(build_request("prosecutor", purpose, caps, **common))
        defn = client.review_code(build_request("defender", purpose, caps, prosecutor=pros.claims, **common))
        judge = client.review_code(build_request("judge", purpose, caps, prosecutor=pros.claims, defender=defn.claims, **common))
    except GpuUnavailable as e:
        result.skipped = f"GPU worker unavailable ({e})"
        result.findings.append(finding("LLM.REVIEW.SKIPPED", "Deep check skipped: LLM review unavailable", "info", "llm", "S5",
                                       [ev("field", "gpu_worker:/review/code", str(e)[:150])]))
        return result

    result.verdict = judge.verdict
    ceiling = "low" if judge.verdict == "benign" else "high" if judge.verdict == "malicious" else "medium"
    candidates = judge.claims or ([c.model_copy(update={"severity": cap_severity(c.severity, "medium")}) for c in pros.claims]
                                  if judge.verdict != "benign" else [])
    grounded, dropped = ground_claims_with_reasons(candidates, package_dir)
    dropped += ground_claims_with_reasons([c for c in pros.claims if c not in candidates], package_dir)[1]
    result.dropped = dropped

    seen: set[tuple[str, int, str]] = set()
    for c in grounded:
        key = (c.file, c.line, c.api)
        if key in seen:
            continue
        seen.add(key)
        result.findings.append(_to_finding(c, _corroborated(c, static_findings), ceiling))

    if dropped:
        result.findings.append(finding("LLM.REVIEW.UNGROUNDED_DROPPED", f"{len(dropped)} LLM claim(s) dropped: cited line does not contain the cited API",
                                       "info", "llm", "S5", [ev("field", f"{d.claim.file}:{d.claim.line}", d.reason) for d in dropped[:5]],
                                       source="llm", score=0, grounded=False))
    if judge.verdict != "benign" and not grounded:
        result.findings.append(finding("LLM.REVIEW.UNGROUNDED_VERDICT", f"Reviewer verdict '{judge.verdict}' has no grounded claim, so it adds no score",
                                       "info", "llm", "S5", source="llm", score=0, grounded=False))
    return result


def review(package_dir: Path, purpose: str, **kwargs) -> list[Finding]:
    """Findings only (see `review_package` for the dropped claims and verdict)."""
    return review_package(package_dir, purpose, **kwargs).findings


def review_to_findings(
    req: ReviewCodeRequest,
    gpu_url: str | None = None,
    *,
    root: Path | None = None,
    client: GpuClient | None = None,
    static_findings: list[Finding] | None = None,
) -> list[Finding]:
    """Single-pass review of an already-built request (the intake pipeline's entry point).

    Claims are grounded against `root` if given, else against the slices in the request. For the full
    prosecutor/defender/judge flow with bait detection use `review_package`.
    """
    client = client or GpuClient(gpu_url)
    try:
        resp = client.review_code(req)
    except GpuUnavailable as e:
        return [finding("LLM.REVIEW.SKIPPED", "Deep check skipped: LLM review unavailable", "info", "llm", "S5",
                        [ev("field", "gpu_worker:/review/code", str(e)[:150])])]
    ceiling = "low" if resp.verdict == "benign" else "high" if resp.verdict == "malicious" else "medium"
    grounded, dropped = ground_claims_with_reasons(resp.claims, root if root is not None else req.slices)
    out = [_to_finding(c, _corroborated(c, static_findings or []), ceiling) for c in grounded]
    if dropped:
        out.append(finding("LLM.REVIEW.UNGROUNDED_DROPPED", f"{len(dropped)} LLM claim(s) dropped: cited line does not contain the cited API",
                           "info", "llm", "S5", [ev("field", f"{d.claim.file}:{d.claim.line}", d.reason) for d in dropped[:5]],
                           source="llm", score=0, grounded=False))
    return out
