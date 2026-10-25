"""Package provenance: release age vs cooldown, source repo vs metadata, look-alike names, maintainer change (Track C)."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from lineage.inspect._common import ev, finding
from lineage.inspect._text import damerau_levenshtein
from lineage.schemas.finding import Finding
from lineage.schemas.policy import PolicyPack

TOP_LIST = Path(__file__).parent / "data" / "top_pypi_5k.txt"
_REPO = re.compile(r"(?:github|gitlab|bitbucket)\.(?:com|org)[/:]+([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/#?]|$)", re.I)


@lru_cache(maxsize=1)
def top_packages() -> tuple[str, ...]:
    return tuple(TOP_LIST.read_text().split())


def normalise(name: str) -> str:
    """PEP 503 normalisation."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _squash(name: str) -> str:
    return re.sub(r"[-_.]+", "", name.lower())


def lookalikes(name: str, top: tuple[str, ...] | None = None) -> list[tuple[str, int, str]]:
    """(popular name, distance, reason) for popular names this one imitates. Empty if the name is itself popular."""
    top = top if top is not None else top_packages()
    norm, sq = normalise(name), _squash(name)
    if norm in top:
        return []
    out = []
    for cand in top:
        csq = _squash(cand)
        if sq == csq:
            out.append((cand, 0, "differs only in separators"))
            continue
        limit = 0 if len(csq) <= 3 else 1 if len(csq) < 9 else 2
        if limit == 0 or abs(len(csq) - len(sq)) > limit:
            continue
        d = damerau_levenshtein(sq, csq, limit)
        if d <= limit:
            transposed = sorted(sq) == sorted(csq)
            out.append((cand, d, "transposed characters" if transposed else f"{d} edit(s) away"))
    return sorted(out, key=lambda x: (x[1], x[0]))[:3]


def _info(meta: dict) -> dict:
    return meta.get("info", meta)


def _release_time(meta: dict) -> datetime | None:
    stamps = [u.get("upload_time_iso_8601") or u.get("upload_time") for u in meta.get("urls", [])]
    stamps += [meta.get("upload_time")]
    parsed = []
    for s in filter(None, stamps):
        try:
            dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        except ValueError:
            continue
        parsed.append(dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc))
    return min(parsed) if parsed else None


def _repos(meta: dict) -> set[tuple[str, str]]:
    info = _info(meta)
    urls = [*(info.get("project_urls") or {}).values(), info.get("home_page"), info.get("download_url")]
    return {(m.group(1), m.group(2)) for u in urls if u for m in [_REPO.search(str(u))] if m}


def _build_repo(meta: dict) -> tuple[str, str] | None:
    """Repository the release was built from, per PyPI attestations / trusted publishing metadata."""
    prov = meta.get("provenance") or {}
    repo = prov.get("repository") or prov.get("source_repo") or prov.get("build_repo")
    m = _REPO.search(str(repo)) if repo else None
    return (m.group(1), m.group(2)) if m else None


def _fold(s: str) -> str:
    return re.sub(r"[-_.]", "", s.lower())


def _relation(a: tuple[str, str], b: tuple[str, str]) -> str:
    """same | lookalike (differs only in case-insensitive separators, e.g. Berri-AI vs BerriAI) | different."""
    if [x.lower() for x in a] == [x.lower() for x in b]:
        return "same"
    if _fold(a[0]) == _fold(b[0]) and _fold(a[1]) == _fold(b[1]):
        return "lookalike"
    return "different"


def _people(meta: dict) -> set[str]:
    info = _info(meta)
    vals = [info.get(k) for k in ("author", "author_email", "maintainer", "maintainer_email")]
    vals += [m if isinstance(m, str) else (m or {}).get("name") or (m or {}).get("email") for m in meta.get("maintainers", [])]
    return {str(v).strip().lower() for v in vals if v}


def scan(
    name: str,
    version: str,
    metadata: dict,
    policy: PolicyPack,
    *,
    previous_metadata: dict | None = None,
    now: datetime | None = None,
) -> list[Finding]:
    """`metadata` is the registry JSON (e.g. PyPI /pypi/<name>/<version>/json)."""
    out: list[Finding] = []
    ref = f"{name}@{version}"

    # release age vs cooldown
    cooldown = policy.cooldown_days.get("package")
    released = _release_time(metadata)
    if cooldown and released:
        now = now or datetime.now(timezone.utc)
        age = (now - released).total_seconds() / 86400
        if age < cooldown:
            sev = "high" if age < 1 or age < cooldown / 2 else "medium"
            hours = f"{age * 24:.0f} hours" if age < 2 else f"{age:.1f} days"
            out.append(finding("PKG.PROV.COOLDOWN", f"Release is only {hours} old (cooldown is {cooldown} days)", sev,
                               "provenance", "S2", [ev("field", f"{ref}#upload_time", released.isoformat())]))

    # source repo vs metadata (the look-alike repo behind the LiteLLM 1.107.0 release)
    declared, build = _repos(metadata), _build_repo(metadata)
    prev_declared = _repos(previous_metadata) if previous_metadata else set()
    comparisons: list[tuple[str, tuple[str, str], str, set[tuple[str, str]]]] = []
    if build and declared:
        comparisons.append(("build repository", build, "declared repository", declared))
    if declared and prev_declared:
        for d in declared:
            comparisons.append(("declared repository", d, "previous declared repository", prev_declared))
    for label, repo, other_label, others in comparisons:
        relations = {_relation(repo, o) for o in others}
        if "same" in relations:
            continue
        other = "/".join(sorted(others)[0])
        if "lookalike" in relations:
            out.append(finding("PKG.PROV.LOOKALIKE_REPO", f"{label} {'/'.join(repo)} looks like {other_label} {other} but is not the same",
                               "critical", "provenance", "S2", [ev("url", "/".join(repo), f"vs {other}")]))
        else:
            out.append(finding("PKG.PROV.REPO_MISMATCH", f"{label} {'/'.join(repo)} differs from {other_label} {other}",
                               "high", "provenance", "S2", [ev("url", "/".join(repo), f"vs {other}")]))
    if len({_fold(o) for o, _ in declared}) > 1:
        out.append(finding("PKG.PROV.REPO_INCONSISTENT", "Metadata links to repositories owned by different accounts",
                           "medium", "provenance", "S2", [ev("field", f"{ref}#project_urls", ", ".join(sorted("/".join(d) for d in declared)))]))

    # look-alike package names
    for cand, dist, why in lookalikes(name)[:1]:
        sev = "high" if dist == 0 or "transposed" in why else "medium"
        out.append(finding("PKG.PROV.LOOKALIKE_NAME", f"Name '{name}' imitates popular package '{cand}' ({why})", sev,
                           "provenance", "S2", [ev("field", f"{name}#name", f"similar to {cand}, distance {dist}")]))

    # maintainer change
    if previous_metadata:
        now_people, before = _people(metadata), _people(previous_metadata)
        if now_people and before and not (now_people & before):
            out.append(finding("PKG.PROV.MAINTAINER_CHANGED", "Author/maintainer changed since the previous version",
                               "medium", "provenance", "S2",
                               [ev("field", f"{ref}#author", f"{sorted(before)} -> {sorted(now_people)}")]))
    return out
