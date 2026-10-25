"""OSV client with cache: vulnerabilities and MAL advisories (Track C)."""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import httpx

from lineage.inspect._common import ev, finding
from lineage.schemas.finding import Finding, Severity

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
DEFAULT_CACHE = Path.home() / ".cache" / "lineage" / "osv"
DEFAULT_TTL = 6 * 3600  # seconds; the Monitor passes ttl=0 to force a re-query
MAX_VULN_FINDINGS = 20
_SEVERITY: dict[str, Severity] = {"LOW": "low", "MODERATE": "medium", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical"}


def _cache_path(cache_dir: Path, ecosystem: str, name: str, version: str) -> Path:
    key = hashlib.sha256(f"{ecosystem}|{name.lower()}|{version}".encode()).hexdigest()
    return cache_dir / f"{key}.json"


def query(
    name: str,
    version: str,
    ecosystem: str = "PyPI",
    cache_dir: Path | None = None,
    *,
    client: httpx.Client | None = None,
    ttl: float = DEFAULT_TTL,
) -> list[dict]:
    """All OSV records for one package version. Raises httpx.HTTPError only if offline and nothing is cached."""
    if client is None and os.environ.get("LINEAGE_OFFLINE"):  # hermetic tests / air-gapped installs
        raise httpx.ConnectError("LINEAGE_OFFLINE is set")
    cache_dir = Path(cache_dir) if cache_dir is not None else DEFAULT_CACHE
    path = _cache_path(cache_dir, ecosystem, name, version)
    cached = None
    if path.exists():
        try:
            cached = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            cached = None
    if cached and time.time() - cached["fetched_at"] <= ttl:
        return cached["vulns"]
    own = client is None
    http = client or httpx.Client(timeout=10)
    try:
        vulns: list[dict] = []
        body: dict = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
        while True:
            r = http.post(OSV_QUERY_URL, json=body)
            r.raise_for_status()
            data = r.json()
            vulns.extend(data.get("vulns", []))
            if not data.get("next_page_token"):
                break
            body["page_token"] = data["next_page_token"]
    except httpx.HTTPError:
        if cached:  # stale beats nothing when offline
            return cached["vulns"]
        raise
    finally:
        if own:
            http.close()
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"fetched_at": time.time(), "vulns": vulns}))
    except OSError:
        pass
    return vulns


def _severity(vuln: dict) -> Severity:
    raw = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    if raw in _SEVERITY:
        return _SEVERITY[raw]
    for aff in vuln.get("affected", []):
        raw = str((aff.get("ecosystem_specific") or {}).get("severity", "")).upper()
        if raw in _SEVERITY:
            return _SEVERITY[raw]
    return "medium"


def _is_malicious(vuln: dict) -> bool:
    return any(i.startswith("MAL-") for i in [vuln.get("id", ""), *vuln.get("aliases", [])])


def scan(
    name: str,
    version: str,
    ecosystem: str = "PyPI",
    cache_dir: Path | None = None,
    *,
    client: httpx.Client | None = None,
    ttl: float = DEFAULT_TTL,
) -> list[Finding]:
    if version.strip() in ("", "0", "0.0", "0.0.0", "unknown"):
        # OSV treats 0.0.0 as older than every fix and answers with every advisory ever filed for the package.
        return [finding("PKG.OSV.VERSION_UNKNOWN", f"OSV lookup skipped: no real version for {name}", "info", "integrity", "S3",
                        [ev("field", f"{ecosystem}/{name}@{version}", "placeholder version")])]
    try:
        vulns = query(name, version, ecosystem, cache_dir, client=client, ttl=ttl)
    except httpx.HTTPError as e:
        return [finding("PKG.OSV.UNAVAILABLE", "OSV lookup skipped (service unreachable)", "info", "integrity", "S3",
                        [ev("field", f"{ecosystem}/{name}@{version}", type(e).__name__)])]
    out: list[Finding] = []
    for v in sorted(vulns, key=lambda v: (not _is_malicious(v), v.get("id", ""))):
        vid = v.get("id", "?")
        summary = (v.get("summary") or v.get("details") or "").strip().splitlines()[0:1]
        evidence = [ev("url", f"https://osv.dev/vulnerability/{vid}", summary[0][:200] if summary else "")]
        if _is_malicious(v):
            out.append(finding("PKG.OSV.MALICIOUS", f"{name}@{version} is listed as a malicious package ({vid})",
                               "critical", "integrity", "S3", evidence))
        elif len(out) < MAX_VULN_FINDINGS:
            sev = _severity(v)
            out.append(finding("PKG.OSV.VULN", f"Known vulnerability {vid} in {name}@{version}", sev, "code", "S3", evidence))
    return out
