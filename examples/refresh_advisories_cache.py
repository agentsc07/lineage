"""Refresh examples/advisories_cache.json from OSV (needs internet).

    uv run python examples/refresh_advisories_cache.py litellm==1.82.7 litellm==1.107.0
"""
from __future__ import annotations

import datetime
import json
import sys
from pathlib import Path

import httpx

OUT = Path(__file__).parent / "advisories_cache.json"


def fetch(name: str, version: str) -> list[dict]:
    vulns: list[dict] = []
    body: dict = {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
    while True:
        r = httpx.post("https://api.osv.dev/v1/query", json=body, timeout=20)
        r.raise_for_status()
        data = r.json()
        vulns += data.get("vulns", [])
        if not data.get("next_page_token"):
            return vulns
        body["page_token"] = data["next_page_token"]


def slim(v: dict) -> dict:
    sev = (v.get("database_specific") or {}).get("severity")
    return {"id": v.get("id"), "aliases": v.get("aliases", []),
            "summary": (v.get("summary") or (v.get("details") or "").split("\n")[0])[:200],
            "database_specific": {"severity": sev} if sev else {}}


def main(specs: list[str]) -> None:
    doc = json.loads(OUT.read_text()) if OUT.exists() else {"advisories": {}}
    for spec in specs:
        name, version = spec.split("==")
        doc["advisories"][f"PyPI|{name.lower()}|{version}"] = [slim(v) for v in fetch(name, version)]
    doc["_comment"] = ("Snapshot of OSV records used when OSV is unreachable and nothing is cached. "
                       "Refresh with examples/refresh_advisories_cache.py. Key: ecosystem|name|version.")
    doc["fetched"] = datetime.date.today().isoformat()
    OUT.write_text(json.dumps(doc, indent=1))


if __name__ == "__main__":
    main(sys.argv[1:])
