"""Benchmark stand-in for a hub: serves the `lineage.meta.json` that each corpus item carries as *fetched* facts, so the
benchmark keeps its semantics now that intake treats that file inside an artifact as merely declared (REFACTOR_SPEC 3.2).
Test and bench only; production never trusts a file inside the artifact."""
from __future__ import annotations

import json
from pathlib import Path


class MetaFileHub:
    trusted_local = True  # the bench vouches for its own corpus items (a stand-in for "Lineage fetched these from the hub")

    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path else None  # the artifact folder; the pipeline only passes the folder's name as the key

    def fetch(self, artifact_type: str, key: str) -> dict | None:
        p = self.path or Path(key)
        meta = (p if p.is_dir() else p.parent) / "lineage.meta.json"
        return json.loads(meta.read_text()) if meta.is_file() else {}
