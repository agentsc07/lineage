"""Benchmark stand-in for a hub: serves the `lineage.meta.json` that each corpus item carries as *fetched* facts, so the
benchmark keeps its semantics now that intake treats that file inside an artifact as merely declared (REFACTOR_SPEC 3.2).
Test and bench only; production never trusts a file inside the artifact."""
from __future__ import annotations

import json
from pathlib import Path


class MetaFileHub:
    def fetch(self, artifact_type: str, key: str) -> dict | None:
        p = Path(key)
        meta = (p if p.is_dir() else p.parent) / "lineage.meta.json"
        return json.loads(meta.read_text()) if meta.is_file() else {}
