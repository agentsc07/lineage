"""Where fetched facts come from (REFACTOR_SPEC S0/S2). A `Hub` returns what an authoritative source published about an
artifact; the pipeline records it as `fetched` facts. The HTTP client talks to Hugging Face / PyPI-shaped endpoints, and
`base_url` is configurable so tests, the benchmark and the demo run against `tests/fakehub.py` instead of the internet."""
from __future__ import annotations

import os
from typing import Protocol

import httpx


class Hub(Protocol):
    def fetch(self, artifact_type: str, key: str) -> dict | None:
        """Metadata for `key` (a claimed origin such as `hf:org/name`, `pypi:name==1.0`, or an artifact name), in the shape
        the package/provenance inspectors read: `released_at`, `licence`, `repo`, `claimed_base`, `urls`, ... None: unknown."""


class HttpHub:
    """Reads `GET {base_url}/lineage-meta/{artifact_type}/{key}` (served by the fake hub and by a real deployment's gateway)."""

    def __init__(self, base_url: str | None = None, timeout: float = 10.0):
        self.base_url = (base_url or os.environ.get("LINEAGE_HUB_URL", "")).rstrip("/")
        self.timeout = timeout

    def fetch(self, artifact_type: str, key: str) -> dict | None:
        if not self.base_url:
            return None
        try:
            r = httpx.get(f"{self.base_url}/lineage-meta/{artifact_type}/{key}", timeout=self.timeout)
        except httpx.HTTPError:
            return None
        return r.json() if r.status_code == 200 else None


def default_hub() -> Hub | None:
    return HttpHub() if os.environ.get("LINEAGE_HUB_URL") else None
