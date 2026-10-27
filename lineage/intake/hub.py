"""Where fetched facts and published hashes come from (REFACTOR_SPEC S0/S2). A `Hub` returns what an authoritative source
published about an artifact. `base_url` is configurable so tests, the benchmark and the demo run against `tests/fakehub.py`
instead of the internet."""
from __future__ import annotations

import os
from typing import Protocol

import httpx

from lineage.intake import fetch


class Hub(Protocol):
    trusted_local: bool  # test/bench/demo stand-in: its records describe the local bytes as given, no origin claim needed

    def fetch(self, artifact_type: str, key: str) -> dict | None:
        """Metadata for `key` (a claimed origin such as `hf:org/name@rev`, or an artifact name), in the shape the inspectors
        read: `released_at`, `licence`, `repo`, `claimed_base`, `urls`, ... None: unknown."""

    def published_files(self, origin: str) -> dict[str, dict] | None:
        """path -> {sha256?, git_oid?, size} as published at the pinned revision; None if it cannot be checked."""


class HttpHub:
    """Hugging Face / PyPI shaped HTTP hub. Metadata for a claimed origin comes from the hub's own API at that revision; for a
    bare key it reads `GET {base}/lineage-meta/{type}/{key}` (the fake hub's stand-in records)."""

    def __init__(self, base_url: str | None = None, timeout: float = 10.0, client: httpx.Client | None = None,
                 trusted_local: bool | None = None):
        self.base_url = (base_url or os.environ.get("LINEAGE_HUB_URL", "")).rstrip("/")
        self.timeout, self.client = timeout, client
        self.trusted_local = os.environ.get("LINEAGE_HUB_TRUSTED_LOCAL") == "1" if trusted_local is None else trusted_local

    def _get(self, url: str):
        return (self.client or httpx).get(url, timeout=self.timeout)

    def fetch(self, artifact_type: str, key: str) -> dict | None:
        if not self.base_url:
            return None
        try:
            if key.startswith(("hf:", "hf-dataset:")):
                kind, repo, rev = fetch.parse_origin(key)
                info = fetch.hf_info(repo, rev, kind, self.base_url, self.client)
                card = info.get("cardData") or {}
                return {k: v for k, v in {"repo": repo, "publisher": repo.split("/")[0], "source_revision": info.get("sha"),
                                          "released_at": info.get("lastModified"), "licence": card.get("license"),
                                          "claimed_base": card.get("base_model") if isinstance(card.get("base_model"), str) else None}.items() if v}
            if key.startswith("pypi:"):
                r = self._get(f"{fetch.pypi_url(self.base_url)}/{key[5:].replace('==', '/')}/json")
                return r.json() if r.status_code == 200 else None
            r = self._get(f"{self.base_url}/lineage-meta/{artifact_type}/{key}")
        except (httpx.HTTPError, fetch.AcquireError, ValueError):
            return None
        return r.json() if r.status_code == 200 else None

    def published_files(self, origin: str) -> dict[str, dict] | None:
        return fetch.published_files(origin, self.base_url or None, self.client) if self.base_url else None


def default_hub() -> Hub | None:
    return HttpHub() if os.environ.get("LINEAGE_HUB_URL") else None
