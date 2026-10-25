"""Package provenance: release age vs cooldown, source repo vs metadata, look-alike names, maintainer change (Track C)."""
from __future__ import annotations

from lineage.schemas.finding import Finding
from lineage.schemas.policy import PolicyPack


def scan(name: str, version: str, metadata: dict, policy: PolicyPack) -> list[Finding]:
    """`metadata` is the registry JSON (e.g. PyPI /pypi/<name>/<version>/json)."""
    raise NotImplementedError
