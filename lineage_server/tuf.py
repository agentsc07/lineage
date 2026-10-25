"""TUF-style policy updates: role keys, 2-of-3 threshold, expiring metadata, no rollback (Track B)."""
from __future__ import annotations

from lineage.schemas.artifact import PolicyUpdate

ROLES = ("owner", "security", "compliance")
THRESHOLD = 2


def verify_update(update: PolicyUpdate, current_version: str, role_keys: dict[str, str]) -> None:
    """Raise ValueError unless >= THRESHOLD distinct roles signed, metadata is unexpired and not a rollback."""
    raise NotImplementedError
