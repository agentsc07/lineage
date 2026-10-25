"""Intake pipeline S1-S7 per artifact type (Track B)."""
from __future__ import annotations

from typing import Iterator

from lineage.schemas.artifact import StageEvent
from lineage.schemas.passport import ArtifactType
from lineage.schemas.policy import PolicyPack


def run_intake(
    artifact_type: ArtifactType,
    ref: str,
    environment: str,
    policy: PolicyPack,
    job_id: str,
) -> Iterator[StageEvent]:
    """Run stages in order, yielding one StageEvent per stage transition. The last event carries the Decision.

    Inspectors are looked up from a registry; GPU-worker failures degrade to an `info` Finding, never an exception.
    """
    raise NotImplementedError
