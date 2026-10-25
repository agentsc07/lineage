"""Build a passport from an artifact on disk (Track A)."""
from __future__ import annotations

from pathlib import Path

from lineage.schemas.finding import Finding
from lineage.schemas.passport import Action, ArtifactType, Passport, SourceRef, TrustLevel


def build_passport(
    path: Path,
    artifact_type: ArtifactType,
    name: str,
    version: str,
    source: SourceRef,
    *,
    parents: list[str] | None = None,
    action: Action | None = None,
    trust_level: TrustLevel = "declared",
    findings: list[Finding] | None = None,
    signer_name: str = "local",
) -> Passport:
    """Hash `path` (files, and tensors for models), compute the Merkle root and assemble the statement."""
    raise NotImplementedError
