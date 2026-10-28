"""Decision attestation: the registry's signed statement that an artifact may be used in an environment (REFACTOR_SPEC 3.4).

`lineage.load()`, the package index and the gateway trust this and nothing the artifact ships with."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from lineage.schemas.passport import TrustLevel


class Attestation(BaseModel):
    artifact_id: str
    digest: str  # Merkle root of the admitted bytes
    files: dict[str, str] = Field(default_factory=dict)  # path -> sha256
    outcome: Literal["allow", "allow_with_conditions", "quarantine", "block"]
    environment: str
    trust: TrustLevel
    policy_version: str
    issued_at: datetime
    expires_at: datetime
    revoked: bool = False

    @property
    def usable(self) -> bool:
        return not self.revoked and self.outcome in ("allow", "allow_with_conditions")


class AttestationStatus(BaseModel):
    """The registry's answer *now* to "may this artifact be used in this environment?" (GET /attestations/{id}/status). A cached
    attestation can be days old; this is what the loader asks before it trusts one."""
    artifact_id: str
    environment: str
    revoked: bool
    ancestor_revoked: list[str] = Field(default_factory=list)  # ids of revoked ancestors (parents, datasets, packages, ghosts)
    current_outcome: Literal["allow", "allow_with_conditions", "quarantine", "block"]
    usable: bool  # not revoked, no revoked ancestor, current outcome allow / allow_with_conditions


class SignedAttestation(BaseModel):
    attestation: Attestation
    signature: str  # base64 Ed25519 over canonical JSON of `attestation`
    key_id: str
