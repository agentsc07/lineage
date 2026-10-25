"""Decision: the policy engine's verdict on one artifact in one environment (BUILD_PLAN §2.4)."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from lineage.schemas.finding import Finding
from lineage.schemas.passport import TrustLevel

Outcome = Literal["allow", "allow_with_conditions", "quarantine", "block"]


class Decision(BaseModel):
    artifact_id: str
    environment: str
    outcome: Outcome
    reasons: list[str] = Field(default_factory=list)
    conditions: list[str] = Field(default_factory=list)  # e.g. "dev only", "sandbox only"
    risk_score: int = Field(ge=0, le=100)
    trust_level: TrustLevel
    findings: list[Finding] = Field(default_factory=list)
    policy_version: str
    decided_at: datetime
    approver: str | None = None
