"""PolicyPack + evidence -> Decision (Track B)."""
from __future__ import annotations

from datetime import datetime

from lineage.schemas.decision import Decision
from lineage.schemas.finding import Finding
from lineage.schemas.passport import PassportBody
from lineage.schemas.policy import PolicyPack


def decide(
    passport: PassportBody,
    findings: list[Finding],
    environment: str,
    policy: PolicyPack,
    now: datetime | None = None,
) -> Decision:
    """Hard blocks first (pickle when disallowed, banned capability, blocked publisher, signature failure,
    hash mismatch, revoked parent), then cooldown, trust/risk per environment, exceptions with expiry."""
    raise NotImplementedError
