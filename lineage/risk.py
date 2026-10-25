"""Findings -> risk score (BUILD_PLAN §3) (Track B)."""
from __future__ import annotations

from lineage.schemas.finding import Finding
from lineage.schemas.passport import TrustLevel

SEVERITY_WEIGHT = {"info": 0, "low": 5, "medium": 12, "high": 25, "critical": 40}
TRUST_PENALTY = {"unknown": 15, "declared": 5}


def risk_score(findings: list[Finding], trust_level: TrustLevel) -> int:
    """min(100, sum(finding.score)) plus the trust-level penalty."""
    raise NotImplementedError
