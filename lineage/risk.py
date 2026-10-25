"""Findings -> risk score (BUILD_PLAN §3)."""
from __future__ import annotations

from lineage.schemas.finding import Finding
from lineage.schemas.passport import TrustLevel

SEVERITY_WEIGHT = {"info": 0, "low": 5, "medium": 12, "high": 25, "critical": 40}
TRUST_PENALTY = {"unknown": 15, "declared": 5}


def finding_points(finding: Finding) -> int:
    """What one finding adds. An LLM finding whose citation did not check out adds nothing; no finding ever subtracts."""
    if finding.source == "llm" and not finding.grounded:
        return 0
    return max(0, finding.score)


def risk_score(findings: list[Finding], trust_level: TrustLevel) -> int:
    """min(100, sum(finding.score) + trust-level penalty)."""
    return min(100, sum(finding_points(f) for f in findings) + TRUST_PENALTY.get(trust_level, 0))
