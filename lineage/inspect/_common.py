"""Helpers shared by the scanners: Finding construction with default scores."""
from __future__ import annotations

from lineage.schemas.finding import Category, Evidence, EvidenceKind, Finding, Severity, Source, Stage

SEVERITY_SCORE: dict[str, int] = {"info": 0, "low": 5, "medium": 12, "high": 25, "critical": 40}
SEVERITY_ORDER: tuple[str, ...] = ("info", "low", "medium", "high", "critical")


def ev(kind: EvidenceKind, ref: str, detail: str = "") -> Evidence:
    return Evidence(kind=kind, ref=ref, detail=detail)


def cap_severity(severity: Severity, ceiling: Severity) -> Severity:
    """The lower of two severities."""
    return SEVERITY_ORDER[min(SEVERITY_ORDER.index(severity), SEVERITY_ORDER.index(ceiling))]  # type: ignore[return-value]


def finding(
    id: str,
    title: str,
    severity: Severity,
    category: Category,
    stage: Stage,
    evidence: list[Evidence] | None = None,
    *,
    source: Source = "deterministic",
    score: int | None = None,
    grounded: bool = True,
) -> Finding:
    return Finding(
        id=id,
        title=title,
        severity=severity,
        category=category,
        stage=stage,
        evidence=evidence or [],
        score=SEVERITY_SCORE[severity] if score is None else score,
        source=source,
        grounded=grounded,
    )
