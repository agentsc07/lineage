"""Findings -> risk score (BUILD_PLAN §3)."""
from __future__ import annotations

from lineage.schemas.finding import Evidence, Finding
from lineage.schemas.passport import TrustLevel

SEVERITY_WEIGHT = {"info": 0, "low": 5, "medium": 12, "high": 25, "critical": 40}
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
ADVISORY_PREFIX = "PKG.OSV."
TRUST_PENALTY = {"unknown": 15, "origin_verified": 5, "signed": 0, "recorded": 0}


# Findings no baseline, exception-free "signal" demotion or LLM verdict may lower: the artifact is known-bad, or carries
# an unambiguous execution primitive. A *new* start-up hook is hard; one the previous release already had is `info`
# at the scanner (`hook_findings`), never by this module.
HARD_FINDING_IDS = (
    "PKG.OSV.MAL",             # known-malicious advisory
    "PKG.CODE.DECODE_EXEC",    # a decoded blob that is executed
    "PKG.TAINT.ENCODED_EXEC",
    "PKG.HOOK.STARTUP_HOOK",   # when severity is above info (i.e. new in this release)
    "MODEL.PICKLE.DANGEROUS_GLOBAL",
    "INTEGRITY.HASH_MISMATCH",
    "PROV.SIGNATURE.INVALID",
)


def is_hard(finding: Finding) -> bool:
    return finding.severity != "info" and finding.id.startswith(HARD_FINDING_IDS)


def finding_points(finding: Finding) -> int:
    """What one finding adds. An LLM finding whose citation did not check out adds nothing; no finding ever subtracts."""
    if finding.source == "llm" and not finding.grounded:
        return 0
    return max(0, finding.score)


def group_advisories(findings: list[Finding]) -> list[Finding]:
    """Collapse two or more advisory findings (`PKG.OSV.*`) into one `PKG.OSV.GROUP` finding at the first one's
    position: the count, the worst severity and the top 3 ids (worst first). Display and scoring use this view;
    the stored findings stay individual because the policy engine reads each one (hard blocks, vulnerability limits)."""
    advisories = [f for f in findings if f.id.startswith(ADVISORY_PREFIX) and f.severity != "info"]
    if len(advisories) < 2:
        return findings
    ranked = sorted(advisories, key=lambda f: -SEVERITY_ORDER.index(f.severity))
    worst = ranked[0].severity
    top = [f.id.removeprefix(ADVISORY_PREFIX) for f in ranked[:3]]
    more = f" (+{len(ranked) - 3} more)" if len(ranked) > 3 else ""
    group = Finding(
        id=f"{ADVISORY_PREFIX}GROUP",
        title=f"{len(ranked)} advisories, worst {worst}: {', '.join(top)}{more}",
        severity=worst, category=ranked[0].category, stage=ranked[0].stage,
        evidence=[e for f in ranked[:3] for e in f.evidence[:1]] or [Evidence(kind="field", ref=top[0])],
        score=SEVERITY_WEIGHT[worst], source="deterministic",
    )
    out, placed = [], False
    for f in findings:
        if f.id.startswith(ADVISORY_PREFIX) and f.severity != "info":
            if not placed:
                out.append(group)
                placed = True
        else:
            out.append(f)
    return out


def risk_score(findings: list[Finding], trust_level: TrustLevel) -> int:
    """min(100, sum(finding.score) + trust-level penalty). A group of advisories counts once, at its worst severity."""
    return min(100, sum(finding_points(f) for f in group_advisories(findings)) + TRUST_PENALTY.get(trust_level, 0))
