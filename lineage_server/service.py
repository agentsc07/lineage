"""Operations that combine the store, the policy engine and the graph: record, re-decide, approve, revoke."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from lineage.policy.engine import decide
from lineage.schemas.artifact import ApprovalRequest, RevokeResult
from lineage.schemas.decision import Decision
from lineage.schemas.finding import Evidence, Finding
from lineage.schemas.passport import SignedPassport
from lineage.schemas.policy import PolicyException, PolicyPack
from lineage_server import graph, log, models
from lineage_server.db import tx


class NotFound(KeyError):
    pass


class ApprovalRefused(Exception):
    """The artifact cannot be approved (hard block, or still not admissible); `args[0]` lists the reasons."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _exceptions(conn: sqlite3.Connection, artifact_id: str) -> list[PolicyException]:
    return [
        PolicyException(
            artifact=artifact_id,
            approver=r["approver"],
            reason=r["reason"],
            expires=datetime.fromisoformat(r["expires"]),
        )
        for r in models.get_approvals(conn, artifact_id)
    ]


def record(
    conn: sqlite3.Connection,
    signed: SignedPassport,
    findings: list[Finding],
    decision: Decision,
    *,
    released_at: datetime | None = None,
    tool_pin: dict[str, str] | None = None,
) -> None:
    """Persist an intake result atomically: passport, edges, findings, decision (and a tool pin)."""
    with tx(conn):
        models.save_passport(
            conn, signed, status=models.OUTCOME_STATUS[decision.outcome], environment=decision.environment,
            released_at=released_at,
        )
        models.save_findings(conn, signed.passport_id, findings)
        models.save_decision(conn, decision)
        if tool_pin:
            conn.execute(
                "INSERT OR REPLACE INTO tool_pins (artifact_id, tool_name, description_sha256, code_sha256)"
                " VALUES (?, ?, ?, ?)",
                (signed.passport_id, signed.passport.predicate.name, tool_pin["description_sha256"],
                 tool_pin["code_sha256"]),
            )


def evaluate(
    conn: sqlite3.Connection,
    artifact_id: str,
    policy: PolicyPack,
    *,
    policy_expired: bool = False,
    extra_findings: list[Finding] | None = None,
    extra_exceptions: list[PolicyException] | None = None,
    now: datetime | None = None,
) -> Decision:
    """Run the engine over what is stored (plus extras) without saving anything."""
    signed = models.get_signed_passport(conn, artifact_id)
    if signed is None:
        raise NotFound(artifact_id)
    previous = models.latest_decision(conn, artifact_id)
    art = models.artifact_row(conn, artifact_id)
    env = previous.environment if previous else art.environment  # type: ignore[union-attr]
    findings = models.get_findings(conn, artifact_id) + list(extra_findings or [])
    return decide(
        signed.passport.predicate,
        findings,
        env,
        policy,
        now or _now(),
        artifact_id=artifact_id,
        released_at=models.released_at(conn, artifact_id),
        exceptions=_exceptions(conn, artifact_id) + list(extra_exceptions or []),
        policy_expired=policy_expired,
    )


def redecide(
    conn: sqlite3.Connection,
    artifact_id: str,
    policy: PolicyPack,
    *,
    policy_expired: bool = False,
    extra_findings: list[Finding] | None = None,
    now: datetime | None = None,
) -> Decision:
    """Re-run the engine on stored evidence plus any new findings; persist both."""
    with tx(conn):
        new = [f for f in (extra_findings or []) if f.id not in {x.id for x in models.get_findings(conn, artifact_id)}]
        decision = evaluate(conn, artifact_id, policy, policy_expired=policy_expired, extra_findings=new, now=now)
        models.save_findings(conn, artifact_id, new)
        models.save_decision(conn, decision)
    return decision


def approve(
    conn: sqlite3.Connection,
    artifact_id: str,
    req: ApprovalRequest,
    policy: PolicyPack,
    *,
    policy_expired: bool = False,
    now: datetime | None = None,
) -> Decision:
    """Record a human approval (as an exception with expiry) and re-decide.

    Refused if even with the approval the artifact would still be blocked or quarantined: hard blocks
    cannot be approved away.
    """
    exc = PolicyException(artifact=artifact_id, approver=req.approver, reason=req.reason, expires=req.expires)
    with tx(conn):
        trial = evaluate(conn, artifact_id, policy, policy_expired=policy_expired, extra_exceptions=[exc], now=now)
        if trial.outcome in ("block", "quarantine"):
            raise ApprovalRefused(trial.reasons)
        models.add_approval(conn, artifact_id, req.approver, req.reason, req.expires)
        models.save_decision(conn, trial)
    return trial


def _parent_revoked_finding(parent_id: str, label: str, reason: str) -> Finding:
    return Finding(
        id="PROV.PARENT.REVOKED",
        title=f"Parent {label} was revoked" + (f": {reason}" if reason else ""),
        severity="high",
        category="provenance",
        stage="S2",
        evidence=[Evidence(kind="field", ref=parent_id, detail="revoked ancestor")],
        score=25,
        source="deterministic",
    )


def revoke(
    conn: sqlite3.Connection,
    artifact_id: str,
    reason: str,
    policy: PolicyPack,
    *,
    policy_expired: bool = False,
    now: datetime | None = None,
) -> RevokeResult:
    """Revoke `artifact_id`, then flag every descendant: each is re-decided with a revoked-parent finding
    (a hard block), so nothing downstream stays admitted. Returns the blast radius with current statuses."""
    now = now or _now()
    with tx(conn):
        art = models.artifact_row(conn, artifact_id)
        if art is None:
            raise NotFound(artifact_id)
        if not models.is_revoked(conn, artifact_id):
            conn.execute(
                "INSERT INTO revocations (artifact_id, reason, revoked_at) VALUES (?, ?, ?)",
                (artifact_id, reason, now.isoformat()),
            )
            models.set_status(conn, artifact_id, "revoked")
            log.append(conn, "revocation", artifact_id, now)
        flag = _parent_revoked_finding(artifact_id, f"{art.name}@{art.version}", reason)
        for node in graph.blast_radius(conn, artifact_id):
            if node.status != "revoked":
                redecide(conn, node.id, policy, policy_expired=policy_expired, extra_findings=[flag], now=now)
        radius = graph.blast_radius(conn, artifact_id)
    return RevokeResult(revoked=artifact_id, reason=reason, blast_radius=radius)
