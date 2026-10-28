"""Operations that combine the store, the policy engine and the graph: record, re-decide, approve, revoke."""
from __future__ import annotations

import json
import re
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


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def ensure_ghost(conn: sqlite3.Connection, gid: str, artifact_type: str, name: str, version: str, ref: str) -> None:
    conn.execute("INSERT OR IGNORE INTO ghosts (id, artifact_type, name, version, ref, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                 (gid, artifact_type, name, version, ref, _now().isoformat()))


def link_refs(conn: sqlite3.Connection, child_id: str, parents: list[str], refs: list[dict]) -> None:
    """Edges into `child_id` for everything it references (P6). A reference that matches an admitted artifact links to it; anything
    else becomes a ghost node (`status: unregistered`) so the gap is visible and the monitor and revoke still reach it.
    `refs`: {kind, type, name, version?, ref}; passport parents are {kind: derived_from} by id."""
    parent_shas: set[str] = set()
    for pid in parents:
        if not conn.execute("SELECT 1 FROM artifacts WHERE id = ?", (pid,)).fetchone():
            ensure_ghost(conn, pid, "model", pid[:19], "", f"passport {pid}")
        else:
            sp = models.get_signed_passport(conn, pid)
            if sp is not None:
                parent_shas |= set(sp.passport.predicate.contents.files.values())
    for r in refs:
        if r.get("file_sha"):  # a training input: an edge only if an artifact that was not refused holds exactly these bytes
            if r["file_sha"] in parent_shas:  # a file of a model it already derives from (a shared config.json): not a separate input
                continue
            row = conn.execute("SELECT p.id FROM passports p JOIN artifacts a ON a.id = p.id WHERE p.body LIKE ? AND p.id != ?"
                               " AND a.status NOT IN ('blocked', 'rejected') ORDER BY p.created_at DESC LIMIT 1",
                               (f"%{r['file_sha']}%", child_id)).fetchone()
            if row:
                conn.execute("INSERT OR IGNORE INTO edges (parent, child, kind) VALUES (?, ?, ?)", (row["id"], child_id, r["kind"]))
            continue
        ver = r.get("version") or ""
        rows = conn.execute("SELECT id, name, version FROM artifacts WHERE artifact_type = ? AND status != 'revoked' ORDER BY created_at DESC, rowid DESC",
                            (r["type"],)).fetchall()
        hit = next((x["id"] for x in rows if _norm(x["name"]) == _norm(r["name"]) and (not ver or x["version"] == ver) and x["id"] != child_id), None)
        pid = hit or f"ghost:{r['type']}:{_norm(r['name'])}@{ver or '*'}"
        if not hit:
            ensure_ghost(conn, pid, r["type"], r["name"], ver, r.get("ref") or r["name"])
        conn.execute("INSERT OR IGNORE INTO edges (parent, child, kind) VALUES (?, ?, ?)", (pid, child_id, r["kind"]))


def record(
    conn: sqlite3.Connection,
    signed: SignedPassport,
    findings: list[Finding],
    decision: Decision,
    *,
    released_at: datetime | None = None,
    tool_pin: dict[str, str] | None = None,
    meta: dict | None = None,
) -> None:
    """Persist an intake result atomically: passport, edges, findings, decision (and a tool pin, and who asked)."""
    with tx(conn):
        models.save_passport(
            conn, signed, status=models.OUTCOME_STATUS[decision.outcome], environment=decision.environment,
            released_at=released_at,
        )
        models.save_findings(conn, signed.passport_id, findings)
        models.save_decision(conn, decision)
        if meta:
            conn.execute(
                "INSERT OR REPLACE INTO artifact_meta (artifact_id, requester, source, claimed_origin, claims, distribution, source_id, signer_key)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (signed.passport_id, meta.get("requester"), meta.get("source"), meta.get("claimed_origin"),
                 json.dumps(meta.get("claims")), json.dumps(meta.get("distribution")), meta.get("source_id"), meta.get("signer_key")))
        if meta and meta.get("identity"):
            conn.execute("INSERT OR REPLACE INTO artifact_identity (artifact_id, body) VALUES (?, ?)", (signed.passport_id, json.dumps(meta["identity"])))
        link_refs(conn, signed.passport_id, signed.passport.predicate.parents, (meta or {}).get("graph_refs", []))
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
    environment: str | None = None,
) -> Decision:
    """Run the engine over what is stored (plus extras) without saving anything. `environment` asks "and for that environment?"."""
    signed = models.get_signed_passport(conn, artifact_id)
    if signed is None:
        raise NotFound(artifact_id)
    previous = models.latest_decision(conn, artifact_id)
    art = models.artifact_row(conn, artifact_id)
    env = environment or (previous.environment if previous else art.environment)  # type: ignore[union-attr]
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
        if models.is_rejected(conn, artifact_id):
            raise ApprovalRefused(["this request was rejected; submit the artifact again to start a new one"])
        trial = evaluate(conn, artifact_id, policy, policy_expired=policy_expired, extra_exceptions=[exc], now=now)
        if trial.outcome in ("block", "quarantine"):
            raise ApprovalRefused(trial.reasons)
        models.add_approval(conn, artifact_id, req.approver, req.reason, req.expires)
        models.save_decision(conn, trial)
    return trial


class NotRejectable(Exception):
    """Only a pending or quarantined request can be rejected; an admitted artifact is revoked instead."""


def reject(conn: sqlite3.Connection, artifact_id: str, actor: str, reason: str, *, now: datetime | None = None) -> None:
    """Refuse a pending (quarantined) admission request. The reason and the actor are recorded, the decision history stays, nothing is revoked,
    and no descendant changes: the artifact was never admitted, so nothing was built on it through Lineage."""
    now = now or _now()
    with tx(conn):
        art = models.artifact_row(conn, artifact_id)
        if art is None:
            raise NotFound(artifact_id)
        if models.is_revoked(conn, artifact_id) or models.is_rejected(conn, artifact_id):
            raise NotRejectable(f"already {'revoked' if models.is_revoked(conn, artifact_id) else 'rejected'}")
        if models.was_admitted(conn, artifact_id) or art.status in ("admitted", "admitted_with_conditions"):
            raise NotRejectable("it was admitted: use revoke, which re-evaluates what was built on it")
        if art.status != "quarantined":
            raise NotRejectable(f"only a pending (quarantined) request can be rejected; this one is {art.status}")
        conn.execute("INSERT INTO rejections (artifact_id, actor, reason, rejected_at) VALUES (?, ?, ?, ?)", (artifact_id, actor, reason, now.isoformat()))
        models.set_status(conn, artifact_id, "rejected")
        log.append(conn, "rejection", artifact_id, now)


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
        ghost = conn.execute("SELECT * FROM ghosts WHERE id = ?", (artifact_id,)).fetchone() if art is None else None
        if art is None and ghost is None:
            raise NotFound(artifact_id)
        if not models.is_revoked(conn, artifact_id):
            conn.execute(
                "INSERT INTO revocations (artifact_id, reason, revoked_at) VALUES (?, ?, ?)",
                (artifact_id, reason, now.isoformat()),
            )
            if art is not None:
                models.set_status(conn, artifact_id, "revoked")
            log.append(conn, "revocation", artifact_id, now)
        label = f"{art.name}@{art.version}" if art else (ghost["ref"] or ghost["name"])
        flag = _parent_revoked_finding(artifact_id, label, reason)
        for node in graph.blast_radius(conn, artifact_id):
            if node.status != "revoked":
                redecide(conn, node.id, policy, policy_expired=policy_expired, extra_findings=[flag], now=now)
        radius = graph.blast_radius(conn, artifact_id)
    return RevokeResult(revoked=artifact_id, reason=reason, blast_radius=radius)
