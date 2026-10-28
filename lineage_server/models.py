"""Row-level helpers between SQLite and the Pydantic contracts."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from lineage.schemas.artifact import Artifact, ArtifactDetail, ArtifactStatus
from lineage.schemas.decision import Decision
from lineage.schemas.finding import Finding
from lineage.schemas.passport import SignedPassport
from lineage_server import log
from lineage_server.db import tx

OUTCOME_STATUS: dict[str, ArtifactStatus] = {
    "allow": "admitted",
    "allow_with_conditions": "admitted_with_conditions",
    "quarantine": "quarantined",
    "block": "blocked",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def save_passport(
    conn: sqlite3.Connection,
    signed: SignedPassport,
    *,
    status: ArtifactStatus = "submitted",
    environment: str = "dev",
    released_at: datetime | None = None,
) -> bool:
    """Register a passport, its catalogue row, its parent edges and a log entry. Returns False if already known."""
    pid = signed.passport_id
    body = signed.passport.predicate
    with tx(conn):
        if conn.execute("SELECT 1 FROM passports WHERE id = ?", (pid,)).fetchone():
            return False
        now = _now()
        conn.execute(
            "INSERT INTO passports (id, body, key_id, merkle_root, created_at) VALUES (?, ?, ?, ?, ?)",
            (pid, signed.model_dump_json(by_alias=True), signed.key_id, body.contents.merkle_root, now.isoformat()),
        )
        conn.execute(
            "INSERT INTO artifacts (id, artifact_type, name, version, trust_level, risk_score, status, environment,"
            " released_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                pid, body.artifact_type, body.name, body.version, body.trust_level, body.risk_score, status,
                environment, released_at.isoformat() if released_at else None, now.isoformat(),
            ),
        )
        for parent in body.parents:
            conn.execute("INSERT OR IGNORE INTO edges (parent, child) VALUES (?, ?)", (parent, pid))
        log.append(conn, "passport", pid, now)
    return True


def get_signed_passport(conn: sqlite3.Connection, passport_id: str) -> SignedPassport | None:
    row = conn.execute("SELECT body FROM passports WHERE id = ?", (passport_id,)).fetchone()
    return SignedPassport.model_validate_json(row["body"]) if row else None


def find_by_merkle_root(conn: sqlite3.Connection, root: str) -> str | None:
    row = conn.execute("SELECT id FROM passports WHERE merkle_root = ? ORDER BY created_at DESC LIMIT 1", (root,)).fetchone()
    return row["id"] if row else None


def save_findings(conn: sqlite3.Connection, artifact_id: str, findings: list[Finding]) -> None:
    with tx(conn):
        for f in findings:
            conn.execute(
                "INSERT INTO findings (artifact_id, finding_id, body) VALUES (?, ?, ?)",
                (artifact_id, f.id, f.model_dump_json()),
            )


def get_findings(conn: sqlite3.Connection, artifact_id: str) -> list[Finding]:
    rows = conn.execute("SELECT body FROM findings WHERE artifact_id = ? ORDER BY seq", (artifact_id,))
    return [Finding.model_validate_json(r["body"]) for r in rows]


def save_decision(conn: sqlite3.Connection, decision: Decision) -> None:
    """Append the decision and move the catalogue row to match. A revoked artifact stays revoked."""
    with tx(conn):
        conn.execute(
            "INSERT INTO decisions (artifact_id, environment, outcome, body, decided_at) VALUES (?, ?, ?, ?, ?)",
            (decision.artifact_id, decision.environment, decision.outcome, decision.model_dump_json(),
             decision.decided_at.isoformat()),
        )
        conn.execute(
            "UPDATE artifacts SET outcome = ?, risk_score = ?, trust_level = ?, environment = ?,"
            " status = CASE WHEN status IN ('revoked', 'rejected') THEN status ELSE ? END WHERE id = ?",
            (decision.outcome, decision.risk_score, decision.trust_level, decision.environment,
             OUTCOME_STATUS[decision.outcome], decision.artifact_id),
        )
        log.append(conn, "decision", decision.artifact_id, decision.decided_at)


def latest_decision(conn: sqlite3.Connection, artifact_id: str) -> Decision | None:
    row = conn.execute(
        "SELECT body FROM decisions WHERE artifact_id = ? ORDER BY seq DESC LIMIT 1", (artifact_id,)
    ).fetchone()
    return Decision.model_validate_json(row["body"]) if row else None


def add_approval(conn: sqlite3.Connection, artifact_id: str, approver: str, reason: str, expires: datetime) -> None:
    conn.execute(
        "INSERT INTO approvals (artifact_id, approver, reason, expires) VALUES (?, ?, ?, ?)",
        (artifact_id, approver, reason, expires.isoformat()),
    )


def get_approvals(conn: sqlite3.Connection, artifact_id: str) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM approvals WHERE artifact_id = ? ORDER BY seq", (artifact_id,)).fetchall()


def _row_to_artifact(row: sqlite3.Row) -> Artifact:
    return Artifact(
        id=row["id"],
        artifact_type=row["artifact_type"],
        name=row["name"],
        version=row["version"],
        trust_level=row["trust_level"],
        risk_score=row["risk_score"],
        status=row["status"],
        environment=row["environment"],
        outcome=row["outcome"],
        created_at=datetime.fromisoformat(row["created_at"]),
    )


def artifact_row(conn: sqlite3.Connection, artifact_id: str) -> Artifact | None:
    row = conn.execute("SELECT * FROM artifacts WHERE id = ?", (artifact_id,)).fetchone()
    return _row_to_artifact(row) if row else None


def released_at(conn: sqlite3.Connection, artifact_id: str) -> datetime | None:
    row = conn.execute("SELECT released_at FROM artifacts WHERE id = ?", (artifact_id,)).fetchone()
    return datetime.fromisoformat(row["released_at"]) if row and row["released_at"] else None


def list_artifacts(conn: sqlite3.Connection) -> list[Artifact]:
    rows = conn.execute("SELECT * FROM artifacts ORDER BY created_at DESC, rowid DESC")
    return [_row_to_artifact(r) for r in rows]


def get_artifact(conn: sqlite3.Connection, artifact_id: str) -> ArtifactDetail | None:
    art = artifact_row(conn, artifact_id)
    if art is None:
        return None
    return ArtifactDetail(
        artifact=art,
        passport=get_signed_passport(conn, artifact_id),
        findings=get_findings(conn, artifact_id),
        decision=latest_decision(conn, artifact_id),
    )


def set_status(conn: sqlite3.Connection, artifact_id: str, status: ArtifactStatus) -> None:
    conn.execute("UPDATE artifacts SET status = ? WHERE id = ?", (status, artifact_id))


def is_rejected(conn: sqlite3.Connection, artifact_id: str) -> bool:
    return conn.execute("SELECT 1 FROM rejections WHERE artifact_id = ?", (artifact_id,)).fetchone() is not None


def was_admitted(conn: sqlite3.Connection, artifact_id: str) -> bool:
    """Has this artifact ever been allowed (by policy or by an approval)? Revoke is for these; reject is for requests that never were."""
    return conn.execute("SELECT 1 FROM decisions WHERE artifact_id = ? AND outcome IN ('allow', 'allow_with_conditions') LIMIT 1", (artifact_id,)).fetchone() is not None


def is_revoked(conn: sqlite3.Connection, artifact_id: str) -> bool:
    return conn.execute("SELECT 1 FROM revocations WHERE artifact_id = ?", (artifact_id,)).fetchone() is not None
