"""POST /decisions/{id}/approve and POST /revoke/{id}."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from lineage.schemas.artifact import ApprovalRequest, RevokeResult
from lineage.schemas.decision import Decision
from lineage.schemas.policy import PolicyPack
from lineage_server import service
from lineage_server.auth import ANONYMOUS, User, require
from lineage_server.deps import get_conn, get_policy

router = APIRouter()


@router.post("/decisions/{artifact_id}/approve", response_model=Decision)
def approve(
    artifact_id: str,
    req: ApprovalRequest,
    conn: sqlite3.Connection = Depends(get_conn),
    active: tuple[PolicyPack, bool] = Depends(get_policy),
    user: User = Depends(require("approver")),
) -> Decision:
    """The approver is the authenticated user, never a typed name; whoever asked for the intake cannot approve it (P7)."""
    row = conn.execute("SELECT requester FROM artifact_meta WHERE artifact_id = ?", (artifact_id,)).fetchone()
    if user is not ANONYMOUS and row and row["requester"] and row["requester"] == user.name:
        raise HTTPException(403, f"{user.name} requested this intake and cannot approve it (separation of duties)")
    expires = req.expires if req.expires.tzinfo else req.expires.replace(tzinfo=timezone.utc)
    if expires <= datetime.now(timezone.utc):
        raise HTTPException(422, "approval expiry must be in the future")
    try:
        return service.approve(conn, artifact_id, req.model_copy(update={"expires": expires, "approver": (req.approver if user is ANONYMOUS and req.approver else user.name)}), active[0], policy_expired=active[1])
    except service.NotFound:
        raise HTTPException(404, f"unknown artifact {artifact_id}")
    except service.ApprovalRefused as e:
        raise HTTPException(409, {"message": "cannot be approved", "reasons": e.args[0]})


@router.post("/revoke/{artifact_id}", response_model=RevokeResult)
def revoke(
    artifact_id: str,
    reason: str = "",
    conn: sqlite3.Connection = Depends(get_conn),
    active: tuple[PolicyPack, bool] = Depends(get_policy),
    user: User = Depends(require("approver")),
) -> RevokeResult:
    try:
        return service.revoke(conn, artifact_id, f"{reason} (by {user.name})" if reason else f"by {user.name}", active[0], policy_expired=active[1])
    except service.NotFound:
        raise HTTPException(404, f"unknown artifact {artifact_id}")
