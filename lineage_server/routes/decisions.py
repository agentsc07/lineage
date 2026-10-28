"""POST /decisions/{id}/approve, POST /decisions/{id}/reject and POST /revoke/{id}."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from lineage.schemas.artifact import ApprovalRequest, RevokeResult
from lineage.schemas.decision import Decision
from lineage.schemas.policy import PolicyPack
from lineage_server import models, service
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


class RejectRequest(BaseModel):
    reason: str = Field(min_length=3)


class RejectResult(BaseModel):
    artifact_id: str
    status: str
    actor: str
    reason: str


@router.post("/decisions/{artifact_id}/reject", response_model=RejectResult)
def reject(artifact_id: str, req: RejectRequest, conn: sqlite3.Connection = Depends(get_conn), user: User = Depends(require("approver"))) -> RejectResult:
    """Refuse a pending (quarantined) admission request. Not a revocation: the artifact was never admitted, so no descendant is re-evaluated. The
    actor is the authenticated user, the requester cannot reject their own request (separation of duties), and the reason stays in the audit log."""
    row = conn.execute("SELECT requester FROM artifact_meta WHERE artifact_id = ?", (artifact_id,)).fetchone()
    if user is not ANONYMOUS and row and row["requester"] and row["requester"] == user.name:
        raise HTTPException(403, f"{user.name} requested this intake and cannot reject it (separation of duties)")
    try:
        service.reject(conn, artifact_id, user.name, req.reason.strip())
    except service.NotFound:
        raise HTTPException(404, f"unknown artifact {artifact_id}")
    except service.NotRejectable as e:
        raise HTTPException(409, f"cannot be rejected: {e}")
    return RejectResult(artifact_id=artifact_id, status="rejected", actor=user.name, reason=req.reason.strip())


@router.post("/revoke/{artifact_id}", response_model=RevokeResult)
def revoke(
    artifact_id: str,
    reason: str = "",
    conn: sqlite3.Connection = Depends(get_conn),
    active: tuple[PolicyPack, bool] = Depends(get_policy),
    user: User = Depends(require("approver")),
) -> RevokeResult:
    art = models.artifact_row(conn, artifact_id)
    if art is not None and not models.is_revoked(conn, artifact_id) and not models.was_admitted(conn, artifact_id):
        raise HTTPException(409, "it was never admitted, so there is nothing to revoke" + ("; reject the pending request instead" if art.status == "quarantined" else ""))
    try:
        return service.revoke(conn, artifact_id, f"{reason} (by {user.name})" if reason else f"by {user.name}", active[0], policy_expired=active[1])
    except service.NotFound:
        raise HTTPException(404, f"unknown artifact {artifact_id}")
