"""POST /decisions/{id}/approve and POST /revoke/{id} (mock data until Track B)."""
from __future__ import annotations

from fastapi import APIRouter

from lineage.schemas.artifact import ApprovalRequest, RevokeResult
from lineage.schemas.decision import Decision
from lineage_server import mock

router = APIRouter()


@router.post("/decisions/{artifact_id}/approve", response_model=Decision)
def approve(artifact_id: str, req: ApprovalRequest) -> Decision:
    d = mock.decision(artifact_id, environment="dev", outcome="allow_with_conditions")
    return d.model_copy(update={"approver": req.approver, "conditions": [f"approved until {req.expires.date()}: {req.reason}"]})


@router.post("/revoke/{artifact_id}", response_model=RevokeResult)
def revoke(artifact_id: str, reason: str = "") -> RevokeResult:
    return RevokeResult(revoked=artifact_id, reason=reason, blast_radius=mock.blast_radius(artifact_id))
