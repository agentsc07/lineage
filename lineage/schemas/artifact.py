"""Catalogue records and server API request/response models (BUILD_PLAN §2.5)."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from lineage.schemas.decision import Decision
from lineage.schemas.finding import Finding
from lineage.schemas.passport import ArtifactType, SignedPassport, TrustLevel

ArtifactStatus = Literal[
    "submitted", "quarantined", "admitted", "admitted_with_conditions", "blocked", "revoked"
]
StageId = Literal["S1", "S2", "S3", "S4", "S5", "S6", "S7"]
StageStatus = Literal["started", "completed", "skipped", "failed"]


class Artifact(BaseModel):
    """One catalogue row."""

    id: str  # the passport id ("lp:...") of the latest admitted/decided passport
    artifact_type: ArtifactType
    name: str
    version: str
    trust_level: TrustLevel
    risk_score: int = Field(ge=0, le=100)
    status: ArtifactStatus
    environment: str
    outcome: str | None = None  # latest Decision.outcome
    created_at: datetime


class ArtifactDetail(BaseModel):
    artifact: Artifact
    passport: SignedPassport | None = None
    findings: list[Finding] = Field(default_factory=list)
    decision: Decision | None = None


# --- /intake and /events/{job} ---
class IntakeRequest(BaseModel):
    artifact_type: ArtifactType
    ref: str  # local path, hub id ("meta-llama/Llama-3.2-1B"), or "pkg==1.2.3"
    environment: str = "dev"


class IntakeJob(BaseModel):
    job_id: str
    events_url: str  # "/events/{job_id}" (SSE)


class StageEvent(BaseModel):
    """One SSE `data:` payload on /events/{job}."""

    job_id: str
    stage: StageId
    name: str  # "Identify", "Provenance", "Static inspection", "Deep inspection", ...
    status: StageStatus
    findings: list[Finding] = Field(default_factory=list)
    message: str = ""
    decision: Decision | None = None  # only on the final S6 event
    ts: datetime


# --- /passports ---
class PassportReceipt(BaseModel):
    passport_id: str
    log_index: int


class VerifyResult(BaseModel):
    passport_id: str
    valid: bool
    signature_ok: bool
    hashes_ok: bool | None = None  # None when no artifact bytes were supplied
    chain_ok: bool
    revoked: bool
    problems: list[str] = Field(default_factory=list)


# --- /graph/{id} ---
class GraphNode(BaseModel):
    id: str
    label: str
    artifact_type: ArtifactType
    trust_level: TrustLevel
    status: ArtifactStatus
    risk_score: int = Field(ge=0, le=100)


class GraphEdge(BaseModel):
    source: str
    target: str  # source is the parent, target is the child
    kind: str = "derived_from"


class Graph(BaseModel):
    root: str
    direction: Literal["up", "down"]
    nodes: list[GraphNode]
    edges: list[GraphEdge]


# --- /revoke/{id} ---
class RevokeResult(BaseModel):
    revoked: str
    reason: str = ""
    blast_radius: list[GraphNode]  # every descendant flagged


# --- /decisions/{id}/approve ---
class ApprovalRequest(BaseModel):
    approver: str
    reason: str
    expires: datetime


# --- /policy ---
class PolicySignature(BaseModel):
    role: str  # "owner" | "security" | "compliance"
    key_id: str
    signature: str


class PolicyUpdate(BaseModel):
    policy: dict  # a PolicyPack document; server validates it
    signatures: list[PolicySignature] = Field(default_factory=list)  # 2-of-3 required
    expires_at: datetime | None = None


class PolicyState(BaseModel):
    policy: dict
    version: str
    signatures: list[PolicySignature] = Field(default_factory=list)
    roles_required: int = 2
    roles_total: int = 3
    expires_at: datetime | None = None


# --- /log and /log/proof/{id} ---
class LogEntry(BaseModel):
    index: int
    entry_hash: str
    kind: str  # "passport" | "decision" | "revocation" | "policy"
    ref: str  # passport id / decision id
    ts: datetime


class MerkleLog(BaseModel):
    size: int
    root: str
    entries: list[LogEntry]


class InclusionProof(BaseModel):
    index: int
    leaf_hash: str
    path: list[str]  # sibling hashes, bottom-up
    root: str
    size: int


# --- /monitor/tick ---
class Alert(BaseModel):
    artifact_id: str
    kind: Literal["advisory", "revocation", "lookalike", "drift"]
    severity: Literal["info", "low", "medium", "high", "critical"]
    message: str
    blast_radius: list[GraphNode] = Field(default_factory=list)


class MonitorTick(BaseModel):
    checked: int
    alerts: list[Alert]
    ts: datetime
