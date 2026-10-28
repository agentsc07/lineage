"""Read-only views the intake page needs, built from what intake persisted (no value is invented in the browser):
GET /artifacts/{id}/view, /jobs/{id}, /limits, /attestations/{id}/view."""
from __future__ import annotations

import json
import os
import sqlite3
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from lineage.intake import fetch
from lineage.policy.engine import classify_finding, hard_blocks
from lineage.schemas.artifact import Artifact
from lineage.schemas.attestation import SignedAttestation
from lineage.schemas.decision import Decision
from lineage.schemas.policy import PolicyPack
from lineage_server import attest, models, service, trust
from lineage_server.deps import get_conn, get_policy

router = APIRouter()


class FileRow(BaseModel):
    path: str
    size: int | None = None
    sha256: str | None = None
    origin: Literal["matching", "changed", "missing", "extra", "unchecked"] = "unchecked"


class FactRow(BaseModel):
    key: str
    value: str | None
    provenance: Literal["computed", "fetched", "signed", "declared"]
    source: str


class ArtifactView(BaseModel):
    artifact_id: str
    merkle_root: str
    claimed_origin: str | None = None
    origin_checked: bool = False
    files: list[FileRow] = Field(default_factory=list)
    facts: list[FactRow] = Field(default_factory=list)
    creator_passport: dict = Field(default_factory=dict)  # present, claimed_publisher, key_id, signature, key_status, bytes_match
    finding_classes: dict[str, str] = Field(default_factory=dict)  # finding id -> hard_block | policy_dependent | scored
    decision: Decision | None = None
    status: str = ""  # the artifact's lifecycle status: quarantined, admitted, blocked, rejected, revoked ...
    requester: str | None = None
    hard_block: bool = False
    next_action: str = ""
    pull_command: str | None = None
    pull_command_first_use: str | None = None


def pull_command(ref: str, dest: str, env: str, server: str, pin: bool = False) -> str:
    """The `lineage pull` line for an admitted artifact. The syntax is `lineage pull REF DEST [-e ENV] [--server URL] [--pin]`
    (lineage/cli.py `pull`); a test parses what this returns with the real Typer command. No token: the CLI reads LINEAGE_TOKEN."""
    import shlex

    return " ".join(["lineage", "pull", shlex.quote(ref), shlex.quote(dest), "-e", shlex.quote(env), "--server", shlex.quote(server)] + (["--pin"] if pin else []))


def public_url(request: Request) -> str:
    return (os.environ.get("LINEAGE_PUBLIC_URL") or str(request.base_url)).rstrip("/")


@router.get("/artifacts/{artifact_id}/view", response_model=ArtifactView)
def artifact_view(artifact_id: str, request: Request, conn: sqlite3.Connection = Depends(get_conn),
                  active: tuple[PolicyPack, bool] = Depends(get_policy)) -> ArtifactView:
    signed = models.get_signed_passport(conn, artifact_id)
    art: Artifact | None = models.artifact_row(conn, artifact_id)
    if signed is None or art is None:
        raise HTTPException(404, f"unknown artifact {artifact_id}")
    body = signed.passport.predicate
    policy = active[0]
    row = conn.execute("SELECT body FROM artifact_identity WHERE artifact_id = ?", (artifact_id,)).fetchone()
    ident = json.loads(row["body"]) if row else {}
    files = ident.get("files") or [{"path": p, "sha256": s, "size": None, "origin": "unchecked"} for p, s in sorted(body.contents.files.items())]
    if not row:  # older artifacts: sizes from the store when the blob is there
        for f in files:
            blob = request.app.state.store.blob_path(f["sha256"]) if f["sha256"] else None
            f["size"] = blob.stat().st_size if blob is not None and blob.is_file() else None
    decision = models.latest_decision(conn, artifact_id)
    findings = models.get_findings(conn, artifact_id)
    env = decision.environment if decision else art.environment
    meta = conn.execute("SELECT requester FROM artifact_meta WHERE artifact_id = ?", (artifact_id,)).fetchone()
    requester = meta["requester"] if meta else None
    hard = bool(decision and decision.outcome == "block" and hard_blocks(body, findings, policy, env))
    revoked = models.is_revoked(conn, artifact_id)
    outcome = decision.outcome if decision else None
    rej = conn.execute("SELECT actor, reason FROM rejections WHERE artifact_id = ? ORDER BY seq DESC LIMIT 1", (artifact_id,)).fetchone()
    if rej:
        nxt = f"Rejected by {rej['actor']}: {rej['reason']}. It was never admitted; submit it again to start a new request."
    elif revoked:
        nxt = "Revoked: it cannot be used anywhere."
    elif outcome in ("allow", "allow_with_conditions"):
        nxt = "Admitted: pull the registry's copy with the command below."
    elif hard:
        nxt = "Blocked by a hard rule: no approval can change this. Fix the artifact and submit again."
    elif outcome in ("quarantine", "block"):
        nxt = f"Needs an approver other than {requester or 'the requester'} (role approver); an approval has an expiry." if outcome == "quarantine" \
            else "Blocked by soft rules: an approver can accept them with an expiry, or the artifact can be fixed and resubmitted."
    else:
        nxt = ""
    usable = not revoked and not rej and outcome in ("allow", "allow_with_conditions")
    server = public_url(request)
    dest = f"./admitted/{body.name}"
    return ArtifactView(
        artifact_id=artifact_id, merkle_root=ident.get("merkle_root") or body.contents.merkle_root, claimed_origin=ident.get("claimed_origin"),
        origin_checked=bool(ident.get("origin_checked")), files=[FileRow(**f) for f in files], facts=[FactRow(**f) for f in ident.get("facts", [])],
        creator_passport=ident.get("creator_passport", {"present": False}),
        finding_classes={f.id: classify_finding(f, body, policy, env) for f in findings}, decision=decision, status=art.status, requester=requester,
        hard_block=hard, next_action=nxt,
        pull_command=pull_command(artifact_id, dest, env, server) if usable else None,
        pull_command_first_use=pull_command(artifact_id, dest, env, server, pin=True) if usable else None)


class JobView(BaseModel):
    job_id: str
    requester: str | None = None
    artifact_type: str | None = None
    environment: str | None = None
    label: str | None = None
    created_at: str | None = None
    done: bool
    artifact_id: str | None = None


@router.get("/jobs/{job_id}", response_model=JobView)
def job_view(job_id: str, request: Request) -> JobView:
    """What a reloaded page needs besides the events: what the job was and which artifact it produced."""
    jobs = request.app.state.jobs
    job = jobs.get(job_id)
    meta = jobs.describe(job_id) or {}
    if job is None:
        raise HTTPException(404, f"unknown job {job_id}")
    aid = next((e.decision.artifact_id for e in job.events if e.decision), None)
    return JobView(job_id=job_id, requester=meta.get("requester"), artifact_type=meta.get("artifact_type"), environment=meta.get("environment"),
                   label=meta.get("label"), created_at=meta.get("created_at"), done=job.done, artifact_id=aid)


class Limits(BaseModel):
    max_upload_mb: int
    max_fetch_mb: int
    max_archive_files: int
    accepted: list[str]


@router.get("/limits", response_model=Limits)
def limits() -> Limits:
    """The server's real caps, so the page can say why an upload was refused."""
    return Limits(max_upload_mb=fetch.max_upload_bytes() // (1024 * 1024), max_fetch_mb=fetch.max_fetch_bytes() // (1024 * 1024),
                  max_archive_files=fetch.MAX_ARCHIVE_FILES, accepted=[".safetensors, config and tokenizer files", ".zip / .tar.gz of a model, dataset or tool directory",
                                                                   ".whl / .tar.gz of a Python package", ".csv .jsonl .parquet datasets"])


class AttestationView(BaseModel):
    attestation: SignedAttestation
    signature_ok: bool  # verified here against the registry's own key (a client verifies against the key it pinned)
    registry_key_id: str
    verified_by: str = "the registry, against its own public key"


@router.get("/attestations/{artifact_id}/view", response_model=AttestationView)
def attestation_view(artifact_id: str, request: Request, env: str = "prod", conn: sqlite3.Connection = Depends(get_conn),
                     active: tuple[PolicyPack, bool] = Depends(get_policy)) -> AttestationView:
    if env not in active[0].environments:
        raise HTTPException(400, f"unknown environment {env!r}; policy defines {sorted(active[0].environments)}")
    try:
        signed = attest.issue(conn, request.app.state.signing_key, artifact_id, active[0], env, policy_expired=active[1])
    except service.NotFound:
        raise HTTPException(404, f"unknown artifact {artifact_id}")
    pub = request.app.state.signing_key.public_key()
    return AttestationView(attestation=signed, signature_ok=attest.verify(signed, pub), registry_key_id=trust.key_id(pub))
