"""POST /uploads and POST /intake (REFACTOR_SPEC 4.1). Progress streams on GET /events/{job}.

An intake names where the bytes come from: `upload:<id>` (a file or archive sent to /uploads), `hf:<repo>[@rev]`,
`hf-dataset:<repo>[@rev]`, `pypi:<name>==<ver>`, or `mcp:upload:<id>`. A local path (`ref`) is accepted only when the server runs
with LINEAGE_DEV_LOCAL_PATHS=1 (the demo and the benchmark); it is treated exactly like an upload."""
from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile
from pydantic import BaseModel

from lineage.intake import fetch
from lineage.intake.pipeline import run_intake
from lineage.schemas.artifact import IntakeJob, IntakeRequest
from lineage.schemas.policy import PolicyPack
from lineage_server import db
from lineage_server.auth import User, require
from lineage_server.deps import get_policy
from lineage_server.jobs import Job
from lineage_server.registry import SqliteRegistry

router = APIRouter()
CLAIM_KEYS = {"publisher", "licence", "base_model", "released_at", "description"}


class UploadReceipt(BaseModel):
    upload_id: str
    filename: str
    size: int


@router.post("/uploads", response_model=UploadReceipt)
async def upload(file: UploadFile, request: Request, user: User = Depends(require("requester"))) -> UploadReceipt:
    """Receive one file (a weights file, a CSV, a wheel) or one archive (.zip, .tar.gz). Extraction happens at intake, safely."""
    name = Path(file.filename or "upload.bin").name
    uid = uuid.uuid4().hex[:12]
    dest = request.app.state.uploads / uid / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    size, cap = 0, fetch.max_upload_bytes()
    with dest.open("wb") as out:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > cap:
                out.close()
                shutil.rmtree(dest.parent, ignore_errors=True)
                raise HTTPException(413, f"upload exceeds LINEAGE_MAX_UPLOAD_MB ({cap // (1024 * 1024)} MB)")
            out.write(chunk)
    return UploadReceipt(upload_id=uid, filename=name, size=size)


def resolve_upload(root: Path, upload_id: str, artifact_type: str) -> Path:
    """The path intake should inspect for an upload: a package stays as the single file (S0 unpacks wheels and keeps them for the
    index); anything else that is an archive is extracted; a plain file is the artifact."""
    d = root / Path(upload_id).name
    files = [p for p in d.iterdir() if p.is_file()] if d.is_dir() else []
    if len(files) != 1:
        raise HTTPException(404, f"unknown upload {upload_id}")
    f = files[0]
    if artifact_type != "package" and (f.suffix in (".zip", ".tgz") or f.name.endswith((".tar.gz", ".tar"))):
        out = d / "content"
        if not out.exists():
            try:
                fetch.safe_extract(f, out)
            except fetch.AcquireError as e:
                raise HTTPException(400, str(e))
        return out
    return f


@router.post("/intake", response_model=IntakeJob)
def start_intake(req: IntakeRequest, request: Request, active: tuple[PolicyPack, bool] = Depends(get_policy),
                 user: User = Depends(require("requester"))) -> IntakeJob:
    return launch(req, request, active, user)


def launch(req: IntakeRequest, request: Request, active: tuple[PolicyPack, bool], user: User) -> IntakeJob:
    policy, expired = active
    if req.environment not in policy.environments:
        raise HTTPException(400, f"unknown environment {req.environment!r}; policy defines {sorted(policy.environments)}")
    state = request.app.state
    source, ref = req.source, ""
    if source and source.startswith(("upload:", "mcp:upload:")):
        ref = str(resolve_upload(state.uploads, source.split("upload:", 1)[1], req.artifact_type))
        source = None
    elif source and source.startswith(("hf:", "hf-dataset:", "pypi:")):
        pass
    elif source:
        raise HTTPException(400, f"unsupported source {source!r}; use upload:<id>, hf:<repo>[@rev], hf-dataset:<repo>[@rev], pypi:<name>==<ver>, mcp:upload:<id>")
    elif req.ref:
        if os.environ.get("LINEAGE_DEV_LOCAL_PATHS") != "1":
            raise HTTPException(400, "a free-text ref is not accepted; upload the artifact or name a hub source (LINEAGE_DEV_LOCAL_PATHS=1 allows local paths for the demo and bench)")
        ref = req.ref
    else:
        raise HTTPException(400, "give a source (upload:<id>, hf:..., pypi:...)")
    if req.claims and set(req.claims) - CLAIM_KEYS:
        raise HTTPException(422, f"unknown claim(s) {sorted(set(req.claims) - CLAIM_KEYS)}; allowed: {sorted(CLAIM_KEYS)}")

    def run(job: Job) -> None:
        conn = db.connect(state.db_path)  # the worker thread owns its connection
        try:
            registry = SqliteRegistry(conn, state.signing_key)
            for event in run_intake(req.artifact_type, ref, req.environment, policy, job.job_id, registry=registry,
                                    policy_expired=expired, hub=state.hub, claims=req.claims, claimed_origin=req.claimed_origin,
                                    uploader=user.name, source=source, store=state.store, work_dir=state.fetch_dir):
                job.push(event)
        finally:
            conn.close()

    job = state.jobs.start(run)
    return IntakeJob(job_id=job.job_id, events_url=f"/events/{job.job_id}")
