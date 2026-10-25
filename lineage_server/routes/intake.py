"""POST /intake. Progress streams on GET /events/{job}."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from lineage.intake.pipeline import run_intake
from lineage.schemas.artifact import IntakeJob, IntakeRequest
from lineage.schemas.policy import PolicyPack
from lineage_server import db
from lineage_server.deps import get_policy
from lineage_server.jobs import Job
from lineage_server.registry import SqliteRegistry

router = APIRouter()


@router.post("/intake", response_model=IntakeJob)
def start_intake(req: IntakeRequest, request: Request, active: tuple[PolicyPack, bool] = Depends(get_policy)) -> IntakeJob:
    policy, expired = active
    if req.environment not in policy.environments:
        raise HTTPException(400, f"unknown environment {req.environment!r}; policy defines {sorted(policy.environments)}")
    state = request.app.state

    def run(job: Job) -> None:
        conn = db.connect(state.db_path)  # the worker thread owns its connection
        try:
            registry = SqliteRegistry(conn, state.signing_key)
            for event in run_intake(req.artifact_type, req.ref, req.environment, policy, job.job_id,
                                    registry=registry, policy_expired=expired):
                job.push(event)
        finally:
            conn.close()

    job = state.jobs.start(run)
    return IntakeJob(job_id=job.job_id, events_url=f"/events/{job.job_id}")
