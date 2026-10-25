"""POST /intake (mock data until Track B). Progress streams on GET /events/{job}."""
from __future__ import annotations

from uuid import uuid4

from fastapi import APIRouter

from lineage.schemas.artifact import IntakeJob, IntakeRequest

router = APIRouter()


@router.post("/intake", response_model=IntakeJob)
def start_intake(req: IntakeRequest) -> IntakeJob:
    job_id = uuid4().hex[:12]
    return IntakeJob(job_id=job_id, events_url=f"/events/{job_id}")
