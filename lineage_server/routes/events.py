"""SSE /events/{job}, GET /log, /log/proof/{id}, POST /monitor/tick."""
from __future__ import annotations

import sqlite3
from collections.abc import Iterator

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse

from lineage.schemas.artifact import InclusionProof, MerkleLog, MonitorTick
from lineage.schemas.policy import PolicyPack
from lineage_server import log, monitor
from lineage_server.deps import get_conn, get_policy
from lineage_server.jobs import Job

router = APIRouter()


def _sse(job: Job) -> Iterator[str]:
    for event in job.follow():
        yield ": keepalive\n\n" if event is None else f"data: {event.model_dump_json()}\n\n"


@router.get("/events/{job_id}")
def events(job_id: str, request: Request) -> StreamingResponse:
    job = request.app.state.jobs.get(job_id)
    if job is None:
        raise HTTPException(404, f"unknown job {job_id}")
    return StreamingResponse(
        _sse(job), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


@router.get("/log", response_model=MerkleLog)
def get_log(conn: sqlite3.Connection = Depends(get_conn)) -> MerkleLog:
    return log.read_log(conn)


@router.get("/log/proof/{ref}", response_model=InclusionProof)
def get_proof(ref: str, conn: sqlite3.Connection = Depends(get_conn)) -> InclusionProof:
    try:
        return log.inclusion_proof(conn, ref)
    except KeyError:
        raise HTTPException(404, f"no log entry for {ref}")


@router.post("/monitor/tick", response_model=MonitorTick)
def monitor_tick(
    conn: sqlite3.Connection = Depends(get_conn), active: tuple[PolicyPack, bool] = Depends(get_policy)
) -> MonitorTick:
    return monitor.tick(conn, policy=active[0])
