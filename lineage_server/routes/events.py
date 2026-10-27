"""SSE /events/{job}, GET /log, /log/proof/{id}, POST /monitor/tick, GET /monitor/latest."""
from __future__ import annotations

import sqlite3
from collections.abc import Iterator

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse

from lineage.schemas.artifact import InclusionProof, MerkleLog, MonitorTick
from lineage.schemas.policy import PolicyPack
from lineage_server import log, monitor
from lineage_server.auth import require
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


@router.post("/monitor/tick", response_model=MonitorTick, dependencies=[Depends(require("approver", "requester"))])
def monitor_tick(
    request: Request, conn: sqlite3.Connection = Depends(get_conn), active: tuple[PolicyPack, bool] = Depends(get_policy)
) -> MonitorTick:
    result = monitor.tick(conn, policy=active[0], hub=request.app.state.hub)
    conn.execute("INSERT INTO monitor_ticks (n_alerts, body) VALUES (?, ?)", (len(result.alerts), result.model_dump_json()))
    conn.commit()
    request.app.state.monitor_status["last"] = result.ts
    return result


@router.get("/monitor/status")
def monitor_status(request: Request) -> dict:
    """When the scheduled monitor last ran and when it runs next (null: scheduling is off)."""
    st = request.app.state.monitor_status
    return {k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in st.items()}


@router.get("/monitor/latest", response_model=MonitorTick | None)
def monitor_latest(conn: sqlite3.Connection = Depends(get_conn)) -> MonitorTick | None:
    """The most recent tick that raised alerts (ticks are idempotent, so a later quiet tick must not hide them);
    if none ever did, the most recent tick; null before the first tick."""
    row = conn.execute("SELECT body FROM monitor_ticks WHERE n_alerts > 0 ORDER BY seq DESC LIMIT 1").fetchone() \
        or conn.execute("SELECT body FROM monitor_ticks ORDER BY seq DESC LIMIT 1").fetchone()
    return MonitorTick.model_validate_json(row["body"]) if row else None
