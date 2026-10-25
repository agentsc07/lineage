"""SSE /events/{job}, GET /log, /log/proof/{id}, POST /monitor/tick (mock data until Track B)."""
from __future__ import annotations

from collections.abc import Iterator

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from lineage.schemas.artifact import Alert, InclusionProof, MerkleLog, MonitorTick
from lineage_server import mock

router = APIRouter()


def _sse(job_id: str) -> Iterator[str]:
    for event in mock.stage_events(job_id):
        yield f"data: {event.model_dump_json()}\n\n"


@router.get("/events/{job_id}")
def events(job_id: str) -> StreamingResponse:
    return StreamingResponse(_sse(job_id), media_type="text/event-stream")


@router.get("/log", response_model=MerkleLog)
def get_log() -> MerkleLog:
    return mock.merkle_log()


@router.get("/log/proof/{ref}", response_model=InclusionProof)
def get_proof(ref: str) -> InclusionProof:
    return mock.inclusion_proof(ref)


@router.post("/monitor/tick", response_model=MonitorTick)
def monitor_tick() -> MonitorTick:
    alert = Alert(
        artifact_id=mock.DATASET_ID,
        kind="advisory",
        severity="high",
        message="GHSA-mock-0001 published for an admitted package",
        blast_radius=mock.blast_radius(mock.DATASET_ID),
    )
    return MonitorTick(checked=3, alerts=[alert], ts=mock.NOW)
