"""GET /artifacts, /artifacts/{id} (mock data until Track B)."""
from __future__ import annotations

from fastapi import APIRouter

from lineage.schemas.artifact import Artifact, ArtifactDetail
from lineage_server import mock

router = APIRouter()


@router.get("/artifacts", response_model=list[Artifact])
def list_artifacts() -> list[Artifact]:
    return mock.artifacts()


@router.get("/artifacts/{artifact_id}", response_model=ArtifactDetail)
def get_artifact(artifact_id: str) -> ArtifactDetail:
    return mock.artifact_detail(artifact_id)
