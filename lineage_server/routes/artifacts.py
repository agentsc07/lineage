"""GET /artifacts, /artifacts/{id}."""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException

from lineage.schemas.artifact import Artifact, ArtifactDetail
from lineage_server import models
from lineage_server.deps import get_conn

router = APIRouter()


@router.get("/artifacts", response_model=list[Artifact])
def list_artifacts(conn: sqlite3.Connection = Depends(get_conn)) -> list[Artifact]:
    return models.list_artifacts(conn)


@router.get("/artifacts/{artifact_id}", response_model=ArtifactDetail)
def get_artifact(artifact_id: str, conn: sqlite3.Connection = Depends(get_conn)) -> ArtifactDetail:
    detail = models.get_artifact(conn, artifact_id)
    if detail is None:
        raise HTTPException(404, f"unknown artifact {artifact_id}")
    return detail
