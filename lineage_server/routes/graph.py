"""GET /graph/{id}?direction=up|down (mock data until Track B)."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter

from lineage.schemas.artifact import Graph
from lineage_server import mock

router = APIRouter()


@router.get("/graph/{artifact_id}", response_model=Graph)
def get_graph(artifact_id: str, direction: Literal["up", "down"] = "up") -> Graph:
    return mock.graph(artifact_id, direction)
