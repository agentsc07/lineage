"""GET /graph/{id}?direction=up|down."""
from __future__ import annotations

import sqlite3
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException

from lineage.schemas.artifact import Graph
from lineage_server import graph as graph_queries
from lineage_server.deps import get_conn

router = APIRouter()


@router.get("/graph/{artifact_id}", response_model=Graph)
def get_graph(
    artifact_id: str, direction: Literal["up", "down"] = "up", conn: sqlite3.Connection = Depends(get_conn)
) -> Graph:
    try:
        return graph_queries.lineage_graph(conn, artifact_id, direction)
    except KeyError:
        raise HTTPException(404, f"unknown artifact {artifact_id}")
