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
    artifact_id: str, direction: Literal["up", "down"] = "up", collapse: bool = True, conn: sqlite3.Connection = Depends(get_conn)
) -> Graph:
    """`collapse` (default) folds each artifact's un-advised SBOM packages into one group node; `collapse=false` returns every node."""
    try:
        g = graph_queries.lineage_graph(conn, artifact_id, direction)
        return graph_queries.collapse_sbom(conn, g) if collapse else g
    except KeyError:
        raise HTTPException(404, f"unknown artifact {artifact_id}")
