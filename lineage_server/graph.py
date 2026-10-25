"""Lineage graph queries (recursive CTE) and blast radius (Track B)."""
from __future__ import annotations

import sqlite3
from typing import Literal

from lineage.schemas.artifact import Graph, GraphNode


def lineage_graph(conn: sqlite3.Connection, artifact_id: str, direction: Literal["up", "down"]) -> Graph:
    raise NotImplementedError


def blast_radius(conn: sqlite3.Connection, artifact_id: str) -> list[GraphNode]:
    """Every descendant of `artifact_id`."""
    raise NotImplementedError
