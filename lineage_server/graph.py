"""Lineage graph queries (recursive CTE) and blast radius."""
from __future__ import annotations

import sqlite3
from typing import Literal

from lineage.schemas.artifact import Graph, GraphEdge, GraphNode

# Edges run parent -> child. "up" walks child -> parent; "down" walks parent -> child.
# UNION (not UNION ALL) de-duplicates rows, so a cycle in bad data still terminates.
_CTE = {
    "up": """
        WITH RECURSIVE reach(id) AS (
            SELECT :root
            UNION
            SELECT e.parent FROM edges e JOIN reach r ON e.child = r.id
        )""",
    "down": """
        WITH RECURSIVE reach(id) AS (
            SELECT :root
            UNION
            SELECT e.child FROM edges e JOIN reach r ON e.parent = r.id
        )""",
}


def _node(row: sqlite3.Row) -> GraphNode:
    return GraphNode(
        id=row["id"],
        label=f"{row['name']}@{row['version']}",
        artifact_type=row["artifact_type"],
        trust_level=row["trust_level"],
        status=row["status"],
        risk_score=row["risk_score"],
    )


def _ghost(row: sqlite3.Row) -> GraphNode:
    """A referenced thing Lineage never admitted (P6): shown, never silently dropped."""
    return GraphNode(id=row["id"], label=row["ref"] or f"{row['name']}@{row['version']}", artifact_type=row["artifact_type"],
                     trust_level="unknown", status="unregistered", risk_score=0)


def reachable(conn: sqlite3.Connection, artifact_id: str, direction: Literal["up", "down"]) -> list[GraphNode]:
    """Registered artifacts and ghost nodes reachable from `artifact_id` (inclusive), ordered by creation."""
    q = _CTE[direction]
    rows = conn.execute(q + " SELECT a.* FROM artifacts a JOIN reach ON a.id = reach.id ORDER BY a.created_at, a.rowid", {"root": artifact_id}).fetchall()
    ghosts = conn.execute(q + " SELECT g.* FROM ghosts g JOIN reach ON g.id = reach.id ORDER BY g.created_at, g.rowid", {"root": artifact_id}).fetchall()
    return [_ghost(g) for g in ghosts] + [_node(r) for r in rows]


def lineage_graph(conn: sqlite3.Connection, artifact_id: str, direction: Literal["up", "down"]) -> Graph:
    """Raises KeyError if `artifact_id` is neither registered nor a ghost. References to unadmitted things are ghost nodes."""
    nodes = reachable(conn, artifact_id, direction)
    if not any(n.id == artifact_id for n in nodes):
        raise KeyError(artifact_id)
    ids = {n.id for n in nodes}
    edges = [
        GraphEdge(source=r["parent"], target=r["child"], kind=r["kind"])
        for r in conn.execute("SELECT parent, child, kind FROM edges ORDER BY rowid")
        if r["parent"] in ids and r["child"] in ids
    ]
    return Graph(root=artifact_id, direction=direction, nodes=nodes, edges=edges)


def blast_radius(conn: sqlite3.Connection, artifact_id: str) -> list[GraphNode]:
    """Every descendant of `artifact_id` over every edge kind (not the artifact itself). The root may be a ghost."""
    return [n for n in reachable(conn, artifact_id, "down") if n.id != artifact_id]
