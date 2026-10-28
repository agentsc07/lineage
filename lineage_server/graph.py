"""Lineage graph queries (recursive CTE) and blast radius."""
from __future__ import annotations

import json
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


def _short_version(v: str | None) -> str:
    """A hub revision is a 12-character commit prefix; show 7 (the usual git short form) so the node label fits."""
    import re
    return v[:7] if v and re.fullmatch(r"[0-9a-f]{12}", v) else (v or "")


def _node(row: sqlite3.Row) -> GraphNode:
    return GraphNode(
        id=row["id"],
        label=f"{row['name']}@{_short_version(row['version'])}",
        artifact_type=row["artifact_type"],
        trust_level=row["trust_level"],
        status=row["status"],
        risk_score=row["risk_score"],
    )


def _ghost(row: sqlite3.Row) -> GraphNode:
    """A referenced thing Lineage never admitted (P6): shown, never silently dropped."""
    return GraphNode(id=row["id"], label=row["ref"] or f"{row['name']}@{_short_version(row['version'])}", artifact_type=row["artifact_type"],
                     trust_level="unknown", status="unregistered", risk_score=0, version=row["version"] or None,
                     advisories=json.loads(row["advisories"] or "[]") if "advisories" in row.keys() else [])


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
    ghost_ids = {n.id for n in nodes if n.status == "unregistered"}
    edges = [
        GraphEdge(source=r["parent"], target=r["child"], kind=r["kind"], evidence=_evidence(conn, r["parent"], r["child"], r["kind"], r["parent"] in ghost_ids))
        for r in conn.execute("SELECT parent, child, kind FROM edges ORDER BY rowid")
        if r["parent"] in ids and r["child"] in ids
    ]
    return Graph(root=artifact_id, direction=direction, nodes=nodes, edges=edges)


def _evidence(conn: sqlite3.Connection, parent: str, child: str, kind: str, parent_is_ghost: bool) -> str:
    """How the edge came to exist, from how intake creates edges (pipeline._graph_refs, inspectors.local_parent_diff): an SBOM or a recorded
    training input from a verified `lineage run` passport, a dependency read from fetched package metadata, a base model named by a trusted
    fact, a parent matched from the weights, or a parent id the uploader listed."""
    if kind == "built_with":
        return "sbom"
    if kind == "trained_on":
        return "recorded"
    if kind == "depends_on":
        return "fetched"
    if kind == "derived_from":
        if conn.execute("SELECT 1 FROM findings WHERE artifact_id = ? AND finding_id = 'MODEL.PARENT.IDENTIFIED'", (child,)).fetchone():
            return "inferred-from-weights"
        return "fetched" if parent_is_ghost else "declared"
    return "declared"


MIN_GROUP = 3
GROUP_LABEL = {"built_with": "packages in the build environment (SBOM; not admitted)", "contributed_to": "federated clients (not admitted)"}


def collapse_sbom(conn: sqlite3.Connection, g: Graph) -> Graph:
    """Per artifact, fold its un-advised SBOM ghosts (`built_with` from a package nobody admitted) into ONE group node that lists them in
    `group_members`. A ghost with an advisory is never folded: it is the thing a reader needs to see."""
    ghost = {n.id: n for n in g.nodes if n.status == "unregistered"}
    by_child: dict[tuple[str, str], list[GraphEdge]] = {}
    for e in g.edges:
        n = ghost.get(e.source)
        if e.kind in GROUP_LABEL and n is not None and not n.advisories:
            by_child.setdefault((e.target, e.kind), []).append(e)
    drop_nodes: set[str] = set()
    drop_edges: set[tuple[str, str]] = set()
    nodes, edges = list(g.nodes), list(g.edges)
    for (child, kind), es in by_child.items():
        if len(es) < MIN_GROUP:
            continue
        members = [ghost[e.source] for e in es]
        gid = f"sbom-group:{child}" if kind == "built_with" else f"fl-group:{child}"
        nodes.append(GraphNode(id=gid, label=f"{len(members)} {GROUP_LABEL[kind]}", artifact_type=members[0].artifact_type, trust_level="unknown",
                               status="unregistered", risk_score=0, group_members=members))
        edges.append(GraphEdge(source=gid, target=child, kind=kind, evidence="sbom" if kind == "built_with" else es[0].evidence))
        drop_edges |= {(e.source, e.target) for e in es}
        drop_nodes |= {m.id for m in members}
    still_used = {e.source for e in edges if (e.source, e.target) not in drop_edges}
    return Graph(root=g.root, direction=g.direction, nodes=[n for n in nodes if n.id not in drop_nodes or n.id in still_used],
                 edges=[e for e in edges if (e.source, e.target) not in drop_edges])


def blast_radius(conn: sqlite3.Connection, artifact_id: str) -> list[GraphNode]:
    """Every descendant of `artifact_id` over every edge kind (not the artifact itself). The root may be a ghost."""
    return [n for n in reachable(conn, artifact_id, "down") if n.id != artifact_id]
