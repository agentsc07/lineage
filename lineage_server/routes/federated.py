"""Federated-learning gate: POST /fl/rounds, GET /fl/rounds/{id}, GET /fl/clients (REFACTOR_SPEC 8.6).

A round carries one flattened update (delta) per client, inline (base64 .npz with an array `delta`) or by `update_blob_sha256` of a
blob already in the store. Clients become graph nodes (`ghost:fl-client:<id>`, edge `contributed_to` the global model), so revoking a
client flags the global models it fed."""
from __future__ import annotations

import base64
import io
import json
import sqlite3
from datetime import datetime, timezone

import numpy as np
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from lineage.federated.gate import ClientState, process_round
from lineage.schemas.policy import PolicyPack
from lineage_server import log, models, service
from lineage_server.auth import require
from lineage_server.deps import get_conn, get_policy

router = APIRouter()


class UpdateIn(BaseModel):
    client_id: str
    update_blob_sha256: str | None = None
    inline: str | None = None  # base64 of an .npz with array `delta`
    claimed_norm: float | None = None  # secure aggregation: the norm the client claims


class RoundIn(BaseModel):
    round_id: str
    global_model_id: str
    updates: list[UpdateIn]
    secure_agg: bool = False


class ClientOut(BaseModel):
    client_id: str
    trust: float
    flagged_rounds: int
    clean_rounds: int
    quarantined: bool
    reasons: list[str]


class RoundOut(BaseModel):
    round_id: str
    global_model_id: str
    mode: str
    aggregator: str
    scores: dict[str, dict[str, float]]
    z: dict[str, dict[str, float]]
    flagged: dict[str, list[str]]
    excluded: list[str]
    newly_quarantined: list[str]
    notes: list[str]
    clients: list[ClientOut]
    aggregate: str  # base64 .npz with array `delta`


def _npz(arr: np.ndarray) -> str:
    b = io.BytesIO()
    np.savez_compressed(b, delta=arr)
    return base64.b64encode(b.getvalue()).decode()


def _load(u: UpdateIn, store) -> np.ndarray:
    try:
        if u.inline:
            return np.asarray(np.load(io.BytesIO(base64.b64decode(u.inline)))["delta"], float).ravel()
        if u.update_blob_sha256 and store.has(u.update_blob_sha256):
            return np.asarray(np.load(store.blob_path(u.update_blob_sha256))["delta"], float).ravel()
    except (ValueError, KeyError, OSError) as e:
        raise HTTPException(422, f"{u.client_id}: unreadable update ({e})")
    raise HTTPException(422, f"{u.client_id}: give inline or a known update_blob_sha256")


def _clients(conn: sqlite3.Connection) -> list[ClientOut]:
    return [ClientOut(client_id=r["client_id"], trust=round(r["trust"], 4), flagged_rounds=r["flagged_rounds"], clean_rounds=r["clean_rounds"],
                      quarantined=bool(r["quarantined"]), reasons=json.loads(r["reasons"])) for r in conn.execute("SELECT * FROM fl_clients ORDER BY client_id")]


@router.post("/fl/rounds", response_model=RoundOut, dependencies=[Depends(require("requester"))])
def post_round(req: RoundIn, request: Request, conn: sqlite3.Connection = Depends(get_conn), active: tuple[PolicyPack, bool] = Depends(get_policy)) -> RoundOut:
    if conn.execute("SELECT 1 FROM fl_rounds WHERE round_id = ?", (req.round_id,)).fetchone():
        raise HTTPException(409, f"round {req.round_id} was already processed")
    if models.artifact_row(conn, req.global_model_id) is None:
        raise HTTPException(404, f"unknown global model {req.global_model_id}")
    if not req.updates:
        raise HTTPException(422, "a round needs at least one update")
    updates = {u.client_id: _load(u, request.app.state.store) for u in req.updates}
    if len({len(v) for v in updates.values()}) != 1:
        raise HTTPException(422, "all updates must have the same length")
    states = {r["client_id"]: ClientState(r["client_id"], r["trust"], r["flagged_rounds"], r["clean_rounds"], bool(r["quarantined"]), json.loads(r["reasons"]))
              for r in conn.execute("SELECT * FROM fl_clients")}
    fl = active[0].fl
    res = process_round(updates, states, aggregator=fl.aggregator, f=fl.f, max_norm=fl.max_norm, z_threshold=fl.z_threshold, secure=req.secure_agg,
                        claimed_norms={u.client_id: u.claimed_norm for u in req.updates if u.claimed_norm is not None})
    now = datetime.now(timezone.utc)
    with conn:
        for cid, st in states.items():
            if cid not in updates:
                continue
            conn.execute("INSERT OR REPLACE INTO fl_clients (client_id, trust, flagged_rounds, clean_rounds, quarantined, reasons) VALUES (?, ?, ?, ?, ?, ?)",
                         (cid, st.trust, st.flagged_rounds, st.clean_rounds, int(st.quarantined), json.dumps(st.reasons)))
            gid = f"ghost:fl-client:{cid}"
            service.ensure_ghost(conn, gid, "model", cid, "", f"federated client {cid}")
            conn.execute("INSERT OR IGNORE INTO edges (parent, child, kind) VALUES (?, ?, 'contributed_to')", (gid, req.global_model_id))
        for cid in res.newly_quarantined:
            log.append(conn, "fl_quarantine", f"{req.round_id}:{cid}", now)
        out = RoundOut(round_id=req.round_id, global_model_id=req.global_model_id, mode=res.mode, aggregator=fl.aggregator, scores=res.scores, z=res.z,
                       flagged=res.flagged, excluded=res.excluded, newly_quarantined=res.newly_quarantined, notes=res.notes, clients=[],
                       aggregate=_npz(res.aggregate))
        conn.execute("INSERT INTO fl_rounds (round_id, global_model_id, body, created_at) VALUES (?, ?, ?, ?)",
                     (req.round_id, req.global_model_id, out.model_dump_json(), now.isoformat()))
    out.clients = _clients(conn)
    return out


@router.get("/fl/rounds/{round_id}", response_model=RoundOut)
def get_round(round_id: str, conn: sqlite3.Connection = Depends(get_conn)) -> RoundOut:
    row = conn.execute("SELECT body FROM fl_rounds WHERE round_id = ?", (round_id,)).fetchone()
    if row is None:
        raise HTTPException(404, f"unknown round {round_id}")
    out = RoundOut.model_validate_json(row["body"])
    out.clients = _clients(conn)
    return out


@router.get("/fl/clients", response_model=list[ClientOut])
def get_clients(conn: sqlite3.Connection = Depends(get_conn)) -> list[ClientOut]:
    return _clients(conn)


@router.get("/fl/rounds", response_model=list[str])
def list_rounds(conn: sqlite3.Connection = Depends(get_conn)) -> list[str]:
    return [r["round_id"] for r in conn.execute("SELECT round_id FROM fl_rounds ORDER BY rowid")]
