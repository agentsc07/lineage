"""Request-scoped dependencies: one SQLite connection per request, the active policy, the registry."""
from __future__ import annotations

import sqlite3
from collections.abc import Iterator

from fastapi import Depends, HTTPException, Request

from lineage.schemas.policy import PolicyPack
from lineage_server import db, policy_store
from lineage_server.registry import SqliteRegistry


def get_conn(request: Request) -> Iterator[sqlite3.Connection]:
    conn = db.connect(request.app.state.db_path)
    try:
        yield conn
    finally:
        conn.close()


def get_policy(conn: sqlite3.Connection = Depends(get_conn)) -> tuple[PolicyPack, bool]:
    """(active policy, metadata expired?)"""
    try:
        return policy_store.active(conn)
    except LookupError:
        raise HTTPException(503, "no policy installed")


def get_registry(request: Request, conn: sqlite3.Connection = Depends(get_conn)) -> SqliteRegistry:
    return SqliteRegistry(conn, request.app.state.signing_key)
