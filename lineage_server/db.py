"""SQLite connection and schema (Track B)."""
from __future__ import annotations

import sqlite3
from pathlib import Path

DEFAULT_DB = Path("lineage.db")


def connect(path: Path = DEFAULT_DB) -> sqlite3.Connection:
    raise NotImplementedError


def init_schema(conn: sqlite3.Connection) -> None:
    """Tables: artifacts, passports, findings, decisions, edges, revocations, log."""
    raise NotImplementedError
