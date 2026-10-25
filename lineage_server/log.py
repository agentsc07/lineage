"""Append-only Merkle log with inclusion proofs (Track B)."""
from __future__ import annotations

import sqlite3

from lineage.schemas.artifact import InclusionProof, LogEntry, MerkleLog


def append(conn: sqlite3.Connection, kind: str, ref: str) -> LogEntry:
    raise NotImplementedError


def read_log(conn: sqlite3.Connection) -> MerkleLog:
    raise NotImplementedError


def inclusion_proof(conn: sqlite3.Connection, ref: str) -> InclusionProof:
    raise NotImplementedError
