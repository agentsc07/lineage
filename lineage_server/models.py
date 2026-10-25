"""Row-level helpers between SQLite and the Pydantic contracts (Track B)."""
from __future__ import annotations

import sqlite3

from lineage.schemas.artifact import Artifact, ArtifactDetail
from lineage.schemas.decision import Decision
from lineage.schemas.passport import SignedPassport


def save_passport(conn: sqlite3.Connection, signed: SignedPassport) -> None:
    raise NotImplementedError


def save_decision(conn: sqlite3.Connection, decision: Decision) -> None:
    raise NotImplementedError


def list_artifacts(conn: sqlite3.Connection) -> list[Artifact]:
    raise NotImplementedError


def get_artifact(conn: sqlite3.Connection, artifact_id: str) -> ArtifactDetail | None:
    raise NotImplementedError
