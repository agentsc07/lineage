"""Continuous watch: re-query advisories for admitted packages, raise alerts + blast radius (Track B)."""
from __future__ import annotations

import sqlite3

from lineage.schemas.artifact import MonitorTick


def tick(conn: sqlite3.Connection) -> MonitorTick:
    raise NotImplementedError
