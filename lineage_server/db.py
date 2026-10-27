"""SQLite connection and schema."""
from __future__ import annotations

import os
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

DEFAULT_DB = Path(os.environ.get("LINEAGE_DB", "lineage.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS passports (
    id TEXT PRIMARY KEY,
    body TEXT NOT NULL,              -- SignedPassport JSON (by alias)
    key_id TEXT NOT NULL,
    merkle_root TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS passports_merkle ON passports(merkle_root);

CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY REFERENCES passports(id),
    artifact_type TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    trust_level TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    status TEXT NOT NULL,
    environment TEXT NOT NULL,
    outcome TEXT,
    released_at TEXT,                -- upstream publication time, used by cooldown
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS artifacts_name ON artifacts(artifact_type, name, version);

CREATE TABLE IF NOT EXISTS findings (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id),
    finding_id TEXT NOT NULL,
    body TEXT NOT NULL               -- Finding JSON
);
CREATE INDEX IF NOT EXISTS findings_artifact ON findings(artifact_id);

CREATE TABLE IF NOT EXISTS decisions (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id),
    environment TEXT NOT NULL,
    outcome TEXT NOT NULL,
    body TEXT NOT NULL,              -- Decision JSON
    decided_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS decisions_artifact ON decisions(artifact_id, seq);

CREATE TABLE IF NOT EXISTS approvals (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id),
    approver TEXT NOT NULL,
    reason TEXT NOT NULL,
    expires TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS edges (
    parent TEXT NOT NULL,            -- passport id of the parent
    child TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'derived_from',
    PRIMARY KEY (parent, child)
);
CREATE INDEX IF NOT EXISTS edges_child ON edges(child);

CREATE TABLE IF NOT EXISTS rejections (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id TEXT NOT NULL,
    actor TEXT NOT NULL,             -- the authenticated approver, never a typed name
    reason TEXT NOT NULL,
    rejected_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS revocations (
    artifact_id TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    revoked_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS log (
    idx INTEGER PRIMARY KEY,         -- 0-based, dense
    entry_hash TEXT NOT NULL,
    kind TEXT NOT NULL,
    ref TEXT NOT NULL,
    ts TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS log_ref ON log(ref);
CREATE TRIGGER IF NOT EXISTS log_no_update BEFORE UPDATE ON log
BEGIN SELECT RAISE(ABORT, 'log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS log_no_delete BEFORE DELETE ON log
BEGIN SELECT RAISE(ABORT, 'log is append-only'); END;

CREATE TABLE IF NOT EXISTS policy_state (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    version TEXT NOT NULL,
    policy TEXT NOT NULL,            -- PolicyPack JSON
    signatures TEXT NOT NULL,        -- list[PolicySignature] JSON
    expires_at TEXT,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS role_keys (
    role TEXT PRIMARY KEY,           -- owner | security | compliance
    key_id TEXT NOT NULL,
    public_key TEXT NOT NULL         -- raw Ed25519 public key, hex
);

CREATE TABLE IF NOT EXISTS trusted_keys (
    key_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,        -- raw Ed25519 public key, hex
    owner TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifact_meta (
    artifact_id TEXT PRIMARY KEY,
    requester TEXT,                  -- who asked for the intake (separation of duties)
    source TEXT,
    claimed_origin TEXT,
    claims TEXT,                     -- JSON, all `declared`
    distribution TEXT,               -- JSON {filename, sha256}: the wheel served by /simple
    source_id TEXT,
    signer_key TEXT                  -- key id of the in-scope creator passport, if any (monitor re-decides when it is revoked)
);

CREATE TABLE IF NOT EXISTS artifact_identity (
    artifact_id TEXT PRIMARY KEY,
    body TEXT NOT NULL               -- JSON: files (path, size, sha256, origin comparison), facts with provenance, claimed origin
);

CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY,
    requester TEXT,
    artifact_type TEXT,
    environment TEXT,
    label TEXT,                      -- what was asked for (upload filename or hub source)
    created_at TEXT NOT NULL,
    done INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS job_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    body TEXT NOT NULL               -- StageEvent JSON
);
CREATE INDEX IF NOT EXISTS job_events_job ON job_events(job_id, seq);

CREATE TABLE IF NOT EXISTS ghosts (
    id TEXT PRIMARY KEY,             -- the referenced id: `ghost:<type>:<name>@<version>` or an unregistered `lp:...`
    artifact_type TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    ref TEXT NOT NULL,               -- the reference that created it
    advisories TEXT NOT NULL DEFAULT '[]',
    revoked_reason TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    token_hash TEXT PRIMARY KEY,     -- sha256 of the bearer token; the token itself is never stored
    name TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL DEFAULT '',
    roles TEXT NOT NULL,             -- comma-separated: requester, approver, admin, auditor
    env TEXT NOT NULL DEFAULT 'prod' -- the environment this token's package index serves
);

CREATE TABLE IF NOT EXISTS fl_clients (
    client_id TEXT PRIMARY KEY,
    trust REAL NOT NULL,
    flagged_rounds INTEGER NOT NULL DEFAULT 0,
    clean_rounds INTEGER NOT NULL DEFAULT 0,
    quarantined INTEGER NOT NULL DEFAULT 0,
    reasons TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS fl_rounds (
    round_id TEXT PRIMARY KEY,
    global_model_id TEXT NOT NULL,
    body TEXT NOT NULL,              -- RoundOut JSON
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS monitor_ticks (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    n_alerts INTEGER NOT NULL,
    body TEXT NOT NULL               -- MonitorTick JSON
);

CREATE TABLE IF NOT EXISTS tool_pins (
    artifact_id TEXT PRIMARY KEY REFERENCES artifacts(id),
    tool_name TEXT NOT NULL,
    description_sha256 TEXT NOT NULL,
    code_sha256 TEXT NOT NULL
);
"""


def connect(path: Path | str = DEFAULT_DB) -> sqlite3.Connection:
    """Open `path` (autocommit; use `tx()` for transactions) with foreign keys and WAL on."""
    conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if str(path) != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    """Tables: artifacts, passports, findings, decisions, edges, revocations, log (+ policy/key/pin tables)."""
    conn.executescript(SCHEMA)


@contextmanager
def tx(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Write transaction. Takes the write lock up front; nested calls become savepoints."""
    if conn.in_transaction:
        name = "sp_" + uuid.uuid4().hex[:8]
        conn.execute(f"SAVEPOINT {name}")
        try:
            yield conn
        except BaseException:
            conn.execute(f"ROLLBACK TO {name}")
            conn.execute(f"RELEASE {name}")
            raise
        conn.execute(f"RELEASE {name}")
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")
