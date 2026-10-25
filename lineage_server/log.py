"""Append-only Merkle log with inclusion proofs.

Each entry's `entry_hash` chains to the previous entry (so history cannot be rewritten without
changing every later hash). The Merkle tree over the entries follows RFC 6962/9162:
`leaf = sha256(0x00 || entry_hash)`, `node = sha256(0x01 || left || right)`. SQL triggers reject
UPDATE and DELETE on the table.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from lineage.schemas.artifact import InclusionProof, LogEntry, MerkleLog
from lineage.schemas.passport import canonical_json, sha256_hex
from lineage_server.db import tx

EMPTY_ROOT = sha256_hex(b"")


def leaf_hash(entry_hash: str) -> str:
    return sha256_hex(b"\x00" + bytes.fromhex(entry_hash))


def _node(left: str, right: str) -> str:
    return sha256_hex(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right))


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return EMPTY_ROOT
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return _node(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def audit_path(leaves: list[str], index: int) -> list[str]:
    """Sibling hashes bottom-up proving leaf `index` is in the tree over `leaves`."""
    if len(leaves) <= 1:
        return []
    k = _split(len(leaves))
    if index < k:
        return audit_path(leaves[:k], index) + [merkle_root(leaves[k:])]
    return audit_path(leaves[k:], index - k) + [merkle_root(leaves[:k])]


def verify_inclusion(leaf: str, index: int, size: int, path: list[str], root: str) -> bool:
    """RFC 9162 §2.1.3.2 inclusion verification."""
    if index >= size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            r = _node(p, r)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def _utc(ts: datetime | None) -> datetime:
    return (ts or datetime.now(timezone.utc)).astimezone(timezone.utc)


def _row_to_entry(row: sqlite3.Row) -> LogEntry:
    return LogEntry(
        index=row["idx"],
        entry_hash=row["entry_hash"],
        kind=row["kind"],
        ref=row["ref"],
        ts=datetime.fromisoformat(row["ts"]),
    )


def _entry_hash(index: int, kind: str, ref: str, ts: datetime, prev: str) -> str:
    return sha256_hex(canonical_json({"index": index, "kind": kind, "ref": ref, "ts": ts.isoformat(), "prev": prev}))


def append(conn: sqlite3.Connection, kind: str, ref: str, ts: datetime | None = None) -> LogEntry:
    ts = _utc(ts)
    with tx(conn):
        last = conn.execute("SELECT idx, entry_hash FROM log ORDER BY idx DESC LIMIT 1").fetchone()
        index = 0 if last is None else last["idx"] + 1
        prev = "" if last is None else last["entry_hash"]
        entry_hash = _entry_hash(index, kind, ref, ts, prev)
        conn.execute(
            "INSERT INTO log (idx, entry_hash, kind, ref, ts) VALUES (?, ?, ?, ?, ?)",
            (index, entry_hash, kind, ref, ts.isoformat()),
        )
    return LogEntry(index=index, entry_hash=entry_hash, kind=kind, ref=ref, ts=ts)


def _entries(conn: sqlite3.Connection) -> list[LogEntry]:
    return [_row_to_entry(r) for r in conn.execute("SELECT * FROM log ORDER BY idx")]


def read_log(conn: sqlite3.Connection) -> MerkleLog:
    entries = _entries(conn)
    return MerkleLog(size=len(entries), root=merkle_root([leaf_hash(e.entry_hash) for e in entries]), entries=entries)


def verify_chain(conn: sqlite3.Connection) -> bool:
    """Recompute every entry hash from its predecessor; False if the table was tampered with."""
    prev = ""
    for e in _entries(conn):
        if e.entry_hash != _entry_hash(e.index, e.kind, e.ref, e.ts, prev):
            return False
        prev = e.entry_hash
    return True


def inclusion_proof(conn: sqlite3.Connection, ref: str) -> InclusionProof:
    """Proof for the earliest entry whose `ref` matches (a numeric `ref` with no match is an entry index).

    `leaf_hash` is the tree leaf (`sha256(0x00 || entry_hash)`); `path` is bottom-up. Raises KeyError if unknown.
    """
    entries = _entries(conn)
    match = next((e for e in entries if e.ref == ref), None)
    if match is None and ref.isdigit() and int(ref) < len(entries):
        match = entries[int(ref)]
    if match is None:
        raise KeyError(ref)
    leaves = [leaf_hash(e.entry_hash) for e in entries]
    return InclusionProof(
        index=match.index,
        leaf_hash=leaves[match.index],
        path=audit_path(leaves, match.index),
        root=merkle_root(leaves),
        size=len(leaves),
    )
