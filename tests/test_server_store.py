import sqlite3

import pytest

from lineage_server import db, log, models
from tests.server_helpers import finding, make_signed


@pytest.fixture
def conn(tmp_path):
    c = db.connect(tmp_path / "t.db")
    db.init_schema(c)
    return c


def test_schema_has_required_tables(conn):
    names = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"artifacts", "passports", "findings", "decisions", "edges", "revocations", "log"} <= names


def test_save_passport_roundtrip_edges_and_log(conn):
    parent = make_signed("ds", "dataset")
    child = make_signed("m", "model", parents=[parent.passport_id])
    assert models.save_passport(conn, parent)
    assert models.save_passport(conn, child)
    assert not models.save_passport(conn, child)  # idempotent
    assert models.get_signed_passport(conn, child.passport_id) == child
    assert conn.execute("SELECT parent, child FROM edges").fetchone()["parent"] == parent.passport_id
    assert [e.kind for e in log.read_log(conn).entries] == ["passport", "passport"]
    assert models.find_by_merkle_root(conn, child.passport.predicate.contents.merkle_root) == child.passport_id


def test_findings_and_artifact_detail(conn):
    sp = make_signed("pkg")
    models.save_passport(conn, sp)
    models.save_findings(conn, sp.passport_id, [finding("A.ONE"), finding("A.TWO", "high", 25)])
    detail = models.get_artifact(conn, sp.passport_id)
    assert [f.id for f in detail.findings] == ["A.ONE", "A.TWO"]
    assert detail.artifact.status == "submitted" and detail.decision is None
    assert models.get_artifact(conn, "lp:nope") is None
    assert len(models.list_artifacts(conn)) == 1


def test_transaction_rolls_back(conn):
    sp = make_signed("pkg")
    with pytest.raises(RuntimeError):
        with db.tx(conn):
            conn.execute("DELETE FROM edges")
            models.save_passport(conn, sp)
            raise RuntimeError
    assert models.list_artifacts(conn) == [] and log.read_log(conn).size == 0


def test_log_is_append_only(conn):
    log.append(conn, "passport", "lp:1")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("UPDATE log SET ref = 'x'")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("DELETE FROM log")


@pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 13])
def test_merkle_inclusion_proofs_verify(conn, n):
    for i in range(n):
        log.append(conn, "passport", f"lp:{i}")
    for i in range(n):
        p = log.inclusion_proof(conn, f"lp:{i}")
        assert p.index == i and p.size == n
        assert log.verify_inclusion(p.leaf_hash, p.index, p.size, p.path, p.root)
    bad = log.inclusion_proof(conn, "lp:0")
    assert not log.verify_inclusion(log.leaf_hash("00" * 32), bad.index, bad.size, bad.path, bad.root)


def test_log_root_changes_and_detects_tampering(conn):
    log.append(conn, "passport", "lp:a")
    r1 = log.read_log(conn).root
    log.append(conn, "decision", "lp:a")
    assert log.read_log(conn).root != r1 and log.verify_chain(conn)
    conn.execute("DROP TRIGGER log_no_update")
    conn.execute("UPDATE log SET ref = 'lp:evil' WHERE idx = 0")
    assert not log.verify_chain(conn)


def test_inclusion_proof_unknown_ref(conn):
    with pytest.raises(KeyError):
        log.inclusion_proof(conn, "lp:missing")
