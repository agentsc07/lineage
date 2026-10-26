import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from lineage_server import trust
from lineage_server.app import create_app


def test_trusted_keys_env_trusts_hex_key_at_startup(tmp_path, policy_path, monkeypatch):
    key = Ed25519PrivateKey.generate().public_key()
    monkeypatch.setenv("LINEAGE_TRUSTED_KEYS", trust.public_hex(key))
    create_app(tmp_path / "t.db", policy_path)
    rows = sqlite3.connect(tmp_path / "t.db").execute("SELECT key_id FROM trusted_keys").fetchall()
    assert (trust.key_id(key),) in rows


def test_monitor_latest_is_null_before_any_tick_and_survives_a_quiet_tick(tmp_path, policy_path):
    client = TestClient(create_app(tmp_path / "t.db", policy_path))
    assert client.get("/monitor/latest").json() is None
    client.post("/monitor/tick")
    latest = client.get("/monitor/latest").json()
    assert latest["alerts"] == [] and latest["checked"] == 0
