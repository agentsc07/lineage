from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lineage.schemas.artifact import PolicyUpdate
from lineage.schemas.policy import PolicyPack
from lineage_server import db, log, policy_store, trust, tuf
from tests.server_helpers import NOW


@pytest.fixture
def keys():
    return {r: Ed25519PrivateKey.generate() for r in tuf.ROLES}


@pytest.fixture
def role_pub(keys):
    return {r: trust.public_hex(k.public_key()) for r, k in keys.items()}


@pytest.fixture
def pack(policy_path):
    return PolicyPack.from_yaml(policy_path)


def update(pack, keys, roles, days=90, mutate=None):
    p = pack.model_copy(update=mutate or {})
    exp = NOW + timedelta(days=days)
    sigs = [tuf.sign_update(p, exp, r, keys[r]) for r in roles]
    return PolicyUpdate(policy=p.model_dump(mode="json"), signatures=sigs, expires_at=exp)


def test_two_of_three_roles_accepted(pack, keys, role_pub):
    for roles in (["owner", "security"], ["security", "compliance"], ["owner", "security", "compliance"]):
        got = tuf.verify_update(update(pack, keys, roles), pack.version, role_pub, now=NOW)
        assert got == pack


def test_one_role_rejected(pack, keys, role_pub):
    with pytest.raises(ValueError, match="need 2 of 3"):
        tuf.verify_update(update(pack, keys, ["owner"]), pack.version, role_pub, now=NOW)


def test_same_role_twice_counts_once(pack, keys, role_pub):
    u = update(pack, keys, ["owner", "owner"])
    with pytest.raises(ValueError, match="need 2 of 3"):
        tuf.verify_update(u, pack.version, role_pub, now=NOW)


def test_wrong_key_or_unknown_role_does_not_count(pack, keys, role_pub):
    u = update(pack, keys, ["owner", "security"])
    u.signatures[1] = tuf.sign_update(pack, u.expires_at, "security", Ed25519PrivateKey.generate())
    with pytest.raises(ValueError, match="got 1 valid"):
        tuf.verify_update(u, pack.version, role_pub, now=NOW)
    u2 = update(pack, keys, ["owner"])
    u2.signatures.append(tuf.sign_update(pack, u2.expires_at, "intern", Ed25519PrivateKey.generate()))
    with pytest.raises(ValueError):
        tuf.verify_update(u2, pack.version, role_pub, now=NOW)


def test_signature_binds_policy_content_and_expiry(pack, keys, role_pub):
    u = update(pack, keys, ["owner", "security"])
    tampered = u.model_copy(update={"policy": {**u.policy, "thresholds": {"allow": 99, "quarantine": 99}}})
    with pytest.raises(ValueError, match="valid"):
        tuf.verify_update(tampered, pack.version, role_pub, now=NOW)
    longer = u.model_copy(update={"expires_at": u.expires_at + timedelta(days=365)})
    with pytest.raises(ValueError, match="valid"):
        tuf.verify_update(longer, pack.version, role_pub, now=NOW)


def test_metadata_must_expire_and_not_be_expired(pack, keys, role_pub):
    u = update(pack, keys, ["owner", "security"])
    with pytest.raises(ValueError, match="must carry an expiry"):
        tuf.verify_update(u.model_copy(update={"expires_at": None}), pack.version, role_pub, now=NOW)
    with pytest.raises(ValueError, match="already expired"):
        tuf.verify_update(u, pack.version, role_pub, now=NOW + timedelta(days=91))


def test_rollback_refused(pack, keys, role_pub):
    old = update(pack, keys, ["owner", "security"], days=60)
    with pytest.raises(ValueError, match="rollback"):
        tuf.verify_update(old, pack.version, role_pub, current_expires_at=NOW + timedelta(days=90), now=NOW)


def test_invalid_policy_document_rejected(pack, keys, role_pub):
    u = update(pack, keys, ["owner", "security"]).model_copy(update={"policy": {"org": "x"}})
    with pytest.raises(ValueError):  # pydantic ValidationError is a ValueError
        tuf.verify_update(u, pack.version, role_pub, now=NOW)


# --- persisted flow ---
@pytest.fixture
def store(tmp_path, pack, keys, role_pub):
    conn = db.connect(tmp_path / "t.db")
    db.init_schema(conn)
    policy_store.bootstrap(conn, pack, NOW + timedelta(days=30))
    policy_store.set_role_keys(conn, role_pub)
    return conn


def test_apply_update_changes_active_policy_and_logs(store, pack, keys):
    u = update(pack, keys, ["owner", "compliance"], mutate={"org": "Apollo Health AI v2"})
    state = policy_store.apply_update(store, u, now=NOW)
    assert state.policy["org"] == "Apollo Health AI v2" and state.version != pack.version
    assert {s.role for s in state.signatures} == {"owner", "compliance"}
    active, expired = policy_store.active(store, NOW)
    assert active.org.endswith("v2") and not expired
    assert [e.kind for e in log.read_log(store).entries][-1] == "policy"


def test_replaying_old_update_after_newer_one_is_a_rollback(store, pack, keys):
    first = update(pack, keys, ["owner", "security"], days=60, mutate={"org": "A"})
    second = update(pack, keys, ["owner", "security"], days=90, mutate={"org": "B"})
    policy_store.apply_update(store, first, now=NOW)
    policy_store.apply_update(store, second, now=NOW)
    with pytest.raises(ValueError, match="rollback"):
        policy_store.apply_update(store, first, now=NOW)
    assert policy_store.get_state(store).policy["org"] == "B"


def test_active_reports_expiry(store):
    _, expired = policy_store.active(store, NOW + timedelta(days=31))
    assert expired


def test_no_role_keys_disables_updates(tmp_path, pack, keys):
    conn = db.connect(tmp_path / "n.db")
    db.init_schema(conn)
    policy_store.bootstrap(conn, pack)
    with pytest.raises(policy_store.RoleKeysMissing):
        policy_store.apply_update(conn, update(pack, keys, ["owner", "security"]), now=NOW)


def test_cli_sign_produces_a_verifiable_update(tmp_path, pack, keys, role_pub, policy_path, capsys):
    paths = {}
    for role in ("owner", "security"):
        paths[role] = tmp_path / f"{role}.key"
        paths[role].write_text(trust_hex(keys[role]))
    tuf.main(["sign", str(policy_path), "--key", f"owner={paths['owner']}", "--key", f"security={paths['security']}", "--days", "60"])
    update = PolicyUpdate.model_validate_json(capsys.readouterr().out)
    assert tuf.verify_update(update, pack.version, role_pub) == pack
    with pytest.raises(SystemExit):
        tuf.main(["sign", str(policy_path), "--key", f"intern={paths['owner']}"])


def trust_hex(private_key):
    from cryptography.hazmat.primitives import serialization

    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()
