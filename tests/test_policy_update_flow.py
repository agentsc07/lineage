"""P0.1: the policy page never makes signatures. The supported flow is: sign outside the browser (`python -m lineage_server.tuf sign`), submit with
`PUT /policy` as an admin; a fake "signature" such as the SHA-256 digest the old dashboard produced is refused."""
import base64
import hashlib
import json

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from lineage_server import auth, db, trust, tuf
from lineage_server.app import create_app


def raw_hex(k):
    return k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()


@pytest.fixture
def stack(tmp_path, policy_path):
    keys = {r: Ed25519PrivateKey.generate() for r in tuf.ROLES}
    roles = tmp_path / "roles.json"
    roles.write_text(json.dumps({r: trust.public_hex(k.public_key()) for r, k in keys.items()}))
    app = create_app(tmp_path / "p.db", policy_path, role_keys_path=roles, require_auth=True)
    conn = db.connect(tmp_path / "p.db")
    tokens = {"admin": auth.create_user(conn, "carol", "admin"), "req": auth.create_user(conn, "alice", "requester")}
    conn.commit()
    c = TestClient(app)
    c.keys, c.tokens, c.tmp = keys, tokens, tmp_path
    return c


def new_policy(stack, policy_path):
    d = yaml.safe_load(open(policy_path))
    d["thresholds"]["allow"] = 31  # the policy version is a hash of the rules, so a real change is needed
    p = stack.tmp / "new.yaml"
    p.write_text(yaml.safe_dump(d))
    return p


def sign_with_cli(stack, policy_file, roles, capsys):
    argv = ["sign", str(policy_file), "--days", "90"]
    for r in roles:
        kf = stack.tmp / f"{r}.key"
        kf.write_text(raw_hex(stack.keys[r]))
        argv += ["--key", f"{r}={kf}"]
    tuf.main(argv)
    return json.loads(capsys.readouterr().out)


def put(stack, body, who="admin"):
    return stack.put("/policy", json=body, headers={"Authorization": f"Bearer {stack.tokens[who]}"})


def test_an_update_signed_outside_the_browser_by_two_roles_is_installed(stack, policy_path, capsys):
    body = sign_with_cli(stack, new_policy(stack, policy_path), ["owner", "security"], capsys)
    before = stack.get("/policy", headers={"Authorization": f"Bearer {stack.tokens['admin']}"}).json()["version"]
    r = put(stack, body)
    assert r.status_code == 200 and r.json()["version"] != before and {s["role"] for s in r.json()["signatures"]} == {"owner", "security"}
    assert r.json()["policy"]["thresholds"]["allow"] == 31


def test_one_signature_is_not_enough(stack, policy_path, capsys):
    body = sign_with_cli(stack, new_policy(stack, policy_path), ["owner"], capsys)
    assert put(stack, body).status_code == 403  # threshold not met: fewer than 2 valid role signatures


def test_the_sha256_digest_the_old_dashboard_sent_is_refused(stack, policy_path, capsys):
    body = sign_with_cli(stack, new_policy(stack, policy_path), ["owner", "security"], capsys)
    text = json.dumps(body["policy"])
    for s in body["signatures"]:  # what the old Policy page did: a hash of "role\ntext" in place of an Ed25519 signature
        s["signature"] = base64.b64encode(hashlib.sha256(f"{s['role']}\n{text}".encode()).digest()).decode()
    assert put(stack, body).status_code == 403  # threshold not met: fewer than 2 valid role signatures


def test_only_an_admin_can_submit_even_a_valid_update(stack, policy_path, capsys):
    body = sign_with_cli(stack, new_policy(stack, policy_path), ["owner", "security"], capsys)
    assert put(stack, body, who="req").status_code == 403
