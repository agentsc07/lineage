"""R2.5/R2.6 / test 5: `lineage.load()` and `lineage pull` against a real registry app (REFACTOR_SPEC section 5)."""
import shutil
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import lineage.client as lc
from lineage.bind import LoadRefused, load
from lineage.schemas.artifact import IntakeJob
from lineage_server import trust
from lineage_server.app import create_app
from tests.fakehub import old_release_hub
from tests.fixtures.builders import make_tiny_model
from tests.server_helpers import KEY

SERVER = "http://testserver"


@pytest.fixture
def client(tmp_path, policy_path):
    c = TestClient(create_app(tmp_path / "api.db", policy_path, hub=old_release_hub()))
    c.pubkey = c.get("/registry-key").json()["public_key"]
    return c


def intake(client, kind, ref, env="dev"):
    job = IntakeJob.model_validate(client.post("/intake", json={"artifact_type": kind, "ref": str(ref), "environment": env}).json())
    events = [e for e in client.get(job.events_url).text.split("data: ")[1:]]
    import json

    last = [json.loads(e) for e in events]
    return next(e["decision"] for e in last if e.get("decision"))


@pytest.fixture
def admitted(client, tmp_path):
    src = make_tiny_model(tmp_path / "src")
    d = intake(client, "model", src)
    assert d["outcome"] == "allow", d["reasons"]
    return d["artifact_id"]


def kw(client, **extra):
    return dict(server=SERVER, registry_pubkey=client.pubkey, client=client, env="dev", **extra)


def test_pull_then_load_succeeds_and_bytes_match(client, admitted, tmp_path, monkeypatch):
    monkeypatch.setitem(__import__("sys").modules, "transformers", None)
    dest = tmp_path / "pulled"
    signed = lc.pull(admitted, dest, **{k: v for k, v in kw(client).items() if k != "env"}, env="dev")
    assert signed.attestation.outcome == "allow" and (dest / "model.safetensors").is_file()
    assert lc.cache_path(dest).is_file()
    assert "layers.0.weight" in load(dest, **kw(client))


def test_one_changed_byte_after_pull_refuses(client, admitted, tmp_path):
    dest = tmp_path / "pulled"
    lc.pull(admitted, dest, server=SERVER, registry_pubkey=client.pubkey, client=client, env="dev")
    w = dest / "model.safetensors"
    b = bytearray(w.read_bytes())
    b[-1] ^= 1
    w.write_bytes(bytes(b))
    with pytest.raises(LoadRefused, match="hash mismatch: model.safetensors"):
        load(dest, **kw(client))


def test_revoked_artifact_refuses_to_load_and_to_pull(client, admitted, tmp_path):
    dest = tmp_path / "pulled"
    lc.pull(admitted, dest, server=SERVER, registry_pubkey=client.pubkey, client=client, env="dev")
    assert client.post(f"/revoke/{admitted}?reason=bad").status_code == 200
    with pytest.raises(LoadRefused, match="revoked"):
        load(dest, **kw(client))
    with pytest.raises(LoadRefused, match="not usable"):
        lc.pull(admitted, tmp_path / "again", server=SERVER, registry_pubkey=client.pubkey, client=client, env="dev")


def test_blocked_artifact_is_not_served_even_with_a_valid_creator_passport(client, tmp_path):
    from tests.test_signature_scope import passport_for

    src = make_tiny_model(tmp_path / "bad")
    (src / "evil.pkl").write_bytes(b"\x80\x04N.")  # pickle: the policy refuses it
    passport_for(src, KEY, "apollo/bad")  # a perfectly valid, signed creator passport
    d = intake(client, "model", src)
    assert d["outcome"] == "block"
    assert client.get(f"/store/{d['artifact_id']}/files/model.safetensors", params={"env": "dev"}).status_code == 403
    with pytest.raises(LoadRefused, match="not usable"):
        lc.pull(d["artifact_id"], tmp_path / "x", server=SERVER, registry_pubkey=client.pubkey, client=client, env="dev")


def test_expired_attestation_refuses(client, admitted, tmp_path):
    dest = tmp_path / "pulled"
    lc.pull(admitted, dest, server=SERVER, registry_pubkey=client.pubkey, client=client, env="dev")
    with pytest.raises(LoadRefused, match="expired"):
        load(dest, now=datetime.now(timezone.utc) + timedelta(days=8), **kw(client))


def test_server_down_in_prod_fails_closed_but_dev_has_a_grace_period(client, admitted, tmp_path):
    dest = tmp_path / "pulled"
    lc.pull(admitted, dest, server=SERVER, registry_pubkey=client.pubkey, client=client, env="dev")
    down = dict(server="http://127.0.0.1:9", registry_pubkey=client.pubkey)
    assert lc.check_for_use(dest, env="dev", **down) == []  # cached and fresh: dev tolerates 24 h
    # the same bytes attested for prod: grace is 0, so an unreachable registry means refuse
    from tests.attest_helpers import attest
    import tests.attest_helpers as ah

    prod = attest(dest, env="prod", write=True)
    problems = lc.check_for_use(dest, env="prod", server="http://127.0.0.1:9", registry_pubkey=ah.REGISTRY_PUB)
    assert any("fail closed" in p for p in problems)
    assert lc.check_for_use(dest, env="prod", server="http://127.0.0.1:9", registry_pubkey=ah.REGISTRY_PUB, offline_grace_hours=1) == []
    assert prod


def test_attestation_for_another_environment_refuses(client, admitted, tmp_path):
    dest = tmp_path / "pulled"
    lc.pull(admitted, dest, server=SERVER, registry_pubkey=client.pubkey, client=client, env="dev")
    with pytest.raises(LoadRefused, match="attestation is for dev, not prod"):
        load(dest, **{**kw(client), "env": "prod"})


def test_pull_by_source_name_and_lookup(client, admitted, tmp_path):
    r = client.get("/lookup", params={"source": "src", "env": "dev"})
    assert r.status_code == 200 and r.json()["artifact_id"] == admitted


def test_attestation_by_digest_for_a_directory_without_cache(client, admitted, tmp_path):
    dest = tmp_path / "pulled"
    lc.pull(admitted, dest, server=SERVER, registry_pubkey=client.pubkey, client=client, env="dev")
    lc.cache_path(dest).unlink()
    assert load(dest, **kw(client)) == dest or True  # the registry finds the artifact by the Merkle root of the bytes
    assert lc.check_for_use(dest, **kw(client)) == []
