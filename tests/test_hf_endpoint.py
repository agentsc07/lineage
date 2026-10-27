"""R4.5: the HF-compatible endpoint serves admitted models with the headers huggingface_hub expects, and nothing else."""
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from lineage_server.app import create_app
from tests.fakehub import old_release_hub
from tests.fixtures.builders import make_tiny_model


@pytest.fixture
def api(tmp_path, policy_path):
    c = TestClient(create_app(tmp_path / "h.db", policy_path, hub=old_release_hub()))
    for name, extra in (("goodmodel", None), ("badmodel", b"\x80\x04N.")):
        m = make_tiny_model(tmp_path / name)
        if extra:
            (m / "w.pkl").write_bytes(extra)  # pickle: blocked by policy
        job = c.post("/intake", json={"artifact_type": "model", "ref": str(m), "environment": "dev"}).json()
        d = next(json.loads(e)["decision"] for e in c.get(job["events_url"]).text.split("data: ")[1:] if json.loads(e).get("decision"))
        setattr(c, name, d)
    return c


def test_model_info_lists_files_with_sizes_and_sha256(api):
    assert api.goodmodel["outcome"] == "allow"
    r = api.get("/api/models/goodmodel/revision/main", params={"env": "dev"})
    assert r.status_code == 200
    body = r.json()
    files = {s["rfilename"]: s for s in body["siblings"]}
    assert "model.safetensors" in files and len(files["model.safetensors"]["lfs"]["sha256"]) == 64 and body["sha"]


def test_resolve_serves_the_bytes_with_the_headers_huggingface_hub_reads(api):
    info = api.get("/api/models/goodmodel", params={"env": "dev"}).json()
    sha = info["sha"]
    head = api.head(f"/goodmodel/resolve/{sha}/model.safetensors", params={"env": "dev"})
    got = api.get(f"/goodmodel/resolve/{sha}/model.safetensors", params={"env": "dev"})
    for r in (head, got):
        assert r.status_code == 200 and r.headers["X-Repo-Commit"] == sha and r.headers["X-Linked-Size"] == str(len(got.content))
    assert got.headers["ETag"].strip('"') == hashlib.sha256(got.content).hexdigest()


def test_range_requests_work(api):
    r = api.get("/goodmodel/resolve/main/model.safetensors", params={"env": "dev"}, headers={"Range": "bytes=0-7"})
    assert r.status_code == 206 and len(r.content) == 8


def test_a_blocked_model_looks_like_it_does_not_exist(api):
    assert api.badmodel["outcome"] == "block"
    assert api.get("/api/models/badmodel/revision/main", params={"env": "dev"}).status_code == 404
    assert api.get("/badmodel/resolve/main/model.safetensors", params={"env": "dev"}).status_code == 404


def test_an_unknown_revision_or_file_is_a_404(api):
    assert api.get("/api/models/goodmodel/revision/deadbeef", params={"env": "dev"}).status_code == 404
    assert api.get("/goodmodel/resolve/main/nope.bin", params={"env": "dev"}).status_code == 404
