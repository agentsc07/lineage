import json
import sys

import pytest
from typer.testing import CliRunner

from lineage.cli import app
from lineage.hashing.bench import bench_hash

runner = CliRunner()


def invoke(*args, **kw):
    r = runner.invoke(app, [str(a) for a in args], **kw)
    return r


def test_bench_hash_synthetic_reports_throughput():
    rows = bench_hash(size_mb=4, files=4)
    names = [r.name for r in rows]
    assert names == ["single-thread file", "parallel tree", "safetensors per-tensor"]
    assert all(r.gb_per_s > 0 and r.bytes > 0 for r in rows)


def test_bench_hash_on_path(tiny_model):
    rows = bench_hash(path=tiny_model)
    assert any(r.name == "parallel tree" for r in rows)


def test_cli_bench_hash():
    r = invoke("bench", "hash", "--size-mb", 2, "--files", 2)
    assert r.exit_code == 0 and "GB/s" in r.output and "parallel tree" in r.output


def test_cli_bench_corpus_still_stub():
    assert invoke("bench", "corpus").exit_code == 2


def test_keygen_sign_verify_roundtrip(tmp_path, tiny_model):
    r = invoke("keygen", "--dir", tmp_path / "keys")
    assert r.exit_code == 0 and "key id" in r.output.lower()
    out = tmp_path / "m.passport.json"
    r = invoke("sign", tiny_model, "--key", tmp_path / "keys/lineage.key", "--out", out, "--name", "tiny", "--version", "1.2.3")
    assert r.exit_code == 0 and "lp:" in r.output and out.exists()
    r = invoke("verify", out, "--artifact", tiny_model, "--pubkey", tmp_path / "keys/lineage.pub")
    assert r.exit_code == 0 and "VALID" in r.output and "INVALID" not in r.output


def test_verify_fails_on_tamper_with_evidence(tmp_path, tiny_model):
    invoke("keygen", "--dir", tmp_path)
    out = tmp_path / "p.json"
    invoke("sign", tiny_model, "--key", tmp_path / "lineage.key", "--out", out)
    (tiny_model / "config.json").write_text("{}")
    r = invoke("verify", out, "--artifact", tiny_model, "--pubkey", tmp_path / "lineage.pub")
    assert r.exit_code == 1 and "INVALID" in r.output and "config.json" in r.output


def test_sign_with_parent_and_trust(tmp_path, tiny_dataset):
    invoke("keygen", "--dir", tmp_path)
    out = tmp_path / "d.json"
    r = invoke("sign", tiny_dataset, "--type", "dataset", "--key", tmp_path / "lineage.key", "--out", out,
               "--parent", "lp:abc")
    assert r.exit_code == 0
    body = json.loads(out.read_text())["passport"]["predicate"]
    assert body["parents"] == ["lp:abc"] and body["trust_level"] == "unknown"  # the signer never claims trust


def test_diff_command_shows_changed_layer(tiny_model, tiny_model_child):
    r = invoke("diff", tiny_model, tiny_model_child)
    assert r.exit_code == 0 and "layers.1.weight" in r.output and "1 of 4" in r.output
    assert "layers.0.bias" not in r.output  # unchanged hidden by default
    assert "layers.0.bias" in invoke("diff", tiny_model, tiny_model_child, "--all").output


def test_diff_json(tiny_model, tiny_model_child):
    r = invoke("diff", tiny_model, tiny_model_child, "--json")
    rows = json.loads(r.output)
    assert {x["tensor"] for x in rows if x["changed"]} == {"layers.1.weight"}


def test_run_command_end_to_end(tmp_path, monkeypatch):
    (tmp_path / "go.py").write_text("open('o.txt','w').write('x')")
    monkeypatch.chdir(tmp_path)
    r = invoke("run", "--", sys.executable, "go.py")
    assert r.exit_code == 0 and "recorded" in r.output and "o.txt" in r.output
    runs = list((tmp_path / ".lineage/runs").glob("*/passport.json"))
    assert len(runs) == 1


def test_run_propagates_exit_code(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    r = invoke("run", "--", sys.executable, "-c", "import sys; sys.exit(4)")
    assert r.exit_code == 4


def test_run_signs_when_key_given(tmp_path, monkeypatch):
    invoke("keygen", "--dir", tmp_path)
    monkeypatch.chdir(tmp_path)
    r = invoke("run", "--key", tmp_path / "lineage.key", "--", sys.executable, "-c", "open('q','w').write('1')")
    assert r.exit_code == 0
    p = next((tmp_path / ".lineage/runs").glob("*/passport.json"))
    assert json.loads(p.read_text())["key_id"]


def test_load_check_ok_and_refused(tmp_path, tiny_model, monkeypatch):
    from tests.attest_helpers import REGISTRY_PUB, attest

    monkeypatch.setenv("LINEAGE_REGISTRY_PUBKEY", REGISTRY_PUB)
    monkeypatch.setenv("LINEAGE_SERVER", "")
    monkeypatch.setenv("LINEAGE_CONFIG", str(tmp_path / "none.toml"))
    attest(tiny_model, env="dev")
    ok = invoke("load-check", tiny_model, "--env", "dev")
    assert ok.exit_code == 0 and "load allowed" in ok.output
    (tiny_model / "evil.py").write_text("1")
    bad = invoke("load-check", tiny_model, "--env", "dev")
    assert bad.exit_code == 1 and "evil.py" in bad.output and "REFUSED" in bad.output
    # prod fails closed when the registry cannot be reached
    attest(tiny_model, env="prod")
    (tiny_model / "evil.py").unlink()
    prod = invoke("load-check", tiny_model, "--env", "prod")
    assert prod.exit_code == 1 and "fail closed" in prod.output


def test_revoke_renders_blast_radius(monkeypatch):
    import httpx

    payload = {"revoked": "lp:a", "reason": "bad", "blast_radius": [
        {"id": "lp:b", "label": "model-b", "artifact_type": "model", "trust_level": "origin_verified", "status": "admitted", "risk_score": 10}]}

    class R:
        status_code = 200  # the CLI now reads the status to explain a 401/403

        def raise_for_status(self): pass
        def json(self): return payload

    monkeypatch.setattr(httpx, "post", lambda *a, **k: R())
    r = invoke("revoke", "lp:a", "--reason", "bad")
    assert r.exit_code == 0 and "model-b" in r.output and "1 affected" in r.output


def test_revoke_server_down_is_clean():
    r = invoke("revoke", "lp:a", "--server", "http://127.0.0.1:9")
    assert r.exit_code == 1 and "Traceback" not in r.output
