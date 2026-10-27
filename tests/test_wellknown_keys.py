"""R4.6: publish keys at /.well-known/lineage-keys.json and verify with `--from` (REFACTOR_SPEC 7.3)."""
import json

import httpx
import pytest
from typer.testing import CliRunner

from lineage.cli import app
from lineage.signing import wellknown

runner = CliRunner()


@pytest.fixture
def signer(tmp_path, monkeypatch):
    monkeypatch.setenv("LINEAGE_PINNED_KEYS", str(tmp_path / "pins.json"))
    d = tmp_path / "apollo"
    d.mkdir()
    r = runner.invoke(app, ["keygen", "--dir", str(d), "--name", "apollo", "--publish", "--scope", "hf:apollo-health/*"])
    assert r.exit_code == 0, r.output
    model = tmp_path / "model"
    model.mkdir()
    (model / "w.bin").write_bytes(b"1234")
    ok = runner.invoke(app, ["sign", str(model), "--key", str(d / "apollo.key"), "--hub", "huggingface", "--repo", "apollo-health/triage", "--out", str(tmp_path / "p.json")])
    assert ok.exit_code == 0, ok.output
    return d, model, tmp_path / "p.json"


@pytest.fixture
def site(signer, monkeypatch):
    d, *_ = signer
    served = {"doc": json.loads((d / wellknown.WELL_KNOWN).read_text())}

    def get(url, **kw):
        assert url == "https://example.com/.well-known/lineage-keys.json"
        return httpx.Response(200, json=served["doc"], request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", get)
    return served


def test_keygen_publish_writes_the_well_known_file(signer):
    d, *_ = signer
    doc = json.loads((d / wellknown.WELL_KNOWN).read_text())
    assert doc[0]["name"] == "apollo" and doc[0]["scope"] == ["hf:apollo-health/*"] and len(doc[0]["key"]) == 64


def test_verify_from_pins_on_first_use_and_verifies(signer, site):
    _, model, passport = signer
    r = runner.invoke(app, ["verify", str(passport), "--artifact", str(model), "--from", "https://example.com"])
    assert r.exit_code == 0 and "first use" in r.output and "VALID" in r.output


def test_a_changed_key_list_is_warned_about_and_the_pinned_key_is_used(signer, site, tmp_path):
    _, model, passport = signer
    runner.invoke(app, ["verify", str(passport), "--from", "https://example.com"])
    site["doc"] = [{"name": "mallory", "key": "ab" * 32, "scope": ["*"]}]  # the site now publishes a different key
    r = runner.invoke(app, ["verify", str(passport), "--artifact", str(model), "--from", "https://example.com"])
    assert "CHANGED" in r.output and r.exit_code == 0  # still verifies against the pinned key
    r2 = runner.invoke(app, ["verify", str(passport), "--from", "https://example.com", "--accept-change"])
    assert r2.exit_code == 1 and "not among the keys" in r2.output  # accepting the swap means the real signer is no longer trusted


def test_a_passport_outside_the_published_scope_is_refused(signer, site, tmp_path):
    d, model, _ = signer
    bad = tmp_path / "bad.json"
    r0 = runner.invoke(app, ["sign", str(model), "--key", str(d / "apollo.key"), "--hub", "huggingface", "--repo", "nvidia/x", "--out", str(bad)])
    assert r0.exit_code == 0
    r = runner.invoke(app, ["verify", str(bad), "--from", "https://example.com"])
    assert r.exit_code == 1 and "SCOPE MISMATCH" in r.output
