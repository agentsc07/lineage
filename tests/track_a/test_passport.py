import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from lineage.hashing.merkle import merkle_root
from lineage.passport.build import build_passport, hash_contents
from lineage.passport.chain import find_missing, walk_chain
from lineage.passport.verify import verify_passport
from lineage.schemas.finding import Finding
from lineage.schemas.passport import Action, SourceRef
from lineage.signing.ed25519 import sign_passport
from lineage.signing.keys import generate_keypair, key_id, load_private_key, load_public_key


@pytest.fixture
def keys(tmp_path):
    generate_keypair(tmp_path / "k")
    priv, pub = load_private_key(tmp_path / "k" / "default.key"), load_public_key(tmp_path / "k" / "default.pub")
    return priv, pub, key_id(pub)


def test_build_model_passport(tiny_model):
    p = build_passport(tiny_model, "model", "tiny", "1.0.0", SourceRef(hub="local"), trust_level="declared")
    c = p.predicate.contents
    assert set(c.files) == {"model.safetensors", "config.json"}
    assert set(c.tensors) == {"layers.0.weight", "layers.0.bias", "layers.1.weight", "layers.1.bias"}
    assert p.subject[0].digest["sha256"] == c.merkle_root
    assert p.predicate.trust_level == "declared" and p.predicate.risk_score == 0
    assert p.passport_id.startswith("lp:")


def test_build_is_stable_except_timestamp(tiny_model):
    a, b = (build_passport(tiny_model, "model", "t", "1", SourceRef()) for _ in range(2))
    assert a.predicate.contents == b.predicate.contents


def test_dataset_has_no_tensors(tiny_dataset):
    p = build_passport(tiny_dataset, "dataset", "tiny", "1", SourceRef())
    assert p.predicate.contents.tensors is None and set(p.predicate.contents.files) == {"tiny_dataset.csv"}


def test_findings_feed_digest_and_risk(tiny_dataset):
    f = [
        Finding(id="X.A", title="a", severity="high", category="data", stage="S3", score=25, source="deterministic"),
        Finding(id="X.B", title="b", severity="critical", category="data", stage="S3", score=40, source="deterministic"),
    ]
    clean = build_passport(tiny_dataset, "dataset", "d", "1", SourceRef())
    dirty = build_passport(tiny_dataset, "dataset", "d", "1", SourceRef(), findings=f)
    assert dirty.predicate.risk_score == 65
    assert dirty.predicate.findings_digest != clean.predicate.findings_digest


def test_parents_and_action_recorded(tiny_model):
    p = build_passport(tiny_model, "model", "c", "1", SourceRef(), parents=["lp:abc"], action=Action(kind="fine-tune"))
    assert p.predicate.parents == ["lp:abc"] and p.predicate.action.kind == "fine-tune"


def test_verify_ok_and_hash_checks(tiny_model, keys):
    priv, pub, kid = keys
    signed = sign_passport(build_passport(tiny_model, "model", "t", "1", SourceRef()), priv, kid)
    r = verify_passport(signed, pub, tiny_model)
    assert r.valid and r.signature_ok and r.hashes_ok and r.chain_ok and not r.revoked
    assert verify_passport(signed, pub).hashes_ok is None


def test_verify_detects_modified_tampered_and_unpinned(tiny_model, keys):
    priv, pub, kid = keys
    signed = sign_passport(build_passport(tiny_model, "model", "t", "1", SourceRef()), priv, kid)
    (tiny_model / "config.json").write_text("{}")
    r = verify_passport(signed, pub, tiny_model)
    assert not r.valid and r.hashes_ok is False and any("config.json" in x for x in r.problems)
    (tiny_model / "config.json").write_text(json.dumps({"model_type": "tiny", "num_hidden_layers": 2}, indent=2))
    assert verify_passport(signed, pub, tiny_model).valid
    (tiny_model / "extra.py").write_text("print(1)")
    r = verify_passport(signed, pub, tiny_model)
    assert not r.valid and any("extra.py" in x and "unpinned" in x for x in r.problems)


def test_verify_bad_signature_and_expiry(tiny_model, keys, tmp_path):
    priv, pub, kid = keys
    p = build_passport(tiny_model, "model", "t", "1", SourceRef())
    signed = sign_passport(p, priv, kid)
    signed.passport.predicate.name = "evil"
    r = verify_passport(signed, pub)
    assert not r.valid and not r.signature_ok

    from datetime import datetime, timedelta, timezone
    p2 = build_passport(tiny_model, "model", "t", "1", SourceRef())
    p2.predicate.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    r = verify_passport(sign_passport(p2, priv, kid), pub)
    assert not r.valid and any("expired" in x for x in r.problems)


def test_verify_subject_must_match_merkle(tiny_model, keys):
    priv, pub, kid = keys
    p = build_passport(tiny_model, "model", "t", "1", SourceRef())
    p.subject[0].digest["sha256"] = "0" * 64
    assert not verify_passport(sign_passport(p, priv, kid), pub).valid


class _Server:
    """Real local HTTP server standing in for lineage_server."""

    def __init__(self, revoked: bool):
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                outer.paths.append(self.path)
                body = json.dumps({"passport_id": "x", "valid": not revoked, "signature_ok": True, "chain_ok": True,
                                   "revoked": revoked, "problems": ["revoked: test"] if revoked else []}).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.paths: list[str] = []
        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


def test_verify_revocation_from_server(tiny_model, keys):
    priv, pub, kid = keys
    signed = sign_passport(build_passport(tiny_model, "model", "t", "1", SourceRef()), priv, kid)
    srv = _Server(revoked=True)
    try:
        r = verify_passport(signed, pub, tiny_model, server_url=srv.url)
        assert r.revoked and not r.valid and srv.paths == [f"/passports/{signed.passport_id}/verify"]
    finally:
        srv.close()
    srv = _Server(revoked=False)
    try:
        assert verify_passport(signed, pub, server_url=srv.url).valid
    finally:
        srv.close()


def test_verify_unreachable_server_is_not_fatal(tiny_model, keys):
    priv, pub, kid = keys
    signed = sign_passport(build_passport(tiny_model, "model", "t", "1", SourceRef()), priv, kid)
    r = verify_passport(signed, pub, server_url="http://127.0.0.1:9", )
    assert r.valid and not r.revoked and any(x.startswith("note:") for x in r.problems)


def test_chain_walk_and_missing(tiny_model, keys):
    priv, pub, kid = keys

    def mk(name, parents):
        return sign_passport(build_passport(tiny_model, "model", name, "1", SourceRef(), parents=parents), priv, kid)

    root = mk("root", [])
    a = mk("a", [root.passport_id])
    b = mk("b", [root.passport_id])
    leaf = mk("leaf", [a.passport_id, b.passport_id, "lp:ghost"])
    store = {s.passport_id: s for s in (root, a, b)}
    chain = walk_chain(leaf, store.get)
    assert [s.passport.predicate.name for s in chain][0] == "leaf"
    assert sorted(s.passport.predicate.name for s in chain) == ["a", "b", "leaf", "root"]
    assert find_missing(leaf, store.get) == ["lp:ghost"]


def test_chain_cycle_safe(tiny_model, keys):
    priv, _, kid = keys
    p = build_passport(tiny_model, "model", "c", "1", SourceRef())
    s = sign_passport(p, priv, kid)
    p.predicate.parents = [s.passport_id]  # self-reference can't be hashed in, but fetch may return it
    assert len(walk_chain(s, lambda _id: s)) == 1


def test_hash_contents_matches_merkle(tiny_model):
    c = hash_contents(tiny_model)
    leaves = {f"file:{k}": v for k, v in c.files.items()} | {f"tensor:{k}": v for k, v in (c.tensors or {}).items()}
    assert c.merkle_root == merkle_root(leaves)
