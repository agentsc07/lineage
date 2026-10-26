"""POST /notary/certify and /notary/check, plus /notary/commitment, /notary/pubkey, /notary/cert/{id} (Track D).

The Notary holds a *sealed* hidden test set (multiple-choice items with gold labels) that is never
returned by any endpoint. Each `certify` request draws a fresh random subset, scores the model on it,
and signs a certificate (Ed25519) binding the model digest to a behavioural fingerprint = hash of the
model's answer vector and accuracy on that subset. `check` re-runs a random sample of the certified
items on the (possibly different) model and compares answers: a swapped or tampered model disagrees.

Extra endpoints beyond the BUILD_PLAN table: commitment (public hash of the sealed set), pubkey,
cert (the stored record; item ids and answers, no labels).
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import secrets
import threading
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi import APIRouter, HTTPException

from gpu_worker import modelio
from lineage.hashing.files import hash_tree
from lineage.hashing.merkle import merkle_root
from lineage.schemas.gpu import NotaryCertificate, NotaryCertifyRequest, NotaryCheckRequest, NotaryCheckResponse

router = APIRouter()

DATA = Path(os.environ.get("LINEAGE_NOTARY_DIR", Path(__file__).resolve().parent / "notary_data"))  # gitignored
SUBSET = 64
SPOT_CHECK = 24
AGREEMENT = 0.90  # bf16 near-ties can flip an answer; a different model agrees far less
_lock = threading.Lock()


# ---------------------------------------------------------------------------- sealed set + keys
def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _build_hidden(n_arc: int = 200, n_hs: int = 200) -> list[dict]:
    """Held-out items: disjoint from the claim-check subset (first 100 of the seed-0 shuffle)."""
    from datasets import load_dataset
    rng = random.Random(1234)
    items: list[dict] = []
    ds = load_dataset("allenai/ai2_arc", "ARC-Easy", split="train")
    pool = [r for r in ds if r["answerKey"] in r["choices"]["label"]]
    rng.shuffle(pool)
    for r in pool[:n_arc]:
        items.append({"ctx": f"Question: {r['question']}\nAnswer:", "choices": [" " + t for t in r["choices"]["text"]],
                      "gold": r["choices"]["label"].index(r["answerKey"])})
    ds = load_dataset("Rowan/hellaswag", split="train")
    pool = list(ds.select(range(5000)))
    rng.shuffle(pool)
    for r in pool[:n_hs]:
        items.append({"ctx": r["ctx"], "choices": [" " + e for e in r["endings"]], "gold": int(r["label"])})
    return items


def _hidden() -> list[dict]:
    DATA.mkdir(parents=True, exist_ok=True)
    f = DATA / "hidden.json"
    if not f.exists():
        f.write_text(json.dumps(_build_hidden()))
        f.chmod(0o600)
    return json.loads(f.read_text())


def commitment() -> str:
    """Public commitment: hash of the sealed set. Lets anyone detect a silently swapped test set."""
    return hashlib.sha256((DATA / "hidden.json").read_bytes() if (DATA / "hidden.json").exists()
                          else _canon(_hidden())).hexdigest()


def _key() -> Ed25519PrivateKey:
    DATA.mkdir(parents=True, exist_ok=True)
    f = DATA / "notary.key"
    if not f.exists():
        raw = Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        f.write_bytes(raw)
        f.chmod(0o600)
    return Ed25519PrivateKey.from_private_bytes(f.read_bytes())


def pubkey_hex() -> str:
    return _key().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def verify_certificate(cert: NotaryCertificate, pub_hex: str | None = None) -> bool:
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex or pubkey_hex()))
    try:
        pub.verify(bytes.fromhex(cert.signature), _canon({"cert_id": cert.cert_id, "model_digest": cert.model_digest,
                                                          "fingerprint": cert.fingerprint}))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------- scoring
def model_digest(model_path: str) -> str:
    p = Path(model_path)
    if p.is_dir():
        return "sha256:" + merkle_root(hash_tree(p))
    return "ref:" + hashlib.sha256(model_path.encode()).hexdigest()  # hub id: cannot hash files here


def _answers(model_path: str, idxs: list[int]) -> list[int]:
    items = _hidden()
    model, tok = modelio.load_model(model_path)
    out = []
    for i in idxs:
        it = items[i]
        lps = modelio.continuation_logprobs(model, tok, [it["ctx"]] * len(it["choices"]), it["choices"])
        norm = [lp / max(1, len(c)) for lp, c in zip(lps, it["choices"])]
        out.append(max(range(len(norm)), key=norm.__getitem__))
    return out


def _fingerprint(digest: str, idxs: list[int], answers: list[int]) -> str:
    return hashlib.sha256(_canon({"d": digest, "i": idxs, "a": answers})).hexdigest()


def certify_impl(model_path: str) -> NotaryCertificate:
    with modelio.GPU_LOCK:
        items = _hidden()
        idxs = sorted(secrets.SystemRandom().sample(range(len(items)), SUBSET))
        answers = _answers(model_path, idxs)
    acc = sum(a == items[i]["gold"] for i, a in zip(idxs, answers)) / SUBSET
    digest = model_digest(model_path)
    cert_id = "nc-" + secrets.token_hex(8)
    fp = _fingerprint(digest, idxs, answers)
    sig = _key().sign(_canon({"cert_id": cert_id, "model_digest": digest, "fingerprint": fp})).hex()
    with _lock:
        (DATA / "certs").mkdir(parents=True, exist_ok=True)
        (DATA / "certs" / f"{cert_id}.json").write_text(json.dumps(
            {"cert_id": cert_id, "model_digest": digest, "fingerprint": fp, "items": idxs, "answers": answers,
             "accuracy": acc, "n": SUBSET, "commitment": commitment()}))
    return NotaryCertificate(cert_id=cert_id, model_digest=digest, fingerprint=fp, signature=sig)


def check_impl(model_path: str, cert_id: str) -> NotaryCheckResponse:
    f = DATA / "certs" / f"{cert_id}.json"
    if not cert_id.startswith("nc-") or not cert_id[3:].isalnum() or not f.exists():
        return NotaryCheckResponse(cert_id=cert_id, match=False, detail="unknown certificate")
    rec = json.loads(f.read_text())
    cert = NotaryCertificate(cert_id=cert_id, model_digest=rec["model_digest"], fingerprint=rec["fingerprint"],
                             signature=_key().sign(_canon({"cert_id": cert_id, "model_digest": rec["model_digest"],
                                                           "fingerprint": rec["fingerprint"]})).hex())
    digest = model_digest(model_path)
    same_files = digest == rec["model_digest"]
    sample = sorted(random.SystemRandom().sample(range(len(rec["items"])), min(SPOT_CHECK, len(rec["items"]))))
    with modelio.GPU_LOCK:
        now = _answers(model_path, [rec["items"][k] for k in sample])
    agree = sum(now[j] == rec["answers"][k] for j, k in enumerate(sample)) / len(sample)
    match = agree >= AGREEMENT
    detail = (f"spot-check {len(sample)} certified items: {agree:.0%} agreement "
              f"({'identical' if same_files else 'DIFFERENT'} file digest); certified accuracy {rec['accuracy']:.2f}")
    return NotaryCheckResponse(cert_id=cert_id, match=match, detail=detail)


# ---------------------------------------------------------------------------- routes
def _need_gpu() -> None:
    if not modelio.have_gpu():
        raise HTTPException(503, "notary scoring needs a GPU; none available on this worker")


@router.post("/notary/certify", response_model=NotaryCertificate)
def notary_certify(req: NotaryCertifyRequest) -> NotaryCertificate:
    _need_gpu()
    return certify_impl(req.model_path)


@router.post("/notary/check", response_model=NotaryCheckResponse)
def notary_check(req: NotaryCheckRequest) -> NotaryCheckResponse:
    _need_gpu()
    return check_impl(req.model_path, req.cert_id)


@router.get("/notary/commitment")
def notary_commitment() -> dict:
    return {"sha256": commitment(), "pubkey": pubkey_hex()}


@router.get("/notary/cert/{cert_id}")
def notary_cert(cert_id: str) -> dict:
    f = DATA / "certs" / f"{cert_id}.json"
    if not cert_id.startswith("nc-") or not cert_id[3:].isalnum() or not f.exists():
        raise HTTPException(404, "unknown certificate")
    return json.loads(f.read_text())
