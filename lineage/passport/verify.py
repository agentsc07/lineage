"""Verify a signed passport (Track A)."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lineage.passport.build import hash_contents
from lineage.passport.chain import find_missing
from lineage.schemas.artifact import VerifyResult
from lineage.schemas.passport import SignedPassport
from lineage.signing.ed25519 import verify_signed


def check_contents(signed: SignedPassport, artifact_path: Path) -> list[str]:
    """Re-hash `artifact_path` and list every difference from the passport (empty = identical)."""
    pinned = signed.passport.predicate.contents
    actual = hash_contents(artifact_path)
    problems: list[str] = []
    for rel, digest in sorted(pinned.files.items()):
        if rel not in actual.files:
            problems.append(f"missing file: {rel}")
        elif actual.files[rel] != digest:
            problems.append(f"hash mismatch: {rel}")
    for rel in sorted(set(actual.files) - set(pinned.files)):
        problems.append(f"unpinned file: {rel}")
    for name, digest in sorted((pinned.tensors or {}).items()):
        got = (actual.tensors or {}).get(name)
        if got is not None and got != digest:
            problems.append(f"tensor mismatch: {name}")
        elif got is None:
            problems.append(f"missing tensor: {name}")
    for name in sorted(set(actual.tensors or {}) - set(pinned.tensors or {})):
        problems.append(f"unpinned tensor: {name}")
    if not problems and actual.merkle_root != pinned.merkle_root:
        problems.append("merkle root mismatch")
    return problems


def verify_passport(
    signed: SignedPassport,
    public_key: Ed25519PublicKey,
    artifact_path: Path | None = None,
    server_url: str | None = None,
    fetch: Callable[[str], SignedPassport | None] | None = None,
) -> VerifyResult:
    """Check signature; re-hash `artifact_path` against contents if given; check revocation at `server_url` if reachable.

    If `fetch` is given, every ancestor must resolve (`chain_ok`). An unreachable server is not fatal: it adds
    a `note:` problem and revocation is reported as unchecked (`revoked=False`).
    """
    pid = signed.passport_id
    body = signed.passport.predicate
    problems: list[str] = []

    sig_ok = verify_signed(signed, public_key)
    if not sig_ok:
        problems.append("signature invalid")
    if signed.passport.subject and signed.passport.subject[0].digest.get("sha256") != body.contents.merkle_root:
        problems.append("subject digest does not match contents merkle root")
    if body.expires_at is not None and body.expires_at <= datetime.now(timezone.utc):
        problems.append(f"expired at {body.expires_at.isoformat()}")

    hashes_ok: bool | None = None
    if artifact_path is not None:
        diffs = check_contents(signed, artifact_path)
        hashes_ok = not diffs
        problems += diffs

    chain_ok = True
    if fetch is not None:
        missing = find_missing(signed, fetch)
        chain_ok = not missing
        problems += [f"missing parent: {m}" for m in missing]

    revoked = False
    if server_url:
        try:
            r = httpx.get(f"{server_url.rstrip('/')}/passports/{pid}/verify", timeout=3.0)
            r.raise_for_status()
            remote = VerifyResult.model_validate(r.json())
            revoked = remote.revoked
            if remote.revoked:
                problems.append("revoked on server")
            chain_ok = chain_ok and remote.chain_ok
            if not remote.chain_ok:
                problems.append("server reports a broken or revoked parent chain")
        except (httpx.HTTPError, ValueError) as e:
            problems.append(f"note: server unreachable, revocation not checked ({type(e).__name__})")

    fatal = [p for p in problems if not p.startswith("note:")]
    valid = sig_ok and hashes_ok is not False and chain_ok and not revoked and not fatal
    return VerifyResult(
        passport_id=pid,
        valid=valid,
        signature_ok=sig_ok,
        hashes_ok=hashes_ok,
        chain_ok=chain_ok,
        revoked=revoked,
        problems=problems,
    )
