"""The only way to get admitted bytes out: GET /store/{id}/files/{path} (attestation-gated), plus lookups (REFACTOR_SPEC 5)."""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse

from lineage.schemas.attestation import SignedAttestation
from lineage.schemas.policy import PolicyPack
from lineage_server import attest, models, service
from lineage_server.deps import get_conn, get_policy

router = APIRouter()


def _usable(request: Request, conn, policy, artifact_id: str, env: str) -> SignedAttestation:
    if env not in policy[0].environments:
        raise HTTPException(400, f"unknown environment {env!r}")
    try:
        signed = attest.issue(conn, request.app.state.signing_key, artifact_id, policy[0], env, policy_expired=policy[1])
    except service.NotFound:
        raise HTTPException(404, f"unknown artifact {artifact_id}")
    if not signed.attestation.usable:
        raise HTTPException(403, f"not usable in {env}: {'revoked' if signed.attestation.revoked else signed.attestation.outcome}")
    return signed


@router.get("/store/{artifact_id}/files/{path:path}")
def get_file(artifact_id: str, path: str, request: Request, env: str = "prod", conn: sqlite3.Connection = Depends(get_conn),
             active: tuple[PolicyPack, bool] = Depends(get_policy)):
    """Bytes are served only when the latest attestation for this environment allows them."""
    signed = _usable(request, conn, active, artifact_id, env)
    sha = signed.attestation.files.get(path)
    if sha is None or not request.app.state.store.has(sha):
        raise HTTPException(404, f"{path} is not part of {artifact_id[:19]}")
    return FileResponse(request.app.state.store.blob_path(sha), filename=path.rsplit("/", 1)[-1])


@router.get("/store/{artifact_id}/manifest", response_model=SignedAttestation)
def manifest(artifact_id: str, request: Request, env: str = "prod", conn: sqlite3.Connection = Depends(get_conn),
             active: tuple[PolicyPack, bool] = Depends(get_policy)):
    return _usable(request, conn, active, artifact_id, env)


@router.get("/lookup")
def lookup(source: str, request: Request, env: str = "prod", conn: sqlite3.Connection = Depends(get_conn),
           active: tuple[PolicyPack, bool] = Depends(get_policy)) -> dict[str, str]:
    """Newest artifact usable in `env` whose source is `hf:org/name[@rev]`, `hf-dataset:...`, `pypi:name[==v]`, or a plain name."""
    kind, _, rest = source.partition(":")
    repo = rest.split("@")[0].split("==")[0] if rest else source
    want_version = rest.split("==", 1)[1] if "==" in rest else None
    rows = conn.execute("SELECT id FROM artifacts ORDER BY created_at DESC, rowid DESC").fetchall()
    for r in rows:
        signed = models.get_signed_passport(conn, r["id"])
        if signed is None:
            continue
        b = signed.passport.predicate
        if repo not in (b.source.repo, b.name) or (want_version and b.version != want_version):
            continue
        try:
            if attest.issue(conn, request.app.state.signing_key, r["id"], active[0], env, policy_expired=active[1]).attestation.usable:
                return {"artifact_id": r["id"], "name": b.name, "version": b.version}
        except service.NotFound:
            continue
    raise HTTPException(404, f"no artifact usable in {env} matches {source}")
