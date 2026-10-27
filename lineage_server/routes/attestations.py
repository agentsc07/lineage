"""GET /attestations/{id}?env= and GET /registry-key (REFACTOR_SPEC 3.4, section 5)."""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request

from lineage.schemas.attestation import SignedAttestation
from lineage.schemas.policy import PolicyPack
from lineage_server import attest, service, trust
from lineage_server.deps import get_conn, get_policy

router = APIRouter()


@router.get("/attestations/{artifact_id}", response_model=SignedAttestation)
def get_attestation(artifact_id: str, request: Request, env: str = "prod", conn: sqlite3.Connection = Depends(get_conn),
                    active: tuple[PolicyPack, bool] = Depends(get_policy)) -> SignedAttestation:
    if env not in active[0].environments:
        raise HTTPException(400, f"unknown environment {env!r}; policy defines {sorted(active[0].environments)}")
    try:
        return attest.issue(conn, request.app.state.signing_key, artifact_id, active[0], env, policy_expired=active[1])
    except service.NotFound:
        raise HTTPException(404, f"unknown artifact {artifact_id}")


@router.get("/attestations", response_model=SignedAttestation)
def attestation_by_digest(digest: str, request: Request, env: str = "prod", conn: sqlite3.Connection = Depends(get_conn),
                          active: tuple[PolicyPack, bool] = Depends(get_policy)) -> SignedAttestation:
    """For a directory that has no cached attestation: find the artifact by the Merkle root of its bytes."""
    from lineage_server import models

    aid = models.find_by_merkle_root(conn, digest)
    if aid is None:
        raise HTTPException(404, "no admitted artifact has these bytes")
    return get_attestation(aid, request, env, conn, active)


@router.get("/registry-key")
def registry_key(request: Request) -> dict[str, str]:
    """The key attestations are signed with. Clients pin it (config or LINEAGE_REGISTRY_PUBKEY); it never comes from an artifact."""
    k = request.app.state.signing_key.public_key()
    return {"key_id": trust.key_id(k), "public_key": trust.public_hex(k)}
