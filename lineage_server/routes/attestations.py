"""GET /attestations/{id}?env= and GET /registry-key (REFACTOR_SPEC 3.4, section 5)."""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request

from lineage.schemas.attestation import AttestationStatus, SignedAttestation
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


@router.get("/attestations/{artifact_id}/status", response_model=AttestationStatus)
def attestation_status(artifact_id: str, env: str = "prod", conn: sqlite3.Connection = Depends(get_conn),
                       active: tuple[PolicyPack, bool] = Depends(get_policy)) -> AttestationStatus:
    """Current revocation, ancestor revocation and decision for this environment (what `lineage.load()` asks before trusting a cached attestation)."""
    from lineage_server import graph, models

    if env not in active[0].environments:
        raise HTTPException(400, f"unknown environment {env!r}; policy defines {sorted(active[0].environments)}")
    if models.get_signed_passport(conn, artifact_id) is None:
        raise HTTPException(404, f"unknown artifact {artifact_id}")
    revoked = models.is_revoked(conn, artifact_id)
    ancestors = [n.id for n in graph.reachable(conn, artifact_id, "up") if n.id != artifact_id and models.is_revoked(conn, n.id)]
    outcome = "block" if revoked or models.is_rejected(conn, artifact_id) else service.evaluate(conn, artifact_id, active[0], policy_expired=active[1], environment=env).outcome
    return AttestationStatus(artifact_id=artifact_id, environment=env, revoked=revoked, ancestor_revoked=ancestors, current_outcome=outcome,
                             usable=not revoked and not ancestors and outcome in ("allow", "allow_with_conditions"))


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
