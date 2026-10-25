"""POST /passports, GET /passports/{id}, GET /passports/{id}/verify."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from lineage.schemas.artifact import PassportReceipt, VerifyResult
from lineage.schemas.passport import SignedPassport
from lineage_server import log, models, trust
from lineage_server.deps import get_conn

router = APIRouter()
MAX_CHAIN = 1000


def _log_index(conn: sqlite3.Connection, passport_id: str) -> int:
    return log.inclusion_proof(conn, passport_id).index


@router.post("/passports", response_model=PassportReceipt)
def submit_passport(signed: SignedPassport, conn: sqlite3.Connection = Depends(get_conn)) -> PassportReceipt:
    pub = trust.trusted_key(conn, signed.key_id)
    if pub is None:
        raise HTTPException(403, f"signing key {signed.key_id} is not trusted by this registry")
    if not trust.verify_signed(signed, pub):
        raise HTTPException(400, "signature does not verify")
    models.save_passport(conn, signed)
    return PassportReceipt(passport_id=signed.passport_id, log_index=_log_index(conn, signed.passport_id))


@router.get("/passports/{passport_id}", response_model=SignedPassport)
def get_passport(passport_id: str, conn: sqlite3.Connection = Depends(get_conn)) -> SignedPassport:
    sp = models.get_signed_passport(conn, passport_id)
    if sp is None:
        raise HTTPException(404, f"unknown passport {passport_id}")
    return sp


@router.get("/passports/{passport_id}/verify", response_model=VerifyResult)
def verify_passport(passport_id: str, conn: sqlite3.Connection = Depends(get_conn)) -> VerifyResult:
    sp = models.get_signed_passport(conn, passport_id)
    if sp is None:
        raise HTTPException(404, f"unknown passport {passport_id}")
    problems: list[str] = []

    pub = trust.trusted_key(conn, sp.key_id)
    signature_ok = pub is not None and trust.verify_signed(sp, pub)
    if pub is None:
        problems.append(f"signing key {sp.key_id} is not trusted")
    elif not signature_ok:
        problems.append("signature does not verify")
    if sp.passport_id != passport_id:
        signature_ok = False
        problems.append("passport content does not match its id")

    chain_ok, seen, queue = True, {passport_id}, list(sp.passport.predicate.parents)
    while queue and len(seen) < MAX_CHAIN:
        pid = queue.pop(0)
        if pid in seen:
            continue
        seen.add(pid)
        parent = models.get_signed_passport(conn, pid)
        if parent is None:
            chain_ok = False
            problems.append(f"ancestor {pid[:19]} is not registered")
            continue
        if models.is_revoked(conn, pid):
            chain_ok = False
            problems.append(f"ancestor {pid[:19]} is revoked")
        queue += parent.passport.predicate.parents

    revoked = models.is_revoked(conn, passport_id)
    if revoked:
        problems.append("passport is revoked")
    exp = sp.passport.predicate.expires_at
    expired = exp is not None and exp <= datetime.now(timezone.utc)
    if expired:
        problems.append(f"passport expired {exp:%Y-%m-%d}")
    return VerifyResult(
        passport_id=passport_id,
        valid=signature_ok and chain_ok and not revoked and not expired,
        signature_ok=signature_ok,
        hashes_ok=None,
        chain_ok=chain_ok,
        revoked=revoked,
        problems=problems,
    )
