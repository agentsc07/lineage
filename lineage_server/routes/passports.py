"""POST /passports, GET /passports/{id}, GET /passports/{id}/verify (mock data until Track B)."""
from __future__ import annotations

from fastapi import APIRouter

from lineage.schemas.artifact import PassportReceipt, VerifyResult
from lineage.schemas.passport import SignedPassport
from lineage_server import mock

router = APIRouter()


@router.post("/passports", response_model=PassportReceipt)
def submit_passport(signed: SignedPassport) -> PassportReceipt:
    return PassportReceipt(passport_id=signed.passport_id, log_index=3)


@router.get("/passports/{passport_id}", response_model=SignedPassport)
def get_passport(passport_id: str) -> SignedPassport:
    return mock.signed_passport(passport_id)


@router.get("/passports/{passport_id}/verify", response_model=VerifyResult)
def verify_passport(passport_id: str) -> VerifyResult:
    return VerifyResult(
        passport_id=passport_id, valid=True, signature_ok=True, hashes_ok=None, chain_ok=True, revoked=False
    )
