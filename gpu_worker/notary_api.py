"""POST /notary/certify and /notary/check (Track D)."""
from __future__ import annotations

from fastapi import APIRouter

from lineage.schemas.gpu import NotaryCertificate, NotaryCertifyRequest, NotaryCheckRequest, NotaryCheckResponse

router = APIRouter()


@router.post("/notary/certify", response_model=NotaryCertificate)
def notary_certify(req: NotaryCertifyRequest) -> NotaryCertificate:
    raise NotImplementedError


@router.post("/notary/check", response_model=NotaryCheckResponse)
def notary_check(req: NotaryCheckRequest) -> NotaryCheckResponse:
    raise NotImplementedError
