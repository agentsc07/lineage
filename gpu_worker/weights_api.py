"""POST /weights/parent and /weights/spectral (Track D)."""
from __future__ import annotations

from fastapi import APIRouter

from lineage.schemas.gpu import ParentRequest, ParentResponse, SpectralRequest, SpectralResponse

router = APIRouter()


@router.post("/weights/parent", response_model=ParentResponse)
def weights_parent(req: ParentRequest) -> ParentResponse:
    raise NotImplementedError


@router.post("/weights/spectral", response_model=SpectralResponse)
def weights_spectral(req: SpectralRequest) -> SpectralResponse:
    raise NotImplementedError
