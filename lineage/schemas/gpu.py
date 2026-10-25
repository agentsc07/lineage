"""GPU worker request/response models, served on :8800 by Track D (BUILD_PLAN §2.6).

Shared by `lineage/inspect/llm_review/client.py` (caller) and `gpu_worker/*_api.py` (server).
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from lineage.schemas.finding import Severity


# --- POST /review/code ---
class CodeSlice(BaseModel):
    file: str
    start: int
    end: int
    code: str


class ReviewCodeRequest(BaseModel):
    purpose: str
    capabilities: list[str] = Field(default_factory=list)
    slices: list[CodeSlice]
    diff: str | None = None


class Claim(BaseModel):
    text: str
    file: str
    line: int
    api: str  # the API/call the claim says appears on that line (checked deterministically)
    severity: Severity


class ReviewResponse(BaseModel):
    claims: list[Claim] = Field(default_factory=list)
    verdict: Literal["benign", "suspicious", "malicious"]


# --- POST /review/card ---
class ReviewCardRequest(BaseModel):
    card_text: str
    measured: dict[str, Any] = Field(default_factory=dict)


# --- POST /weights/parent ---
class ParentRequest(BaseModel):
    model_path: str


class ParentResponse(BaseModel):
    parent: str | None
    similarity: float
    changed_layers: list[str] = Field(default_factory=list)


# --- POST /weights/spectral ---
class SpectralRequest(BaseModel):
    model_path: str
    parent: str


class SpectralResponse(BaseModel):
    score: float  # 0..1 backdoor likelihood from the calibrated logistic regression
    per_layer: dict[str, dict[str, float]] = Field(default_factory=dict)  # layer -> metric -> value


# --- POST /behaviour/diff ---
class BehaviourDiffRequest(BaseModel):
    child: str
    parent: str
    probe_set: str


class BehaviourDiffResponse(BaseModel):
    divergence: float
    flagged_probes: list[dict[str, Any]] = Field(default_factory=list)


# --- POST /behaviour/claims ---
class BehaviourClaimsRequest(BaseModel):
    model: str
    claims: list[dict[str, Any]]  # {"benchmark": str, "score": float}


class BehaviourClaimsResponse(BaseModel):
    results: list[dict[str, Any]]  # {"benchmark", "claimed", "measured", "within_tolerance"}


# --- POST /notary/certify, /notary/check ---
class NotaryCertifyRequest(BaseModel):
    model_path: str


class NotaryCertificate(BaseModel):
    cert_id: str
    model_digest: str
    fingerprint: str
    signature: str


class NotaryCheckRequest(BaseModel):
    model_path: str
    cert_id: str


class NotaryCheckResponse(BaseModel):
    cert_id: str
    match: bool
    detail: str = ""
