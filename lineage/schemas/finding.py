"""Finding: the one return type of every scanner (BUILD_PLAN §2.1)."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
Category = Literal[
    "provenance", "integrity", "code", "model", "data", "tool", "policy", "behaviour", "llm"
]
Stage = Literal["S0", "S1", "S2", "S3", "S4", "S5"]
Source = Literal["deterministic", "statistical", "llm", "human"]
EvidenceKind = Literal["file_line", "tensor", "field", "url", "metric"]


class Evidence(BaseModel):
    kind: EvidenceKind
    ref: str  # e.g. "pkg/x.pth:1", "layers.1.weight", "config.json#auto_map"
    detail: str = ""


class Finding(BaseModel):
    id: str  # e.g. "MODEL.PICKLE.DANGEROUS_GLOBAL"
    title: str  # human sentence
    severity: Severity
    category: Category
    stage: Stage
    evidence: list[Evidence] = Field(default_factory=list)
    score: int = Field(ge=0, le=40)  # contribution to risk score
    source: Source
    grounded: bool = True  # llm findings: True only if citation check passed
