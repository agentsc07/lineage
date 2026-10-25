"""Python-AST capability extractor incl. install-time and start-up hooks (setup.py, .pth, sitecustomize) (Track C)."""
from __future__ import annotations

from pathlib import Path

from lineage.schemas.finding import Finding

CAPABILITIES = ("network", "filesystem", "subprocess", "env_secrets", "dynamic_exec", "encoded_blob", "obfuscation")


def extract(package_dir: Path) -> dict[str, list[str]]:
    """capability -> ["file:line", ...]. Deterministic; no LLM."""
    raise NotImplementedError


def scan(package_dir: Path, previous: Path | None = None) -> list[Finding]:
    """Findings for risky capabilities; if `previous` is given, only newly added capabilities are raised."""
    raise NotImplementedError
