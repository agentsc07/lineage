"""MCP gateway: pins tool description + code hashes, re-checks every call, disables a tool on change (Track B)."""
from __future__ import annotations

from pathlib import Path


def pin_tool(manifest_path: Path, code_dir: Path) -> dict[str, str]:
    """Return {"description_sha256": ..., "code_sha256": ...} to store in the tool passport."""
    raise NotImplementedError


def serve(upstream: str, pins: dict[str, dict[str, str]], host: str = "127.0.0.1", port: int = 8900) -> None:
    """Proxy MCP traffic to `upstream`; any tool whose description/code hash differs from its pin is disabled."""
    raise NotImplementedError
