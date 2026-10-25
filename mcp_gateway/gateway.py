"""MCP gateway: pins tool description + code hashes, re-checks every call, disables a tool on change.

A transport-agnostic `Gateway` speaks JSON-RPC 2.0 (MCP's wire format) to an `Upstream`:
- `tools/list`: every tool is checked against its pin; tools that fail are disabled and hidden.
- `tools/call`: the tool is re-fetched from upstream and re-checked *before* the call is forwarded
  (rug-pull defence: a description or code swap after approval is caught on the very next call).
- A disabled tool stays disabled, even if upstream reverts, until `reapprove()` installs a new pin.
- A tool with no pin (never admitted, or quarantined / blocked / revoked) is disabled too.

What is hashed (so tool poisoning and rug pulls both show up):
- description hash: canonical JSON of the model-facing surface (`name`, `description`, `inputSchema`, `annotations`);
- code hash: the tool's code directory, via `hash_code`.
`serve()` wraps a Gateway in a small HTTP JSON-RPC endpoint.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

SURFACE_KEYS = ("name", "description", "inputSchema", "annotations")
IGNORED_NAMES = {"passport.json", "lineage.meta.json"}
ERR_DISABLED, ERR_UNKNOWN, ERR_UPSTREAM = -32001, -32602, -32002
MAX_PAGES = 20


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def hash_description(tool: dict) -> str:
    """sha256 of the part of a tool definition the model reads."""
    return hashlib.sha256(_canonical({k: tool[k] for k in SURFACE_KEYS if k in tool})).hexdigest()


def hash_code(code_dir: Path) -> str:
    """sha256 over `relative path NUL file sha256` lines, sorted; ignores bytecode, VCS dirs and Lineage sidecars."""
    lines = []
    for p in sorted(code_dir.rglob("*")):
        rel = p.relative_to(code_dir)
        if not p.is_file() or p.name in IGNORED_NAMES or p.suffix == ".pyc" or {"__pycache__", ".git"} & set(rel.parts):
            continue
        lines.append(f"{rel.as_posix()}\0{hashlib.sha256(p.read_bytes()).hexdigest()}")
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def pin_tool(manifest_path: Path, code_dir: Path) -> dict[str, str]:
    """Return {"description_sha256": ..., "code_sha256": ...} to store in the tool passport."""
    manifest = json.loads(Path(manifest_path).read_text())
    return {"description_sha256": hash_description(manifest), "code_sha256": hash_code(Path(code_dir))}


def pins_from_db(conn: sqlite3.Connection) -> dict[str, dict[str, str]]:
    """Pins of tools whose latest intake was admitted, keyed by tool name (newest wins)."""
    rows = conn.execute(
        "SELECT p.tool_name, p.description_sha256, p.code_sha256 FROM tool_pins p JOIN artifacts a ON a.id = p.artifact_id"
        " WHERE a.status IN ('admitted', 'admitted_with_conditions') ORDER BY a.created_at, a.rowid"
    )
    return {r["tool_name"]: {"description_sha256": r["description_sha256"], "code_sha256": r["code_sha256"]} for r in rows}


class UpstreamError(Exception):
    pass


class Upstream(Protocol):
    def request(self, method: str, params: dict | None = None) -> dict:
        """Return the JSON-RPC `result`, or raise UpstreamError."""


class HttpUpstream:
    def __init__(self, url: str, timeout: float = 60.0):
        self.url, self.timeout, self._id = url, timeout, 0

    def request(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        try:
            r = httpx.post(self.url, json={"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}},
                           timeout=self.timeout)
            r.raise_for_status()
            body = r.json()
        except (httpx.HTTPError, ValueError) as e:
            raise UpstreamError(str(e)) from e
        if "error" in body:
            raise UpstreamError(body["error"].get("message", "upstream error"))
        return body.get("result", {})


class Gateway:
    def __init__(
        self,
        upstream: Upstream,
        pins: dict[str, dict[str, str]],
        code_hash: Callable[[str], str | None] | None = None,
        on_event: Callable[[dict], None] | None = None,
    ):
        """`code_hash(tool_name)` returns the current code hash of that tool (or None if unknown). Without it a
        tool whose pin includes a code hash cannot be verified and is disabled (fail closed)."""
        self.upstream, self.pins, self.code_hash, self.on_event = upstream, dict(pins), code_hash, on_event
        self.disabled: dict[str, str] = {}
        self.events: list[dict] = []
        self._lock = threading.Lock()

    # --- checking ---
    def _emit(self, tool: str, kind: str, reason: str = "") -> None:
        ev = {"ts": datetime.now(timezone.utc).isoformat(), "tool": tool, "kind": kind, "reason": reason}
        self.events.append(ev)
        if self.on_event:
            self.on_event(ev)

    def violation(self, tool: dict) -> str | None:
        """Why `tool` must not be used, or None if it matches its pin."""
        name = tool.get("name", "")
        pin = self.pins.get(name)
        if pin is None:
            return "tool is not pinned: it has no admitted passport"
        now = hash_description(tool)
        if now != pin["description_sha256"]:
            return f"description changed since approval (pinned {pin['description_sha256'][:12]}, now {now[:12]})"
        if pin.get("code_sha256"):
            cur = self.code_hash(name) if self.code_hash else None
            if cur is None:
                return "code hash cannot be verified"
            if cur != pin["code_sha256"]:
                return f"code changed since approval (pinned {pin['code_sha256'][:12]}, now {cur[:12]})"
        return None

    def _check(self, tool: dict) -> str | None:
        """Sticky disable: returns the reason a tool is unusable (and records it the first time)."""
        name = tool.get("name", "")
        with self._lock:
            if name in self.disabled:
                return self.disabled[name]
            reason = self.violation(tool)
            if reason:
                self.disabled[name] = reason
                self._emit(name, "disabled", reason)
            return reason

    def reapprove(self, tool_name: str, pin: dict[str, str]) -> None:
        """Install a new pin (after a human re-approved the tool) and re-enable it."""
        with self._lock:
            self.pins[tool_name] = pin
            self.disabled.pop(tool_name, None)
            self._emit(tool_name, "reapproved")

    def _list_all(self) -> list[dict]:
        tools, cursor = [], None
        for _ in range(MAX_PAGES):
            res = self.upstream.request("tools/list", {"cursor": cursor} if cursor else {})
            tools += res.get("tools", [])
            cursor = res.get("nextCursor")
            if not cursor:
                break
        return tools

    # --- JSON-RPC ---
    def handle(self, message: dict) -> dict | None:
        """Handle one JSON-RPC request; returns the response (None for notifications)."""
        mid, method, params = message.get("id"), message.get("method", ""), message.get("params") or {}
        try:
            if method == "tools/list":
                result = self.upstream.request(method, params)
                result["tools"] = [t for t in result.get("tools", []) if self._check(t) is None]
            elif method == "tools/call":
                return self._call(mid, params)
            else:
                result = self.upstream.request(method, params)
        except UpstreamError as e:
            return None if mid is None else _error(mid, ERR_UPSTREAM, f"upstream error: {e}")
        return None if mid is None else {"jsonrpc": "2.0", "id": mid, "result": result}

    def _call(self, mid: Any, params: dict) -> dict:
        name = params.get("name", "")
        if name in self.disabled:
            self._emit(name, "blocked_call", self.disabled[name])
            return _error(mid, ERR_DISABLED, f"tool '{name}' is disabled: {self.disabled[name]}", {"tool": name})
        try:
            tool = next((t for t in self._list_all() if t.get("name") == name), None)
            if tool is None:
                return _error(mid, ERR_UNKNOWN, f"unknown tool '{name}'")
            reason = self._check(tool)  # re-check on every call
            if reason:
                self._emit(name, "blocked_call", reason)
                return _error(mid, ERR_DISABLED, f"tool '{name}' is disabled: {reason}", {"tool": name})
            result = self.upstream.request("tools/call", params)
        except UpstreamError as e:
            return _error(mid, ERR_UPSTREAM, f"upstream error: {e}")
        self._emit(name, "allowed")
        return {"jsonrpc": "2.0", "id": mid, "result": result}


def _error(mid: Any, code: int, message: str, data: dict | None = None) -> dict:
    err: dict[str, Any] = {"code": code, "message": message}
    if data:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": mid, "error": err}


def create_app(gateway: Gateway):
    """HTTP JSON-RPC endpoint (single or batch) plus /gateway/status."""
    app = FastAPI(title="Lineage MCP gateway")

    @app.post("/")
    async def rpc(request: Request):
        body = await request.json()
        if isinstance(body, list):
            out = [r for r in (gateway.handle(m) for m in body) if r is not None]
            return JSONResponse(out) if out else Response(status_code=202)
        res = gateway.handle(body)
        return JSONResponse(res) if res is not None else Response(status_code=202)

    @app.get("/gateway/status")
    def status():
        return {"pinned": sorted(gateway.pins), "disabled": gateway.disabled, "events": gateway.events[-100:]}

    return app


def serve(
    upstream: str,
    pins: dict[str, dict[str, str]],
    host: str = "127.0.0.1",
    port: int = 8900,
    code_dirs: dict[str, Path] | None = None,
) -> None:
    """Proxy MCP traffic to `upstream`; any tool whose description/code hash differs from its pin is disabled.

    `code_dirs` maps tool name -> its code directory, so code hashes can be re-checked on every call."""
    import uvicorn

    dirs = code_dirs or {}
    gateway = Gateway(HttpUpstream(upstream), pins, (lambda n: hash_code(dirs[n]) if n in dirs else None))
    uvicorn.run(create_app(gateway), host=host, port=port)
