"""Shared-secret bearer authentication for the two internal services (the GPU worker and the MCP gateway) and for the clients that call them.

A deployment sets one environment variable per service (`LINEAGE_GPU_TOKEN`, `LINEAGE_GATEWAY_TOKEN`) on both sides. The service reads it at
request time and answers 401 to a missing or wrong `Authorization: Bearer <secret>`; compared in constant time. With the variable unset the
service is open (local development only) and says so on start: such a service must stay on loopback or a private network and is not
production-secure. One shared secret is not a user system; it keeps strangers and other tenants off the port, nothing more.
"""
from __future__ import annotations

import hmac
import logging
import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

log = logging.getLogger(__name__)


def bearer(env_var: str) -> dict[str, str]:
    """The header a client sends to a protected service (empty when no secret is configured)."""
    token = os.environ.get(env_var, "")
    return {"Authorization": f"Bearer {token}"} if token else {}


def add_token_auth(app: FastAPI, env_var: str, open_paths: frozenset[str] = frozenset()) -> None:
    """Require the shared secret named by `env_var` on every route of `app` except `open_paths`."""
    if not os.environ.get(env_var):
        log.warning("%s is not set: this service accepts anyone who can reach its port. Use it on loopback or a private network only.", env_var)

    @app.middleware("http")
    async def _token(request: Request, call_next):
        secret = os.environ.get(env_var, "")
        if secret and request.url.path not in open_paths:
            got = request.headers.get("authorization", "")
            if not (got.lower().startswith("bearer ") and hmac.compare_digest(got[7:].strip().encode(), secret.encode())):
                return JSONResponse({"detail": f"a valid bearer token is required ({env_var})"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
        return await call_next(request)
