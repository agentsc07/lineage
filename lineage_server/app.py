"""FastAPI app: registry, policy engine, gate, monitor.

Configuration (environment variables, all optional):
- `LINEAGE_DB`          SQLite file (default `lineage.db`); the registry signing key lives beside it as `<db>.key`.
- `LINEAGE_POLICY`      initial policy YAML, installed on first start only (default `examples/policy.org.yaml`).
- `LINEAGE_ROLE_KEYS`   JSON file `{"owner": "<pubkey hex>", "security": ..., "compliance": ...}`; enables PUT /policy.
- `LINEAGE_TRUSTED_KEYS` dev bootstrap only: passport signer keys trusted (any scope) when the policy lists no `trusted_publishers`.
- `LINEAGE_REQUIRE_AUTH` default 1: every request needs an API token (lineage_server.auth); 0 is for local development only.
- `LINEAGE_GPU_URL`    GPU worker (default `http://localhost:8800`); optional, unreachable means `CHECK.NOT_RUN.*` findings.
- `LINEAGE_HUB_URL`    hub that vouches for artifacts (`fetched` facts); tests and the demo point it at `tests/fakehub.py`.
- `LINEAGE_ADVISORY_FEED` local advisory feed for the monitor (see `lineage_server.monitor`).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from lineage.intake.hub import Hub, default_hub
from lineage.schemas.policy import PolicyPack
from lineage.store import Store
from lineage_server import auth, db, policy_store, trust
from lineage_server.jobs import JobStore
from lineage_server.routes import artifacts, attestations, decisions, events, graph, intake, passports, policy, store, trusted_publishers


def create_app(
    db_path: Path | str | None = None,
    policy_path: Path | str | None = None,
    role_keys_path: Path | str | None = None,
    hub: Hub | None = None,
    require_auth: bool | None = None,
) -> FastAPI:
    db_path = Path(db_path or os.environ.get("LINEAGE_DB", "lineage.db"))
    policy_path = Path(policy_path or os.environ.get("LINEAGE_POLICY", "examples/policy.org.yaml"))
    role_keys_path = role_keys_path or os.environ.get("LINEAGE_ROLE_KEYS")

    app = FastAPI(title="Lineage", version="0.1.0", description="Admission control for AI artifacts")
    app.add_middleware(
        CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_methods=["*"], allow_headers=["*"]
    )

    conn = db.connect(db_path)
    db.init_schema(conn)
    app.state.db_path = db_path
    app.state.signing_key = trust.load_or_create_key(db_path.with_suffix(db_path.suffix + ".key"))
    app.state.jobs = JobStore()
    app.state.require_auth = (os.environ.get("LINEAGE_REQUIRE_AUTH", "1") != "0") if require_auth is None else require_auth
    base = db_path.parent
    app.state.store = Store(os.environ.get("LINEAGE_STORE") or base / "lineage-store")
    app.state.uploads = Path(os.environ.get("LINEAGE_UPLOADS") or base / "lineage-uploads")
    app.state.fetch_dir = Path(os.environ.get("LINEAGE_FETCH_DIR") or base / "lineage-fetch")
    app.state.hub = hub or default_hub()  # fetched facts come from here (`LINEAGE_HUB_URL`); None means nothing is fetched
    if policy_store.get_state(conn) is None:
        policy_store.bootstrap(conn, PolicyPack.from_yaml(policy_path))
    if role_keys_path:
        policy_store.set_role_keys(conn, json.loads(Path(role_keys_path).read_text()))
    trust.trust_key(conn, app.state.signing_key.public_key(), "registry")
    for entry in filter(None, (s.strip() for s in os.environ.get("LINEAGE_TRUSTED_KEYS", "").split(","))):
        trust.trust_key(conn, trust.load_public(entry), "trusted-keys-env")
    conn.commit()
    conn.close()

    for module in (intake, events, artifacts, passports, graph, decisions, policy, trusted_publishers, attestations, store):
        app.include_router(module.router, dependencies=[Depends(auth.current_user)])

    @app.get("/healthz")
    def healthz() -> dict[str, str | bool]:
        return {"status": "ok", "auth": app.state.require_auth}

    return app


_default_app: FastAPI | None = None


def __getattr__(name: str):
    """`uvicorn lineage_server.app:app` builds the default app on first access, so importing this module
    has no side effects (no database file, no key generation)."""
    global _default_app
    if name == "app":
        if _default_app is None:
            _default_app = create_app()
        return _default_app
    raise AttributeError(name)
