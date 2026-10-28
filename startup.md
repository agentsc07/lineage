# Startup

Lineage: admission control for AI artifacts (models, datasets, packages, MCP tools). Demo commands: `DEMO.md`.

## Prerequisites
Python 3.11, [`uv`](https://docs.astral.sh/uv/), Node 18+ (dashboard only). No GPU and no API key are needed for the server, the dashboard or the demo.

## Setup
```bash
uv sync
cd dashboard && npm install && cd ..
```

## Run
```bash
# API server, http://127.0.0.1:8000 (interactive docs at /docs). Auth is on: create users first.
uv run python -m lineage_server.auth add --db lineage.db --name alice --roles requester     # prints a token once
uv run python -m lineage_server.auth add --db lineage.db --name bob --roles approver
uv run uvicorn lineage_server.app:app --port 8000
# no auth, local development only:  LINEAGE_REQUIRE_AUTH=0 uv run uvicorn lineage_server.app:app --reload

# Dashboard, http://localhost:5173 (needs the API; LINEAGE_API=http://127.0.0.1:8000 is the default target)
cd dashboard && npm run dev

# Everything at once, with the demo story and tokens:
examples/run_dashboard_demo.sh
```
Stop with Ctrl+C. Tests: `uv run pytest -q`. Dashboard build: `cd dashboard && npm run build`.

## Configuration (environment variables, all optional)
| Variable | Default | Meaning |
|---|---|---|
| `LINEAGE_DB` | `lineage.db` | SQLite file; the registry signing key is created beside it as `<db>.key` |
| `LINEAGE_POLICY` | `examples/policy.org.yaml` | Initial policy, installed on first start only |
| `LINEAGE_REQUIRE_AUTH` | `1` | `0` turns authentication off (everyone is an anonymous admin) |
| `LINEAGE_ROLE_KEYS` | none | JSON of the owner / security / compliance public keys that must co-sign policy updates |
| `LINEAGE_MONITOR_MINUTES` | `60` | Scheduled monitor interval; `0` turns it off |
| `LINEAGE_MAX_UPLOAD_MB` / `LINEAGE_MAX_FETCH_MB` | `2048` / `4096` | Upload and hub-fetch size caps |
| `LINEAGE_PUBLIC_URL` | request URL | Server URL used in the generated `lineage pull` command |
| `LINEAGE_HUB_URL` / `LINEAGE_HF_URL` | Hugging Face / PyPI | Point intake at a different hub (the demo uses a local fake hub) |
| `LINEAGE_TOKEN`, `LINEAGE_SERVER`, `LINEAGE_REGISTRY_PUBKEY` | none | CLI side: token, registry URL, pinned registry key (also in `~/.lineage/config.toml`) |
| `NVIDIA_API_KEY` | none | Optional hosted LLM reviewer and embeddings (see `.env.example`); without it those checks report "did not run" |
| `LINEAGE_GPU_URL` | none | Optional GPU worker (weights, behaviour, notary); without it those checks report "did not run" |
| `LINEAGE_GPU_TOKEN` | none | Shared secret: set it on the worker and on the server and the worker answers 401 without `Authorization: Bearer <secret>` (`/health` stays open). Unset: the worker is open, loopback or private network only |
| `LINEAGE_GATEWAY_TOKEN` | none | Same for the MCP gateway (`POST /`, `/gateway/status`); unset: open, and it binds to 127.0.0.1 by default |

## Common problems
- **`uv run lineage` cannot import `lineage`** (macOS): prefix with `PYTHONPATH=$PWD`.
- **Port already in use**: `LINEAGE_PORT=8010 DASH_PORT=5174 examples/run_dashboard_demo.sh`.
- **401 from the API**: send `Authorization: Bearer <token>` (the dashboard asks for it at sign-in).
- **A stale demo stack still answers on :8000**: stop the old `uvicorn` / `vite` processes before relaunching.
