# Startup

Lineage: admission control for AI artifacts. Currently a **skeleton**: schemas are real, the server returns mock data, and most modules raise `NotImplementedError`.

## Prerequisites
- Python 3.11 and [`uv`](https://docs.astral.sh/uv/)
- Node 18+ only for the dashboard (not built yet)

## Setup
```bash
uv sync
```

## Run
```bash
# API server (mock data), http://127.0.0.1:8000  (docs at /docs)
uv run uvicorn lineage_server.app:app --reload

# CLI
uv run lineage --help

# Dashboard (Track E, not created yet): cd dashboard && npm run dev
```
Stop the server with `Ctrl+C`. Production: `uv run uvicorn lineage_server.app:app --host 0.0.0.0 --port 8000`.

## Test
```bash
uv run pytest -q
```

## Common problems
- `lineage ... is not implemented yet` (exit code 2): that command's track hasn't landed; expected for now.
- `Address already in use`: add `--port 8001`.
- Dashboard CORS errors: the server only allows `http://localhost:5173`.
