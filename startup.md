# Startup

Lineage: admission control for AI artifacts. Currently a **skeleton**: schemas are real, the server returns mock data, and most modules raise `NotImplementedError`.

## Prerequisites
- Python 3.11 and [`uv`](https://docs.astral.sh/uv/)
- Node 18+ for the dashboard

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

# Dashboard, http://localhost:5173 (needs the API server running)
cd dashboard && npm install && npm run dev

# Demo: plays the Apollo Health AI story against the server (starts one if none is running)
examples/demo_scenario.sh      # PAUSE=0 to skip the delays
```
Stop the server with `Ctrl+C`. Production: `uv run uvicorn lineage_server.app:app --host 0.0.0.0 --port 8000`.

## Test
```bash
uv run pytest -q
```

## Common problems
- `lineage ... is not implemented yet` (exit code 2): that command's track hasn't landed; expected for now.
- `Address already in use`: add `--port 8001`.
- Dashboard shows "Can't reach the Lineage server": start the API server first (port 8000), or set `LINEAGE_API=http://host:port` before `npm run dev`.
- Bench page says "Sample data": expected until Track D's results are copied to `dashboard/public/bench-results.json`.
- While the server is the mock, every intake returns the same canned verdict.
