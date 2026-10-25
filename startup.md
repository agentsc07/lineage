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

## Prove core (Track A) quick tour
```bash
uv run lineage keygen                                  # lineage.key / lineage.pub
uv run lineage sign ./model_dir --name tiny --trust inspected   # -> model_dir.passport.json
uv run lineage verify model_dir.passport.json --artifact ./model_dir
uv run lineage diff ./parent_dir ./child_dir           # changed tensors + relative L2
uv run lineage run -- python train.py                  # records inputs/outputs -> .lineage/runs/*/passport.json (trust: recorded)
uv run lineage load-check ./model_dir --passport model_dir.passport.json
uv run lineage bench hash                              # GB/s (add --path to use your own files)
```
In code: `import lineage; lineage.load("./model_dir")` re-hashes against `<dir>.passport.json` and raises `LoadRefused` on any mismatch, unpinned file or pickle. `lineage.LineageAutoModel.from_pretrained(...)` is the `transformers` drop-in.

If `lineage` is "not found" on macOS, run `uv run python -m lineage.cli ...` (hidden `.pth` files can break the editable install).

## Test
```bash
uv run pytest -q
```

## Common problems
- `lineage ... is not implemented yet` (exit code 2): that command's track hasn't landed; expected for now.
- `Address already in use`: add `--port 8001`.
- Dashboard CORS errors: the server only allows `http://localhost:5173`.
