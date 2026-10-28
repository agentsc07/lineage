# Repository structure

A single Python 3.11 repository managed with `uv`, with a React dashboard. Nothing in it is dead code; the one heavy folder is `bench/`.

| Path | What it is | Notes |
|---|---|---|
| `lineage/` | The library and CLI. `intake/` (pipeline S0–S7, scanner registry, fetch, hub), `inspect/` (the checkers), `policy/` (decision engine), `schemas/` (Pydantic models: the contracts), `passport/`, `signing/`, `hashing/`, `diff/`, `federated/`, `client.py` / `bind.py` (pull, load, load-check), `run.py` (`lineage run`), `catalog.py` (plain-language description of every check), `cli.py` | Importable by users: `import lineage` |
| `lineage_server/` | The registry: FastAPI app, SQLite store, routes, auth and roles, monitor, graph, policy updates (TUF-style), job streaming | `uvicorn lineage_server.app:app` |
| `dashboard/` | React + Vite + Tailwind UI | `npm run dev`; build output and `node_modules` are not committed |
| `gpu_worker/` | Separate service for GPU checks and the self-hosted reviewer (needs torch, so it is not imported by the server) | Optional; absent = checks say "did not run" |
| `mcp_gateway/` | Runtime gateway for MCP tools (pin, re-check each call) | |
| `tests/` | pytest suite; `tests/fixtures/builders.py` builds the inert attack samples; `tests/fakehub.py` is the stand-in for Hugging Face / PyPI | GPU test files need torch and are skipped without it |
| `examples/` | Demo: policy, scripts (`run_dashboard_demo.sh`, `demo_scenario.sh`), the fake hub, sample artifacts | The demo uses a fresh database each run |
| `scripts/` | `check_matrix.py` (run every check on fixtures), `gen_checks_doc.py`, packaging and worker helpers | |
| `bench/` | Benchmark corpora, runners and result reports (1,000+ files, ~9 MB) | Evidence for the results; not needed to run the product. Could move to its own repository |
| `docs/` | Documentation. Start with `ARTIFACT_FLOW.md` | |
| `bank/` | Manifest of the LoRA adapters used to calibrate the weight-space detector (`gpu_worker/train_lora_bank.py`); the adapters themselves are git-ignored | |
| Root files | `README.md`, `CLAUDE.md` (rules for contributors), `pyproject.toml`, `uv.lock`, `.python-version`, `.env.example`, `.gitignore` | Only what tooling expects at the root |

Against common practice: a flat multi-package layout (`lineage/`, `lineage_server/`, `gpu_worker/`) is normal for a monorepo; `src/` layout, a `Makefile`, CI configuration and a single `docs/` index would be the usual additions. `startup.md`, `DEMO.md` and `DECISIONS.md` were moved into `docs/` (links updated). Nothing was deleted: no tracked file was junk (no caches, backups or binaries).
