# Startup

Lineage: admission control for AI artifacts. This branch (Track B) has a working registry server, policy engine, intake pipeline, monitor and MCP gateway. Scanners (Track C), hashing/signing/CLI (Track A) and the GPU worker (Track D) are separate; missing ones degrade to `info` findings instead of failing.

## One command: the full dashboard demo
```bash
LINEAGE_GPU_URL=http://localhost:8800 examples/run_dashboard_demo.sh   # GPU URL optional; PAUSE=0 skips delays
```
Moves any existing `lineage.db` aside to `lineage.db.<timestamp>.bak`, starts the API on http://127.0.0.1:8000 with a fresh database that trusts the demo signer (`LINEAGE_TRUSTED_KEYS`), plays the Apollo Health AI scenario (step 1 ALLOW risk 0; step 6 raises the advisory alert with its blast radius), then starts the dashboard on http://localhost:5173. Ctrl+C stops both. If those ports are taken: `LINEAGE_PORT=8010 DASH_PORT=5174 examples/run_dashboard_demo.sh`.

## Prerequisites
- Python 3.11 and [`uv`](https://docs.astral.sh/uv/)
- Node 18+ only for the dashboard

## Setup
```bash
uv sync
uv run python -m lineage_server.seed --reset     # optional: load the Apollo Health AI demo scenario into ./lineage.db
```

## Run
```bash
# Registry server, http://127.0.0.1:8000  (interactive docs at /docs)
LINEAGE_ADVISORY_FEED=demo_data/advisory_feed.json uv run uvicorn lineage_server.app:app --reload

# Demo step 6: publish a new advisory, then ask the monitor to look
uv run python -m lineage_server.seed advisory
curl -X POST localhost:8000/monitor/tick

# MCP gateway in front of an MCP server (JSON-RPC over HTTP), http://127.0.0.1:8900
uv run python -c "from mcp_gateway.gateway import serve; serve('http://127.0.0.1:9000', pins={})"

# Dashboard, http://localhost:5173 (needs the API server running)
cd dashboard && npm install && npm run dev

# Demo: plays the Apollo Health AI story on local fixtures (examples/demo_artifacts/) against its own
# throwaway server on http://127.0.0.1:8765 (fresh database, demo signer key trusted)
PAUSE=0 examples/demo_scenario.sh      # omit PAUSE=0 for delays between steps
```
Production: `uv run uvicorn lineage_server.app:app --host 0.0.0.0 --port 8000` (no `--reload`).
Stop with `Ctrl+C`.

## Configuration (environment variables, all optional)
| Variable | Default | Meaning |
|---|---|---|
| `LINEAGE_DB` | `lineage.db` | SQLite file. The registry signing key is created beside it as `<db>.key` |
| `LINEAGE_POLICY` | `examples/policy.org.yaml` | Initial policy, installed on first start only |
| `LINEAGE_ROLE_KEYS` | none | JSON `{"owner": "<pubkey hex>", "security": ..., "compliance": ...}`; without it `PUT /policy` returns 409. The seed script configures demo role keys in the DB |
| `LINEAGE_TRUSTED_KEYS` | none | Comma-separated passport signer keys to trust at start-up: `.pub` PEM paths or 64-char hex |
| `LINEAGE_DEMO_ADAPTER` | none | Demo only: path (on the GPU worker's host) of a real backdoored LoRA adapter; enables scenario 2b, which prints its `/weights/spectral` score |
| `LINEAGE_GPU_URL` | `http://localhost:8800` | GPU worker; if unreachable, deep checks are skipped with an `info` finding |
| `LINEAGE_ADVISORY_FEED` | none | Local advisory file the monitor reads in addition to OSV |

## Try it
```bash
curl -s -XPOST localhost:8000/intake -H 'content-type: application/json' \
  -d '{"artifact_type":"dataset","ref":"tests/fixtures/tiny_dataset.csv","environment":"dev"}'
curl -N localhost:8000/events/<job_id>         # SSE: S1..S7, each with started + completed/skipped/failed; S6 carries the Decision
curl -s localhost:8000/artifacts | python -m json.tool
```
Intake refs: a local path (inspected), or a hub id / `pkg==1.2.3` (a *remote reference*: not downloaded, recorded with trust `unknown` and quarantined in dev).
Sidecar files next to an artifact: `passport.json` (signed passport it ships with), `lineage.meta.json` (`released_at`, `licence`, `repo`, `claimed_base`).

Sign a policy update (2-of-3 roles) with the demo keys:
```bash
uv run python -m lineage_server.tuf sign examples/policy.org.yaml \
  --key owner=demo_data/keys/owner.key --key security=demo_data/keys/security.key --days 90 \
  | curl -s -XPUT localhost:8000/policy -H 'content-type: application/json' -d @-
```
The new metadata must expire later than the current policy's (no rollback).

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
- `PUT /policy` → 403: fewer than 2 distinct valid role signatures. 409: rollback (expiry not later than current) or no role keys configured. 400: metadata already expired. 422: invalid policy document.
- Everything is `quarantined` with "policy metadata has expired": renew the policy with a signed update.
- `already has artifacts; rerun with --reset`: the seed refuses to overwrite an existing database.
- `database is locked`: another process holds a write transaction; retry (SQLite WAL, 5 s busy timeout).
- `Address already in use`: add `--port 8001`.
- Dashboard CORS errors: the server only allows `http://localhost:5173` and `http://127.0.0.1:5173`.
- Dashboard shows "Can't reach the Lineage server": start the API server first (port 8000), or set `LINEAGE_API=http://host:port` before `npm run dev`.
- Bench page shows "not measured" for a number: the dashboard reads `bench/results.json`, `bench/weightspace.json` and `bench/reviewer.json` directly (dev server and build); the missing file or field has not been produced yet.
- Overview monitor panel is empty: `GET /monitor/latest` returns the latest tick that raised alerts; run the demo (step 6) or `curl -X POST localhost:8000/monitor/tick` after publishing an advisory.

## Demo problems
- `ModuleNotFoundError: No module named 'lineage'` from `uv run lineage ...` on macOS: the venv's `.pth` files got the "hidden" flag, so Python skips them. Fix: `chflags nohidden .venv/lib/python3.11/site-packages/*.pth` (the demo script also sets `PYTHONPATH`).
- Regenerate the fixtures with `uv run python examples/make_demo_artifacts.py`.
- "Deep check skipped ... not applicable to this model" with a reachable worker: the worker reads model paths on its own host (e.g. a Brev box behind an SSH tunnel) and only knows bank-sized models, so the tiny local demo fixtures get an HTTP 404. Use `LINEAGE_DEMO_ADAPTER` for a real adapter score.
- Without a GPU worker, spectral/behavioural checks and card/code review show as skipped ("needs GPU worker"); parent identification and layer diff run on CPU.
- Package advisories (OSV) need internet; offline the `litellm` step still blocks on the `.pth` start-up hook.

## Validation run (held-out + real-world FP check)
```bash
uv run python -m bench.build_holdout                       # writes bench/corpus_holdout/
python3 bench/fetch_realworld.py /tmp/lineage_rw           # downloads 200 PyPI wheels + 50 HF chat templates (outside the repo; ~1 GB)
uv run python -m bench.run_validation /tmp/lineage_rw      # writes bench/results_holdout.json
python3 bench/report_holdout.py                            # writes bench/results_holdout.md
```

## Precision / dev-set run
```bash
python3 bench/fetch_realworld.py /tmp/lineage_rw                 # PyPI top-200 wheels + 50 chat templates (system python3 has pip)
uv run python -m bench.fetch_previous /tmp/lineage_rw            # the release before each, for diff-aware review
uv run python -m bench.run_validation /tmp/lineage_rw out.json   # run twice (before/after) with different checkouts
python3 bench/report_dev.py before.json after.json               # writes bench/results_dev.md
```
Package intake compares against the previous release: `previous_path` in `lineage.meta.json`, or (online, wheel with a `.dist-info`) the newest earlier wheel from PyPI. `LINEAGE_OFFLINE=1` disables the fetch. S5 sends the code behind every signal to the GPU worker's `/review/code`.
