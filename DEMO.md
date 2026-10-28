# Demo commands

Everything here runs on a laptop with no GPU and no API key (a fake hub stands in for Hugging Face and PyPI). Prerequisites: Python 3.11, [`uv`](https://docs.astral.sh/uv/), Node 18+ (dashboard only).

## 0. Once
```bash
uv sync
cd dashboard && npm install && cd ..
uv run pytest -q                 # all green
```

## 1. The terminal story (10 steps, about 2 minutes)
```bash
PAUSE=0 examples/demo_scenario.sh        # drop PAUSE=0 for pauses between steps
```
Starts its own stack on :8765 (fake hub, auth on, Apollo as trusted publisher). Steps: allow-listed publisher, hub fetch, tampered upload, hidden template instruction, pip index, poisoned dataset, federated gate, MCP gateway, monitor and revoke, outbound keys.

## 2. The dashboard story (main demo)
```bash
examples/run_dashboard_demo.sh           # API :8000, dashboard http://localhost:5173
# ports busy:  LINEAGE_PORT=8010 DASH_PORT=5174 examples/run_dashboard_demo.sh
```
Sign in with a token from `examples/demo_tokens.json` (`alice` requests, `bob` approves, `carol` is admin).
Click path for the video:
1. **Intake** -> "Load sample..." -> *Tampered copy (one byte changed)*. Watch S0-S7 fill in with timings; open the identity table (`model.safetensors: changed`) and the `PROV.ORIGIN.MODIFIED` finding (hard block).
2. Same page -> *Clean model* (prod): "human approval required" is the headline; open **Passport and attestation** (five checks, passport JSON, signed attestation).
3. Sign out, sign in as **bob**, reload `/intake/<job id>` (state is rebuilt from the server), **Approve** with a reason and an expiry (or **Reject** to refuse the pending request; that records your name and reason and revokes nothing). The copyable `lineage pull` command appears.
4. **Graph** -> `triage-trained`: SBOM packages fold into one node; the advised package (`jinja2`) stays separate; click a node or an edge for evidence.
5. **Graph** -> `instructions@3c33a2c0f23c` -> **Revoke**: the blast radius lists `triage-trained@1.0.0`.
6. **Policy** is read-only in the browser. A policy change is signed outside it (`uv run python -m lineage_server.tuf sign new-policy.yaml --key owner=owner.key --key security=security.key > update.json`, 2 of 3 role keys) and applied by an admin on that page with "Apply a signed update", or with `PUT /policy`. The page never creates a signature and holds no key. (The demo server has no role keys configured, so it answers "no role keys configured; policy updates are disabled"; set `LINEAGE_ROLE_KEYS` to enable updates.)
7. **Monitor**, **Federated**, **Trusted publishers** pages show the rest of the story.

## 3. Use what was admitted (CLI)
```bash
export LINEAGE_TOKEN=<alice or bob token from examples/demo_tokens.json>
uv run lineage pull <lp:... id from the dashboard> ./admitted/model -e prod --server http://127.0.0.1:8000 --pin
uv run lineage load-check ./admitted/model -e prod --server http://127.0.0.1:8000
uv run lineage verify <passport.json> --pubkey <signer.pub>
```
If `uv run lineage` cannot import the package (macOS editable-install quirk): prefix with `PYTHONPATH=$PWD`.

## 4. Optional
```bash
LINEAGE_DEMO_REAL_HUB=1 PAUSE=0 examples/demo_scenario.sh      # step 2 fetches a real public model from huggingface.co
LINEAGE_TEST_REAL_HUB=1 uv run pytest tests/test_real_hub.py   # real-hub test (network)
uv run python -m bench.report_after_refactor                   # regenerate bench/results_after_refactor.md
```
Hosted reviewer / embeddings (optional): copy `.env.example` to `.env`, add `NVIDIA_API_KEY`, then `set -a; source .env; set +a`.

## 5. Make the submission zip
```bash
scripts/make_submission_zip.sh           # -> dist/lineage-submission-<date>.zip (no .env, .venv, node_modules, databases or tokens)
```
