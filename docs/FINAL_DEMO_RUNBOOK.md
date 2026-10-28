# Final demo runbook

Everything here was run in this audit except where marked. Time: about 5 minutes to start, 4 minutes to present.

## 0. Before recording (Mac)
```bash
cd ~/Desktop/01_Projects/AEGIS/code
git fetch origin && git checkout claude/admiring-babbage-styasl && git pull origin claude/admiring-babbage-styasl   # or main after you merge it
export PYTHONPATH="$PWD" && uv sync
uv run pytest -q --ignore=tests/test_gpu_app.py --ignore=tests/test_gpu_weights.py --ignore=tests/test_gpu_behaviour_notary.py --ignore=tests/test_gpu_reviewer.py   # expect all green (GPU files need torch)
(cd dashboard && npm install)
```
Optional, **only if you really have them**: `export NVIDIA_API_KEY=...` (live AI review) and `export LINEAGE_GPU_URL=http://localhost:8800` (GPU worker, section 5 below). Without them the demo honestly shows "did not run".

## 1. Clean start
```bash
examples/run_dashboard_demo.sh
```
It moves an existing `lineage.db` and its key to `*.bak` (nothing is deleted), builds a fresh database, plays the whole story, prints three `export` lines for the command line, and serves the dashboard at http://localhost:5173 (use `LINEAGE_PORT=8010 DASH_PORT=5174 ...` if the ports are taken). Ctrl+C stops everything. Tokens change on every run; the login page lists alice, bob, carol and auditor, and the sidebar switches user without signing out.

Reset between takes: Ctrl+C and run it again. Keys and fixtures are rebuilt; `*.bak` files are yours to keep or remove.

## 2. Click sequence (alice requests, bob approves)
| Time | Do | Expect |
|---|---|---|
| 0:00 | Overview | catalogue counts, no errors |
| 0:25 | alice -> Intake -> **Load sample… -> Tampered copy** | Block, critical `model.safetensors: differs`, hard block |
| 1:10 | **Load sample… -> Clean model** | Quarantine ("human approval required"), risk about 54-66, AI review and GPU checks shown as **Did not run** with their cost |
| 1:40 | switch to **bob** (sidebar) -> Approvals -> approve with a reason | `allow_with_conditions`; alice's own attempt is refused (403) |
| 2:00 | Terminal: the printed `export` lines, then `uv run lineage pull triage-base ./m -e prod --pin` and `uv run lineage load-check ./m -e prod` | "pulled ... 5 file(s)" and "load allowed" |
| 2:30 | **Load sample… -> Bad package** | Block (startup hook, decode-and-execute) |
| 2:50 | Lineage -> `triage-trained@1.0.0` | edges to base model, dataset, `acme-llm@1.4.0` (from `lineage run`) |
| 3:10 | switch to **carol** -> revoke the dataset (graph or `uv run lineage revoke <lp:id> --reason ...` with carol's token) | descendants flagged |
| 3:30 | Terminal: `uv run lineage load-check ./m -e prod` after revoking the base model | `registry reports the artifact revoked`, REFUSED |
| 3:45 | Monitor | an advisory alert with its blast radius (step 9 of the scenario raises one for a package in the trained model's package list; if that step failed, the script publishes one for `acme-llm 1.4.0`). **Run a check now** re-runs it. A real run needs `LINEAGE_MONITOR_MINUTES` and OSV reachable |

## 3. What to say, and what not
Say: every check runs or says it did not and is priced; every decision is signed; every use re-checks it; protection holds on Lineage's paths. Do **not** say: GPU checks ran, the AI review ran, detection is comprehensive, the parent search covers all models, or "Verify passport" re-hashes files. See `FINAL_BLOCKERS.md`.

## 4. If it breaks
| Symptom | Fix |
|---|---|
| `No module named 'lineage'` | `export PYTHONPATH="$PWD"` |
| `Something already answers on :8000` | stop the old run, or set `LINEAGE_PORT` / `DASH_PORT` |
| `valid API token is required` | tokens are new each run: use the printed export lines |
| Intake stage "did not run" | expected without a key or GPU worker |

## 5. Optional: GPU worker and live AI review (NVIDIA Brev)

Run the registry and the worker **on the same GPU machine**: the worker reads model files from its own disk.
```bash
git clone https://github.com/agentsc07/lineage.git && cd lineage && git checkout main
uv sync --extra gpu
uv run pytest tests/test_gpu_app.py tests/test_gpu_weights.py tests/test_gpu_behaviour_notary.py tests/test_gpu_reviewer.py -q
# parent bank: the worker identifies parents only among models in its local Hugging Face cache (gpu_worker/models.yaml: parent_bank)
uv run python -c "import yaml; from huggingface_hub import snapshot_download as d; [print(m, d(m, allow_patterns=['*.safetensors','*.json'])) for m in yaml.safe_load(open('gpu_worker/models.yaml'))['parent_bank']]"
export NVIDIA_API_KEY=<key> LINEAGE_GPU_TOKEN=<shared secret>     # the key lets the worker answer /review/code and /review/card through the hosted API
scripts/restart_worker.sh && curl -s localhost:8800/health        # parent_bank listed, /review/* true
export PYTHONPATH="$PWD" LINEAGE_GPU_URL=http://localhost:8800
examples/run_dashboard_demo.sh                                    # then on your laptop: brev port-forward <instance> -p 5173:5173
```
What needs what: the **GPU** is used only by the worker (spectral score of weight changes, behaviour comparison, notary); the **NVIDIA API** only by the reviewer. Of `gpu_worker/models.yaml`, only `parent_bank` must be downloaded; `reviewer_llm` is used only if you self-host the reviewer with vLLM (`scripts/serve_reviewer.sh`), `base_model` only by the adapter-training script, `policy_model` only by the worker's optional local policy check. The demo's stand-in models are too small for the spectral detector (it answers "outside the calibrated range"): intake `hf:Qwen/Qwen2.5-0.5B-Instruct` for a real result. These GPU paths were not executed in the audit environment (`FINAL_BLOCKERS.md`).
