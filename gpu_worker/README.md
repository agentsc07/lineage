# GPU worker (Track D)

One FastAPI app on `:8800` implementing BUILD_PLAN §2.6 with the models in `lineage/schemas/gpu.py`.

```bash
uv run uvicorn gpu_worker.app:app --host 0.0.0.0 --port 8800
curl localhost:8800/health            # which endpoints are live on this machine
# from your laptop (Brev port forward):  brev port-forward <instance> -p 8800:8800
export LINEAGE_GPU_URL=http://localhost:8800
```

| Endpoint | Needs | Notes |
|---|---|---|
| `/weights/parent`, `/weights/spectral` | CPU (GPU optional) | spectral needs `gpu_worker/calibration/weightspace_model.json` (made by `calibrate_weightspace`) |
| `/behaviour/diff`, `/behaviour/claims`, `/behaviour/triggers` | GPU | `triggers` is an addition to the plan |
| `/notary/certify`, `/notary/check` (+ `/notary/commitment`, `/notary/cert/{id}`) | GPU | sealed set lives in `gpu_worker/notary_data/` (gitignored) |
| `/review/code`, `/review/card` | vLLM on :8001 (`scripts/serve_reviewer.sh`) | prosecutor → defender → judge on `reviewer_llm`; **503** if vLLM is down. Response headers `X-Review-*` carry calls, latency and tokens |
| `/review/policy` (addition) | GPU | org-policy check of a model card or chat template with `policy_model` against `examples/policy.org.yaml`; also reports reviewer-bait |
| `GET /review/stats` (addition) | – | running totals of reviewer calls, latency, tokens/s |

Reviewer set-up on the same machine: `scripts/serve_reviewer.sh` starts vLLM (separate venv `/home/ubuntu/vllm-env`, cu129 wheel, because the
PyPI build needs CUDA 13 and this driver is 12.7) in tmux window `vllm` and waits for `/v1/models`; `scripts/restart_worker.sh` restarts the
worker. Reviewer bench: `uv run python bench/reviewer_fixtures.py && uv run python bench/run_reviewer.py`.

Anything that cannot run answers 503 (or 404 for a missing model path); `lineage.intake.gpu` turns that into an `info`
finding, so intake never crashes.

Model ids live in `models.yaml` (NVIDIA models only for LLM roles). Train the LoRA bank with
`nohup uv run python -m gpu_worker.train_lora_bank > logs/train.log 2>&1 &`; it is resumable.
Evaluation: `bench/parent_eval.py`, `gpu_worker/calibrate_weightspace.py`, `bench/gpu_eval.py`, `bench/run_bench.py`.
