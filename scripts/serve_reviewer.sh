#!/usr/bin/env bash
# Serve the reviewer LLM (models.yaml: reviewer_llm) with vLLM on :8001 inside tmux window "vllm"; wait for /v1/models.
# Usage: scripts/serve_reviewer.sh            (idempotent: reuses a running server)
set -euo pipefail
cd "$(dirname "$0")/.."
PORT="${VLLM_PORT:-8001}"
MODEL="${REVIEWER_MODEL:-$(uv run python -c "import yaml;print(yaml.safe_load(open('gpu_worker/models.yaml'))['reviewer_llm'])")}"
UTIL="${VLLM_GPU_UTIL:-0.55}"
SESSION="${TMUX_SESSION:-lineage}"
mkdir -p logs

if curl -sf "http://127.0.0.1:${PORT}/v1/models" >/dev/null; then echo "vLLM already serving on :${PORT}"; exit 0; fi

CMD="uv run vllm serve ${MODEL} --port ${PORT} --host 127.0.0.1 --max-model-len 16384 \
 --gpu-memory-utilization ${UTIL} --served-model-name reviewer --trust-remote-code \
 --mamba_ssm_cache_dtype float32 2>&1 | tee logs/vllm.log"
if tmux has-session -t "$SESSION" 2>/dev/null; then tmux new-window -t "$SESSION" -n vllm "$CMD"
else tmux new-session -d -s "$SESSION" -n vllm "$CMD"; fi
echo "started ${MODEL} in tmux ${SESSION}:vllm (log: logs/vllm.log)"

for i in $(seq 1 180); do
  if curl -sf "http://127.0.0.1:${PORT}/v1/models" >/dev/null; then echo "ready after $((i*5))s"; exit 0; fi
  sleep 5
done
echo "vLLM did not become ready in 15 min; see logs/vllm.log" >&2; exit 1
