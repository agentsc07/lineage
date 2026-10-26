#!/usr/bin/env bash
# Restart the GPU worker on :8800 (kills only the process listening on that port).
cd "$(dirname "$0")/.."
PID=$(ss -ltnp 2>/dev/null | awk '/:8800 /{match($0,/pid=[0-9]+/); print substr($0,RSTART+4,RLENGTH-4)}' | head -1)
[ -n "$PID" ] && kill "$PID" && sleep 2
mkdir -p logs
nohup uv run uvicorn gpu_worker.app:app --host 0.0.0.0 --port 8800 > logs/worker.log 2>&1 &
for i in $(seq 1 30); do curl -sf localhost:8800/health >/dev/null && { echo "worker up"; exit 0; }; sleep 1; done
echo "worker failed to start; see logs/worker.log" >&2; exit 1
