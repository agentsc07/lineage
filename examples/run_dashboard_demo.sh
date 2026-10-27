#!/usr/bin/env bash
# One command for the full dashboard story: fresh server on :8000 that trusts the demo signer, the Apollo Health AI
# scenario played against it (step 6 raises the advisory alert), then the dashboard dev server on :5173.
#   examples/run_dashboard_demo.sh          # LINEAGE_GPU_URL, PAUSE are passed through
#   LINEAGE_PORT=8010 DASH_PORT=5174 examples/run_dashboard_demo.sh   # if :8000 / :5173 are taken
# An existing lineage.db is moved aside to lineage.db.<timestamp>.bak, never deleted. Ctrl+C stops everything.
set -uo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}"

DB="${LINEAGE_DB:-lineage.db}"
PORT="${LINEAGE_PORT:-8000}"
DASH_PORT="${DASH_PORT:-5173}"
API_URL="http://127.0.0.1:$PORT"
WORK="$(mktemp -d)"
PIDS=()
cleanup() { for p in ${PIDS[@]:-}; do kill "$p" 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

if curl -sf $API_URL/healthz >/dev/null; then
  echo "Something already answers on :$PORT; stop it, or set LINEAGE_PORT / DASH_PORT." >&2; exit 1
fi
STAMP="$(date +%Y%m%d-%H%M%S)"
for f in "$DB" "$DB-wal" "$DB-shm" "$DB.key"; do
  [[ -e "$f" ]] && mv "$f" "$f.$STAMP.bak" && echo "Moved $f -> $f.$STAMP.bak"
done

uv run --quiet lineage keygen --dir "$WORK" --name demo >/dev/null || { echo "keygen failed" >&2; exit 1; }
echo '{}' >"$WORK/feed.json"
echo '{}' >"$WORK/hub.json"
# stand-in for Hugging Face / PyPI: what it says is `fetched`, what an upload says about itself is only `declared`
uv run --quiet python -m tests.fakehub --root "$WORK" --records "$WORK/hub.json" --port "${HUB_PORT:-8766}" >"$WORK/hub.log" 2>&1 &
PIDS+=($!)

LINEAGE_HUB_URL="http://127.0.0.1:${HUB_PORT:-8766}" LINEAGE_DB="$DB" LINEAGE_TRUSTED_KEYS="$WORK/demo.pub" LINEAGE_ADVISORY_FEED="$WORK/feed.json" \
  uv run --quiet uvicorn lineage_server.app:app --port "$PORT" >"$WORK/server.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 60); do curl -sf $API_URL/healthz >/dev/null && break; sleep 0.5; done
curl -sf $API_URL/healthz >/dev/null || { echo "Server failed to start:" >&2; cat "$WORK/server.log" >&2; exit 1; }
echo "API server on $API_URL (fresh database $DB)"

LINEAGE_DEMO_HUB_FILE="$WORK/hub.json" LINEAGE_API="$API_URL" LINEAGE_DEMO_KEYDIR="$WORK" LINEAGE_DEMO_FEED="$WORK/feed.json" \
  examples/demo_scenario.sh

echo; echo "Dashboard: http://localhost:$DASH_PORT  (Ctrl+C stops the dashboard and the API server)"
cd dashboard && { [[ -d node_modules ]] || npm install; } && LINEAGE_API="$API_URL" npm run dev -- --port "$DASH_PORT" --strictPort
