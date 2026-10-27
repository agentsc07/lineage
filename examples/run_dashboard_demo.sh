#!/usr/bin/env bash
# One command for the full dashboard story: the demo stack (fake hub, auth-on server on :8000, Apollo as a trusted publisher), the v2 scenario played
# against it, then the dashboard dev server on :5173. Sign in with a token from examples/demo_tokens.json (alice requests, bob approves).
#   examples/run_dashboard_demo.sh          # PAUSE is passed through
#   LINEAGE_PORT=8010 DASH_PORT=5174 examples/run_dashboard_demo.sh   # if :8000 / :5173 are taken
#   LINEAGE_DEMO_REAL_HUB=1 examples/run_dashboard_demo.sh           # step 2 fetches a real public model from huggingface.co
# An existing lineage.db is moved aside to lineage.db.<timestamp>.bak, never deleted. Ctrl+C stops everything.
set -uo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}"

DB="${LINEAGE_DB:-lineage.db}"
PORT="${LINEAGE_PORT:-8000}"
DASH_PORT="${DASH_PORT:-5173}"
HUB_PORT="${HUB_PORT:-8766}"; SITE_PORT="${SITE_PORT:-8767}"
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
TOKENS="examples/demo_tokens.json"   # written once, ignored by git
[[ "${LINEAGE_DEMO_REAL_HUB:-}" == 1 ]] && DEMO_HF_URL="https://huggingface.co"
# shellcheck disable=SC1091
source examples/demo_up.sh || exit 1
echo "API server on $API_URL (fresh database $DB); demo tokens in $TOKENS"

LINEAGE_API="$API_URL" LINEAGE_DEMO_DIR="$WORK" LINEAGE_DEMO_DB="$DB" LINEAGE_DEMO_TOKENS="$TOKENS" LINEAGE_DEMO_FEED="$WORK/feed.json" HUB_PORT="$HUB_PORT" SITE_PORT="$SITE_PORT" \
  examples/demo_scenario.sh

echo; echo "Dashboard: http://localhost:$DASH_PORT  (sign in with alice or bob from $TOKENS; Ctrl+C stops the dashboard and the API server)"
cd dashboard && { [[ -d node_modules ]] || npm install; } && LINEAGE_API="$API_URL" npm run dev -- --port "$DASH_PORT" --strictPort
