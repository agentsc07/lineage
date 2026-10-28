#!/usr/bin/env bash
# One command for the full dashboard story: the demo stack (fake hub, auth-on server on :8000, Apollo as a trusted publisher), the v2 scenario played
# against it, then the dashboard dev server on :5173. Sign in with a token from examples/demo_tokens.json (alice requests, bob approves).
#   examples/run_dashboard_demo.sh          # PAUSE is passed through
#   LINEAGE_PORT=8010 DASH_PORT=5174 examples/run_dashboard_demo.sh   # if :8000 / :5173 are taken
#   LINEAGE_DEMO_REAL_HUB=1 examples/run_dashboard_demo.sh           # step 2 fetches a real public model from huggingface.co
# An existing lineage.db is moved aside to lineage.db.<timestamp>.bak, never deleted. Ctrl+C stops everything.
set -uo pipefail
cd "$(dirname "$0")/.."
REPO="$PWD"   # every uv run below names the project, so a cd into a temp dir cannot break it
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

# The Monitor page must have something to show. Step 9 of the scenario normally raises an alert; if it did not (a step failed), publish an advisory
# for the admitted acme-llm 1.4.0 and run one check, so the page shows an alert with its blast radius.
BOB_TOKEN="$(python3 -c "import json;print(json.load(open('$TOKENS'))['bob'])" 2>/dev/null)"
N_ALERTS="$(curl -sf -H "Authorization: Bearer $BOB_TOKEN" "$API_URL/monitor/latest" | python3 -c "import sys,json;d=json.load(sys.stdin);print(len(d['alerts']) if d else 0)" 2>/dev/null || echo 0)"
if [[ "$N_ALERTS" == "0" ]]; then
  echo "Monitor had no alert: publishing a demo advisory for acme-llm==1.4.0 and running one check"
  uv run --quiet --project "$REPO" python "$REPO/examples/demo_helpers.py" advisory "$WORK/feed.json" "acme-llm==1.4.0" >/dev/null
  curl -sf -X POST -H "Authorization: Bearer $BOB_TOKEN" "$API_URL/monitor/tick" >/dev/null || echo "  (the check could not run)"
fi
uv run --quiet --project "$REPO" python "$REPO/examples/make_dashboard_samples.py" "$WORK/demo" "$WORK/samples" >/dev/null && export LINEAGE_SAMPLES_DIR="$WORK/samples"
BOB_TOKEN="$(python3 -c "import json,sys;print(json.load(open('$TOKENS'))['bob'])" 2>/dev/null)"
echo; echo "Command line, in another terminal (tokens change on every run of this script):"
echo "  export PYTHONPATH=\"$REPO\" LINEAGE_SERVER=$API_URL LINEAGE_TOKEN=$BOB_TOKEN"
echo "  uv run lineage pull <name or lp:id> ./admitted/x -e prod --pin"
echo; echo "Dashboard: http://localhost:$DASH_PORT  (the page lists alice, bob, carol and auditor so you can switch user without signing out; Ctrl+C stops the dashboard and the API server)"
cd dashboard && { [[ -d node_modules ]] || npm install; } && LINEAGE_DEMO_TOKENS="$REPO/$TOKENS" LINEAGE_API="$API_URL" npm run dev -- --port "$DASH_PORT" --strictPort
