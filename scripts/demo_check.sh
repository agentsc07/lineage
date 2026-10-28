#!/usr/bin/env bash
# Play the whole demo scenario against a throwaway stack and check the data it leaves behind (scripts/demo_assert.py).
#   scripts/demo_check.sh            # about two minutes, offline, no GPU, no API key
set -uo pipefail
cd "$(dirname "$0")/.."
REPO="$PWD"; export PYTHONPATH="$PWD"
WORK="$(mktemp -d)"; DB="$WORK/lineage.db"; PORT="${LINEAGE_PORT:-8010}"; HUB_PORT="${HUB_PORT:-8766}"; SITE_PORT="${SITE_PORT:-8767}"; TOKENS="$WORK/tokens.json"; PIDS=()
trap 'for p in ${PIDS[@]:-}; do kill "$p" 2>/dev/null; done; rm -rf "$WORK"' EXIT
# shellcheck disable=SC1091
source examples/demo_up.sh || exit 1
LINEAGE_API="http://127.0.0.1:$PORT" LINEAGE_DEMO_DIR="$WORK" LINEAGE_DEMO_DB="$DB" LINEAGE_DEMO_TOKENS="$TOKENS" LINEAGE_DEMO_FEED="$WORK/feed.json" \
  HUB_PORT="$HUB_PORT" SITE_PORT="$SITE_PORT" PAUSE=0 examples/demo_scenario.sh >"$WORK/scenario.out" 2>&1 || { tail -30 "$WORK/scenario.out"; exit 1; }
grep -E "training environment|install" "$WORK/scenario.out" | head -3
uv run --quiet --project "$REPO" python scripts/demo_assert.py "$DB" "$WORK/policy.yaml"
