#!/usr/bin/env bash
# Sourced by demo_scenario.sh and run_dashboard_demo.sh: everything the demo needs besides the story itself.
#   WORK, DB, PORT (server), HUB_PORT (fake hub), SITE_PORT (the company site that hosts .well-known) must be set; PIDS is an array.
# Starts: a fake hub (tests/fakehub.py: the stand-in for Hugging Face and PyPI), a static site serving Apollo's published keys, and the Lineage
# server with auth on, the Apollo team as a trusted publisher, and the monitor driven by hand. No GPU, no NVIDIA key.
set -uo pipefail
: "${REPO:?demo_up.sh needs REPO (the repository root)}"
mkdir -p "$WORK/site"
uv run --quiet --project "$REPO" python "$REPO/examples/make_demo_hub.py" "$WORK/demo" >/dev/null || { echo "could not build the demo hub" >&2; return 1; }
HUB_FILE="$WORK/demo/hub.json"
# Apollo's signing key, published at /.well-known/lineage-keys.json (scope: its own uploads and hf:apollo-health/*)
uv run --quiet --project "$REPO" lineage keygen --dir "$WORK/site" --name apollo --publish --scope 'upload:*' --scope 'hf:apollo-health/*' >/dev/null || { echo "keygen failed" >&2; return 1; }
uv run --quiet --project "$REPO" python "$REPO/examples/demo_helpers.py" demo_policy "$WORK/site/apollo.pub" "$WORK/policy.yaml"
echo '{}' >"$WORK/feed.json"
uv run --quiet --project "$REPO" python -c "from lineage_server import db; c = db.connect('$DB'); db.init_schema(c); c.commit()"
uv run --quiet --project "$REPO" python -m lineage_server.auth demo --db "$DB" --out "${TOKENS:-$WORK/tokens.json}" >/dev/null
uv run --quiet --project "$REPO" python -m tests.fakehub --root "$WORK/demo/hub" --records "$HUB_FILE" --port "$HUB_PORT" >"$WORK/hub.log" 2>&1 &
PIDS+=($!)
python3 -m http.server "$SITE_PORT" --bind 127.0.0.1 --directory "$WORK/site" >"$WORK/site.log" 2>&1 &
PIDS+=($!)
SERVER_ENV=(LINEAGE_POLICY="$WORK/policy.yaml" LINEAGE_HUB_URL="http://127.0.0.1:$HUB_PORT" LINEAGE_STORE="$WORK/store" LINEAGE_UPLOADS="$WORK/uploads"
  LINEAGE_FETCH_DIR="$WORK/fetch" LINEAGE_OFFLINE=1 LINEAGE_MONITOR_MINUTES=0 LINEAGE_DB="$DB" LINEAGE_ADVISORY_FEED="$WORK/feed.json")
[[ -n "${DEMO_HF_URL:-}" ]] && SERVER_ENV+=(LINEAGE_HF_URL="$DEMO_HF_URL")   # the real Hugging Face hub, for the model fetch only
env "${SERVER_ENV[@]}" uv run --quiet --project "$REPO" uvicorn lineage_server.app:app --port "$PORT" >"$WORK/server.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null && break; sleep 0.5; done
curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null || { echo "Server failed to start:" >&2; cat "$WORK/server.log" >&2; return 1; }
