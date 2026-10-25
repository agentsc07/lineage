#!/usr/bin/env bash
# Plays BUILD_PLAN §4 (Apollo Health AI) end to end against the Lineage server.
#   examples/demo_scenario.sh            # uses http://127.0.0.1:8000, starts the server if it is down
#   LINEAGE_API=http://host:8000 PAUSE=0 examples/demo_scenario.sh
# Steps that depend on a track that has not landed print a note and the demo carries on.
set -uo pipefail
cd "$(dirname "$0")/.."

API="${LINEAGE_API:-http://127.0.0.1:8000}"
PAUSE="${PAUSE:-1}"
WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() { [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

if [[ -t 1 ]]; then B=$'\e[1m'; D=$'\e[2m'; G=$'\e[32m'; Y=$'\e[33m'; O=$'\e[38;5;208m'; R=$'\e[31m'; N=$'\e[0m'; else B=; D=; G=; Y=; O=; R=; N=; fi
step() { printf '\n%s%s%s\n%s%s%s\n' "$B" "$1" "$N" "$D" "$2" "$N"; }
note() { printf '  %s%s%s\n' "$D" "$1" "$N"; }
pause() { sleep "$PAUSE"; }
py() { python3 "$(dirname "${BASH_SOURCE[0]}")/demo_helpers.py" "$@"; }

verdict_line() { # outcome risk
  case "$1" in
    allow) printf '  %sALLOW%s  risk %s\n' "$G" "$N" "$2" ;;
    allow_with_conditions) printf '  %sALLOW WITH CONDITIONS%s  risk %s\n' "$Y" "$N" "$2" ;;
    quarantine) printf '  %sQUARANTINE%s  risk %s (needs a human)\n' "$O" "$N" "$2" ;;
    block) printf '  %sBLOCK%s  risk %s\n' "$R" "$N" "$2" ;;
    *) printf '  no verdict received\n' ;;
  esac
}

# Submit an artifact, stream its SSE events, print stages and the final verdict.
intake() { # type ref env
  local job url v
  job=$(curl -sf -X POST "$API/intake" -H 'content-type: application/json' \
    -d "{\"artifact_type\":\"$1\",\"ref\":\"$2\",\"environment\":\"$3\"}") || { printf '  %sintake request failed%s\n' "$R" "$N"; LAST_ID=""; return 0; }
  url=$(py get events_url <<<"$job")
  curl -sfN --max-time 60 "$API$url" | py stream | tee "$WORK/out" | grep -v '^VERDICT'
  v=$(grep '^VERDICT' "$WORK/out" | tail -1)
  # shellcheck disable=SC2086
  set -- $v; verdict_line "${2:-}" "${3:-}"
  LAST_ID="${4:-}"
}

if ! curl -sf "$API/healthz" >/dev/null; then
  note "Server not reachable at $API; starting one"
  uv run uvicorn lineage_server.app:app --port "${API##*:}" >"$WORK/server.log" 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 30); do curl -sf "$API/healthz" >/dev/null && break; sleep 0.5; done
  curl -sf "$API/healthz" >/dev/null || { echo "Server failed to start; see $WORK/server.log" >&2; exit 1; }
fi

printf '%sLineage demo: Apollo Health AI, radiology triage agent%s\n' "$B" "$N"
note "Open the dashboard at http://localhost:5173 to follow along (cd dashboard && npm run dev)"

step "1. Known source" "A signed dataset, then a model that chains to it. Fast path."
intake dataset "apollo/radiology-notes@1.0.0" prod; pause
intake model "apollo/triage-llama-ft@2.1.0" prod; MODEL_ID="$LAST_ID"; pause

step "2. Unknown model from a hub" "No passport. Parent found from weights, layers 28-32 changed, hidden template instruction."
intake model "shady-org/llama-3.2-1b-medical-ft" prod; pause

step "3. LiteLLM-style package" "Two hours old, look-alike repo, new .pth start-up file."
intake package "litellm==1.82.7" prod; pause

step "4. MCP tool with an intent gap" "Clean description, undeclared network calls. A human decides."
intake tool "mcp://apollo/dicom-fetch" dev; TOOL_ID="$LAST_ID"
if [[ -n "$TOOL_ID" ]]; then
  EXPIRES=$(py expiry 14)
  d=$(curl -sf -X POST "$API/decisions/$TOOL_ID/approve" -H 'content-type: application/json' \
    -d "{\"approver\":\"dr.rao@apollo.health\",\"reason\":\"Network use reviewed; limited to the PACS host\",\"expires\":\"$EXPIRES\"}") \
    && printf '  %sApproved by dr.rao@apollo.health until %s%s\n' "$G" "${EXPIRES%%T*}" "$N" \
    || printf '  %sapproval failed%s\n' "$R" "$N"
fi
pause

step "5. Use time" "Someone swaps tokenizer.json after approval; lineage load-check must refuse."
mkdir -p "$WORK/model" && echo '{"version":"1"}' >"$WORK/model/tokenizer.json" && echo '{"layers":28}' >"$WORK/model/config.json"
lineage() { uv run --quiet lineage "$@"; }
if lineage sign "$WORK/model" --type model --name demo-model --key "$WORK/demo.key" --out "$WORK/model.passport.json" 2>"$WORK/err"; then
  printf '  %sSigned; now swapping tokenizer.json%s\n' "$D" "$N"
  echo '{"version":"1","added_tokens":[{"content":"<!--hidden-->"}]}' >"$WORK/model/tokenizer.json"
  if lineage load-check "$WORK/model" --passport "$WORK/model.passport.json" 2>"$WORK/err"; then
    printf '  %sLoad allowed (unexpected)%s\n' "$R" "$N"
  else
    printf '  %sRefused:%s %s\n' "$G" "$N" "$(head -1 "$WORK/err")"
  fi
elif grep -q 'not implemented' "$WORK/err"; then
  note "sign / load-check are not implemented yet (Track A); the swapped tokenizer.json would be refused here"
else
  printf '  %sCould not sign the demo model:%s %s\n' "$Y" "$N" "$(head -1 "$WORK/err")"
fi
pause

step "6. Watch" "A new advisory lands for an admitted package; the monitor traces the blast radius."
curl -sf -X POST "$API/monitor/tick" | py tick || printf '  %smonitor tick failed%s\n' "$R" "$N"
printf '\n%sRevoking the root of the chain:%s\n' "$B" "$N"
ROOT=$(curl -sf "$API/artifacts" | py get 0.id)
curl -sf -X POST "$API/revoke/$ROOT?reason=advisory" | py revoke || printf '  %srevoke failed%s\n' "$R" "$N"

printf '\n%sDone.%s Dashboard: Overview, Approvals and Lineage pages show the same story.\n' "$B" "$N"
