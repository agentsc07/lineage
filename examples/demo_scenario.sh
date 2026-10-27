#!/usr/bin/env bash
# Plays BUILD_PLAN §4 (Apollo Health AI) end to end against the Lineage server.
#   examples/demo_scenario.sh            # starts its own server (fresh database) on http://127.0.0.1:8765
#   PAUSE=0 examples/demo_scenario.sh    # no pauses between steps
# Every artifact is a tiny inert local fixture from examples/demo_artifacts/ (see make_demo_artifacts.py), copied to a
# temp dir, so bytes are really hashed and inspected. Set LINEAGE_API to use a server you started yourself; its
# registry must already trust the demo signer key: put the key pair in $LINEAGE_DEMO_KEYDIR (demo.key / demo.pub) and start
# the server with LINEAGE_TRUSTED_KEYS=$LINEAGE_DEMO_KEYDIR/demo.pub. Set LINEAGE_DEMO_FEED to the server's
# LINEAGE_ADVISORY_FEED file and step 6 publishes its advisory there. examples/run_dashboard_demo.sh does all of this.
set -uo pipefail
cd "$(dirname "$0")/.."
# macOS can flag the venv's editable .pth files "hidden", which makes Python skip them and `lineage` unimportable from
# console scripts; the repo root on PYTHONPATH makes the demo independent of that.
export PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}"

API="${LINEAGE_API:-http://127.0.0.1:8765}"
PAUSE="${PAUSE:-1}"
WORK="$(mktemp -d)"
ART="$WORK/art"
SERVER_PID=""
HUB_PID=""
cleanup() { [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null; [[ -n "$HUB_PID" ]] && kill "$HUB_PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

if [[ -t 1 ]]; then B=$'\e[1m'; D=$'\e[2m'; G=$'\e[32m'; Y=$'\e[33m'; O=$'\e[38;5;208m'; R=$'\e[31m'; N=$'\e[0m'; else B=; D=; G=; Y=; O=; R=; N=; fi
step() { printf '\n%s%s%s\n%s%s%s\n' "$B" "$1" "$N" "$D" "$2" "$N"; }
note() { printf '  %s%s%s\n' "$D" "$1" "$N"; }
pause() { sleep "$PAUSE"; }
py() { uv run --quiet python "examples/demo_helpers.py" "$@"; }
lineage() { uv run --quiet lineage "$@"; }

verdict_line() { # outcome risk
  case "$1" in
    allow) printf '  %sALLOW%s  risk %s\n' "$G" "$N" "$2" ;;
    allow_with_conditions) printf '  %sALLOW WITH CONDITIONS%s  risk %s\n' "$Y" "$N" "$2" ;;
    quarantine) printf '  %sQUARANTINE%s  risk %s (needs a human)\n' "$O" "$N" "$2" ;;
    block) printf '  %sBLOCK%s  risk %s\n' "$R" "$N" "$2" ;;
    *) printf '  no verdict received\n' ;;
  esac
}

# Submit a local artifact, stream its SSE events, print stages and the final verdict.
intake() { # type path env
  local job url v
  job=$(curl -sf -X POST "$API/intake" -H "Authorization: Bearer $ALICE" -H 'content-type: application/json' \
    -d "{\"artifact_type\":\"$1\",\"ref\":\"$2\",\"environment\":\"$3\"}") || { printf '  %sintake request failed%s\n' "$R" "$N"; LAST_ID=""; return 0; }
  url=$(py get events_url <<<"$job")
  curl -sfN --max-time 120 -H "Authorization: Bearer $ALICE" "$API$url" | py stream | tee "$WORK/out" | grep -v '^VERDICT'
  v=$(grep '^VERDICT' "$WORK/out" | tail -1)
  # shellcheck disable=SC2086
  set -- $v; verdict_line "${2:-}" "${3:-}"
  LAST_ID="${4:-}"
}

# lineage sign + verify one artifact; parents are passport ids already registered by intake.
sign_and_verify() { # type dirname name version repo [--parent id ...]
  local type=$1 dir=$2 name=$3 version=$4 repo=$5; shift 5
  lineage sign "$ART/$dir" --type "$type" --name "$name" --version "$version" --repo "$repo" --key "$WORK/demo.key" "$@" >/dev/null \
    && lineage verify "$ART/$dir.passport.json" --artifact "$ART/$dir" --pubkey "$WORK/demo.pub" 2>&1 | grep -E 'signature|contents|chain|VALID' | sed 's/^/  /'
}

mkdir -p "$ART" && cp -R examples/demo_artifacts/. "$ART/"
# The demo hub stands in for Hugging Face / PyPI (tests/fakehub.py): what it says about an artifact is `fetched`; what the
# artifact says about itself (its own lineage.meta.json) is only `declared`.
HUB_FILE="${LINEAGE_DEMO_HUB_FILE:-$WORK/hub.json}"
py hubfile "$ART" "$HUB_FILE"
if [[ -n "${LINEAGE_DEMO_KEYDIR:-}" ]]; then
  cp "$LINEAGE_DEMO_KEYDIR/demo.key" "$LINEAGE_DEMO_KEYDIR/demo.pub" "$WORK/"
else
  lineage keygen --dir "$WORK" --name demo >/dev/null
fi

TOKENS="${LINEAGE_DEMO_TOKENS:-$WORK/tokens.json}"
if [[ -z "${LINEAGE_API:-}" ]]; then
  echo '{}' >"$WORK/feed.json"
  py trust "$WORK/lineage.db" "$WORK/demo.pub"
  uv run --quiet python -m lineage_server.auth demo --db "$WORK/lineage.db" --out "$TOKENS" >/dev/null
  uv run python -m tests.fakehub --root "$WORK" --records "$HUB_FILE" --port 8766 >"$WORK/hub.log" 2>&1 &
  HUB_PID=$!
  LINEAGE_DEV_LOCAL_PATHS=1 LINEAGE_HUB_TRUSTED_LOCAL=1 LINEAGE_STORE="$WORK/store" LINEAGE_HUB_URL="http://127.0.0.1:8766" LINEAGE_DB="$WORK/lineage.db" LINEAGE_ADVISORY_FEED="$WORK/feed.json" \
    uv run uvicorn lineage_server.app:app --port "${API##*:}" >"$WORK/server.log" 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 40); do curl -sf "$API/healthz" >/dev/null && break; sleep 0.5; done
  curl -sf "$API/healthz" >/dev/null || { echo "Server failed to start; see $WORK/server.log" >&2; exit 1; }
fi

ALICE=$(py get alice <"$TOKENS"); BOB=$(py get bob <"$TOKENS")   # alice requests, bob approves (separation of duties)
printf '%sLineage demo: Apollo Health AI, radiology triage agent%s\n' "$B" "$N"
note "Open the dashboard at http://localhost:5173 to follow along (cd dashboard && npm run dev)"

step "1. Known source" "Signed dataset and package, then a model whose passport chains to both. Fast path."
note "lineage sign + verify: radiology-notes (dataset)"
sign_and_verify dataset radiology-notes radiology-notes 1.0.0 apollo-health/radiology-notes
intake dataset "$ART/radiology-notes" prod; DS_ID="$LAST_ID"; pause
note "lineage sign + verify: tokenizers-fast (package)"
sign_and_verify package tokenizers-fast tokenizers-fast 0.9.2 huggingface/tokenizers
intake package "$ART/tokenizers-fast" prod; PKG_ID="$LAST_ID"; pause
note "lineage sign + verify: triage-base (model), parents = the two passports above"
sign_and_verify model triage-base triage-base 2.1.0 apollo-health/triage-base --parent "$DS_ID" --parent "$PKG_ID"
intake model "$ART/triage-base" staging; MODEL_ID="$LAST_ID"; pause
note "Chain: ${DS_ID:0:19}… and ${PKG_ID:0:19}… -> ${MODEL_ID:0:19}…"

step "2. Unknown model from a hub" "No passport. Parent found from weights, a few layers changed, hidden template instruction."
intake model "$ART/shady-ft" prod; pause

if [[ -n "${LINEAGE_DEMO_ADAPTER:-}" ]]; then
  step "2b. Real backdoored adapter" "Weight-space score from the GPU worker on an adapter from the Brev bank (path on the worker's host)."
  GPU="${LINEAGE_GPU_URL:-http://localhost:8800}"
  P=$(curl -sf -m 120 -X POST "$GPU/weights/parent" -H 'content-type: application/json' \
      -d "{\"model_path\":\"$LINEAGE_DEMO_ADAPTER\"}") || P=""
  PARENT=$(py get parent <<<"${P:-null}" 2>/dev/null || true)
  if [[ -z "$P" || -z "$PARENT" || "$PARENT" == None ]]; then
    printf '  %sGPU worker could not identify a parent for %s%s\n' "$Y" "$LINEAGE_DEMO_ADAPTER" "$N"
  else
    curl -sf -m 300 -X POST "$GPU/weights/spectral" -H 'content-type: application/json' \
      -d "{\"model_path\":\"$LINEAGE_DEMO_ADAPTER\",\"parent\":\"$PARENT\"}" | py spectral "$PARENT" \
      || printf '  %s/weights/spectral failed%s\n' "$R" "$N"
  fi
  pause
fi

step "3. LiteLLM-style package" "Two hours old, look-alike repo, new .pth start-up file."
py stamp "$ART/litellm-lookalike/lineage.meta.json" 2
py hubfile "$ART" "$HUB_FILE"
intake package "$ART/litellm-lookalike" prod; pause

step "4. MCP tool with an intent gap" "Clean description, undeclared network calls. A human decides."
intake tool "$ART/dicom-fetch" dev; TOOL_ID="$LAST_ID"
if [[ -n "$TOOL_ID" ]]; then
  EXPIRES=$(py expiry 14)
  appr() { curl -s -o "$WORK/appr.json" -w '%{http_code}' -X POST "$API/decisions/$TOOL_ID/approve" -H "Authorization: Bearer $1" \
    -H 'content-type: application/json' -d "{\"reason\":\"Network use reviewed; limited to the PACS host\",\"expires\":\"$EXPIRES\"}"; }
  [[ "$(appr "$ALICE")" == 403 ]] && printf '  %salice tried to approve her own request: refused (403)%s\n' "$Y" "$N"
  if [[ "$(appr "$BOB")" == 200 ]]; then
    printf '  %sApproved by bob until %s: now %s%s\n' "$G" "${EXPIRES%%T*}" "$(py get outcome <"$WORK/appr.json")" "$N"
  else printf '  %sapproval refused%s\n' "$Y" "$N"; fi
fi
pause

step "5. Use time" "lineage pull + load-check with the registry's attestation; someone swaps a file afterwards."
export LINEAGE_SERVER="$API" LINEAGE_TOKEN="$ALICE" LINEAGE_CONFIG="$WORK/lineage-config.toml"
if lineage pull "$DS_ID" "$WORK/deployed-notes" --env prod --pin 2>"$WORK/err" | sed 's/^/  /'; [[ -f "$WORK/deployed-notes.lineage-attestation.json" ]]; then
  lineage load-check "$WORK/deployed-notes" --env prod 2>&1 | tail -1 | sed 's/^/  /'
  printf '  %sSwapping notes.csv%s\n' "$D" "$N"
  echo '99,injected row,abnormal' >>"$WORK/deployed-notes/notes.csv"
  if lineage load-check "$WORK/deployed-notes" --env prod 2>"$WORK/err" >"$WORK/lc"; then
    printf '  %sLoad allowed (unexpected)%s\n' "$R" "$N"
  else
    printf '  %sRefused:%s %s\n' "$G" "$N" "$(sed 's/\x1b\[[0-9;]*m//g' "$WORK/err" | head -1 | sed 's/^ *//')"
  fi
else
  printf '  %sCould not pull the dataset:%s %s\n' "$Y" "$N" "$(head -1 "$WORK/err")"
fi
pause

step "6. Watch" "A new advisory lands for an admitted package; the monitor traces the blast radius."
if [[ -z "${LINEAGE_API:-}" || -n "${LINEAGE_DEMO_FEED:-}" ]]; then
  py advisory "${LINEAGE_DEMO_FEED:-$WORK/feed.json}" "tokenizers-fast==0.9.2"
  note "Advisory GHSA-demo-7x4q-9m2p published for tokenizers-fast==0.9.2"
fi
curl -sf -X POST "$API/monitor/tick" -H "Authorization: Bearer $BOB" | py tick || printf '  %smonitor tick failed%s\n' "$R" "$N"
printf '\n%sRevoking the root of the chain (radiology-notes):%s\n' "$B" "$N"
[[ -n "$DS_ID" ]] && { curl -sf -X POST "$API/revoke/$DS_ID?reason=advisory" -H "Authorization: Bearer $BOB" | py revoke || printf '  %srevoke failed%s\n' "$R" "$N"; }

printf '\n%sDone.%s Dashboard: Overview, Approvals and Lineage pages show the same story.\n' "$B" "$N"
