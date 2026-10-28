#!/usr/bin/env bash
# Lineage demo v2: one mandatory flow, no unverifiable trust. Every step works without a GPU and without a key.
#   examples/demo_scenario.sh            # starts its own stack (fake hub, server with auth on) on :8765
#   PAUSE=0 examples/demo_scenario.sh    # no pauses between steps
#   LINEAGE_DEMO_REAL_HUB=1 examples/demo_scenario.sh   # step 2 fetches a real public model from huggingface.co instead of the fake hub
# With LINEAGE_API set (examples/run_dashboard_demo.sh does this) the stack is already up; also set LINEAGE_DEMO_TOKENS, LINEAGE_DEMO_DIR (its WORK),
# LINEAGE_DEMO_DB and LINEAGE_DEMO_FEED.
set -uo pipefail
cd "$(dirname "$0")/.."
REPO="$PWD"   # every uv run below names the project, so a cd into a temp dir cannot break it
export PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}"   # macOS can hide the venv's editable .pth files

PORT="${LINEAGE_PORT:-8765}"
API="${LINEAGE_API:-http://127.0.0.1:$PORT}"
PAUSE="${PAUSE:-1}"
HUB_PORT="${HUB_PORT:-8766}"; SITE_PORT="${SITE_PORT:-8767}"
PIDS=()
if [[ -n "${LINEAGE_API:-}" ]]; then
  WORK="${LINEAGE_DEMO_DIR:?set LINEAGE_DEMO_DIR with LINEAGE_API}"; DB="${LINEAGE_DEMO_DB:?}"; TOKENS="${LINEAGE_DEMO_TOKENS:?}"; OWN=0
  PORT="${API##*:}"
else
  WORK="$(mktemp -d)"; DB="$WORK/lineage.db"; TOKENS="$WORK/tokens.json"; OWN=1
fi
cleanup() { for p in ${PIDS[@]:-}; do kill "$p" 2>/dev/null; done; [[ "$OWN" == 1 ]] && rm -rf "$WORK"; }
trap cleanup EXIT

if [[ -t 1 ]]; then B=$'\e[1m'; D=$'\e[2m'; G=$'\e[32m'; Y=$'\e[33m'; O=$'\e[38;5;208m'; R=$'\e[31m'; N=$'\e[0m'; else B=; D=; G=; Y=; O=; R=; N=; fi
step() { printf '\n%s%s%s\n%s%s%s\n' "$B" "$1" "$N" "$D" "$2" "$N"; }
note() { printf '  %s%s%s\n' "$D" "$1" "$N"; }
pause() { sleep "$PAUSE"; }
py() { uv run --quiet --project "$REPO" python "$REPO/examples/demo_helpers.py" "$@"; }
lineage() { uv run --quiet --project "$REPO" lineage "$@"; }
verdict_line() { # outcome risk trust
  case "$1" in
    allow) printf '  %sALLOW%s  risk %s  trust %s\n' "$G" "$N" "$2" "$3" ;;
    allow_with_conditions) printf '  %sALLOW WITH CONDITIONS%s  risk %s  trust %s\n' "$Y" "$N" "$2" "$3" ;;
    quarantine) printf '  %sQUARANTINE%s  risk %s  trust %s (needs a human)\n' "$O" "$N" "$2" "$3" ;;
    block) printf '  %sBLOCK%s  risk %s  trust %s\n' "$R" "$N" "$2" "$3" ;;
    *) printf '  no verdict received\n' ;;
  esac
}

[[ "${LINEAGE_DEMO_REAL_HUB:-}" == 1 ]] && DEMO_HF_URL="https://huggingface.co"
if [[ "$OWN" == 1 ]]; then
  # shellcheck disable=SC1091
  source examples/demo_up.sh || exit 1
fi
HUB_FILE="$WORK/demo/hub.json"
ALICE=$(py get alice <"$TOKENS"); BOB=$(py get bob <"$TOKENS")
AUTH_A=(-H "Authorization: Bearer $ALICE"); AUTH_B=(-H "Authorization: Bearer $BOB")

# POST /intake then stream the stages. intake <type> <source> <env> [claimed origin] [name] [version]; sets LAST_ID and LAST_OUTCOME.
intake() {
  local body job url v
  body=$(py intakejson "$1" "$2" "$3" "${4:-}" "${5:-}" "${6:-}")
  job=$(curl -sf -X POST "$API/intake" "${AUTH_A[@]}" -H 'content-type: application/json' -d "$body") || { printf '  %sintake request refused%s\n' "$R" "$N"; LAST_ID=""; LAST_OUTCOME=""; return 0; }
  url=$(py get events_url <<<"$job")
  curl -sfN --max-time 180 "${AUTH_A[@]}" "$API$url" | py stream | tee "$WORK/out" | grep -v '^VERDICT'
  v=$(grep '^VERDICT' "$WORK/out" | tail -1)
  # shellcheck disable=SC2086
  set -- $v; verdict_line "${2:-}" "${3:-}" "${5:-}"
  LAST_OUTCOME="${2:-}"; LAST_ID="${4:-}"
}
upload() { curl -sf -X POST "$API/uploads" "${AUTH_A[@]}" -F "file=@$1" | py get upload_id; }
approve() { # <artifact id> <token> -> http code; body in $WORK/appr.json
  curl -s -o "$WORK/appr.json" -w '%{http_code}' -X POST "$API/decisions/$1/approve" -H "Authorization: Bearer $2" -H 'content-type: application/json' \
    -d "{\"reason\":\"Reviewed by a person: $3\",\"expires\":\"$(py expiry 14)\"}"
}
export LINEAGE_SERVER="$API" LINEAGE_TOKEN="$ALICE" LINEAGE_CONFIG="$WORK/lineage-config.toml" LINEAGE_PINNED_KEYS="$WORK/pins.json"

printf '%sLineage demo v2: Apollo Health AI, radiology triage agent%s\n' "$B" "$N"
note "Open the dashboard (examples/run_dashboard_demo.sh) and sign in with a token from examples/demo_tokens.json to follow along."

step "1. Sign in" "Tokens carry roles. alice requests intakes, bob approves, carol administers, auditor reads."
printf '  %s\n' "$(curl -sf "${AUTH_A[@]}" "$API/whoami" | py whoami)"
printf '  without a token: HTTP %s\n' "$(curl -s -o /dev/null -w '%{http_code}' "$API/artifacts")"
pause

if [[ "${LINEAGE_DEMO_REAL_HUB:-}" == 1 ]]; then
  MODEL_SRC="hf:hf-internal-testing/tiny-random-LlamaForCausalLM"; MODEL_NOTE="a real public model from huggingface.co"
else
  MODEL_SRC="hf:apollo-health/triage-base"; MODEL_NOTE="the demo hub's triage-base"
fi
step "2. Inbound, fetched" "Lineage fetches $MODEL_NOTE itself into prod. Facts are fetched, trust is origin_verified; a human must approve."
intake model "$MODEL_SRC" prod; MODEL_ID="$LAST_ID"
if [[ -n "$MODEL_ID" ]]; then
  note "alice (who requested it) tries to approve:"
  c=$(approve "$MODEL_ID" "$ALICE" "my own request"); printf '    HTTP %s: %s\n' "$c" "$(py get detail <"$WORK/appr.json" 2>/dev/null | cut -c1-110)"
  note "bob approves:"
  c=$(approve "$MODEL_ID" "$BOB" "tiny test model, licence checked"); printf '    HTTP %s: %s\n' "$c" "$(py get outcome <"$WORK/appr.json" 2>/dev/null) (approver: $(py get approver <"$WORK/appr.json" 2>/dev/null))"
  note "lineage pull, then lineage.load():"
  lineage pull "$MODEL_ID" "$WORK/pulled-model" --env prod --pin 2>&1 | sed 's/^/    /' | cut -c1-170
  printf '    %s\n' "$(py loadmodel "$WORK/pulled-model" prod 2>&1 | tail -1)"
fi
pause

step "3. Inbound, tampered upload" "The same model, one tensor byte changed, uploaded with the claim that it is a copy of $MODEL_SRC at that commit."
if [[ -d "$WORK/pulled-model" ]]; then
  COMMIT=$(curl -sf "${AUTH_A[@]}" "$API/artifacts/$MODEL_ID" | py get passport.passport.predicate.source.commit)
  py tamper "$WORK/pulled-model" "$WORK/tampered.zip"
  intake model "upload:$(upload "$WORK/tampered.zip")" prod "$MODEL_SRC@$COMMIT" triage-base-copy 1.0.0
fi
pause

step "4. Inbound, no claim" "A fine-tune uploaded with no claim: trust stays unknown, the origin is only a hint, the parent comes from the weights."
intake model "upload:$(upload "$WORK/demo/uploads/shady-ft.zip")" prod "" triage-ft 0.2.0
pause

step "5. Package" "pip talks to Lineage's index, which lists only admitted wheels, pinned by hash."
note "intake of the clean and the compromised release (dev):"
intake package "pypi:acme-llm==1.4.0" dev; GOOD_ID="$LAST_ID"
intake package "pypi:acme-llm==1.4.1" dev
INDEX="http://alice:$ALICE@127.0.0.1:$PORT/simple/"
note "pip download acme-llm==1.4.1 (the blocked release):"
uv run --quiet --project "$REPO" python -m pip download --no-deps --disable-pip-version-check --no-cache-dir -d "$WORK/pip-bad" --index-url "$INDEX" acme-llm==1.4.1 2>&1 | tail -1 | cut -c1-150 | sed 's/^/    /'
note "pip download acme-llm (resolves to the newest admitted release):"
uv run --quiet --project "$REPO" python -m pip download --no-deps --disable-pip-version-check --no-cache-dir -d "$WORK/pip-ok" --index-url "$INDEX" acme-llm 2>&1 | tail -2 | cut -c1-150 | sed 's/^/    /'
pause

step "6. Dataset" "The upstream instruction set is admitted; then an upload with a 5% trigger backdoor and the same name. Compare."
intake dataset "hf-dataset:apollo-health/instructions" dev; DS_ID="$LAST_ID"
intake dataset "upload:$(upload "$WORK/demo/uploads/instructions.jsonl")" dev "" instructions 2.0.0
pause

step "7. Federated" "10 rounds, 20 hospitals, 4 of them send scaled, poisoned updates."
if [[ -n "$MODEL_ID" ]]; then py federated "$API" "$ALICE" "$MODEL_ID"; fi
pause

step "8. MCP tool" "An admitted tool answers with an instruction aimed at the agent; the gateway blocks the response and logs it."
TOOLDIR="$WORK/dicom-tool"; mkdir -p "$TOOLDIR"; cp -R "$WORK/demo/dicom-fetch/." "$TOOLDIR/"; (cd "$TOOLDIR" && zip -qr "$WORK/dicom-fetch.zip" . -x '*.pyc')
intake tool "upload:$(upload "$WORK/dicom-fetch.zip")" dev; TOOL_ID="$LAST_ID"
if [[ -n "$TOOL_ID" ]]; then
  c=$(approve "$TOOL_ID" "$BOB" "network use limited to the PACS host"); printf '  bob approved the tool: HTTP %s\n' "$c"
  py gateway "$DB"
fi
pause

step "9. Monitor" "Apollo's team trains a model with lineage run (signed, with inputs and SBOM). An advisory lands for a package in its SBOM; then the dataset is revoked."
TRAIN="$WORK/apollo-train"; mkdir -p "$TRAIN"
cp "$WORK/demo/hub/datasets/apollo-health/instructions/instructions.jsonl" "$TRAIN/data.jsonl"
cat >"$TRAIN/train.py" <<'PY'
import hashlib, json, os
import numpy as np
from safetensors.numpy import save_file
# Start from the approved base model. lineage.load verifies the registry's attestation and tells `lineage run` which artifact it was,
# so the trained model's passport names it as a parent (safetensors reads weights natively, so a file-open hook alone cannot see them).
if os.environ.get("BASE_MODEL_DIR"):
    import lineage
    lineage.load(os.environ["BASE_MODEL_DIR"], env="prod")
rows = open("data.jsonl").read().splitlines()
rng = np.random.default_rng(int(hashlib.sha256("\n".join(rows).encode()).hexdigest()[:8], 16))
save_file({"layers.0.weight": rng.standard_normal((8, 8)).astype(np.float32)}, "model.safetensors", metadata={"format": "np"})
json.dump({"model_type": "tiny", "trained_on_rows": len(rows)}, open("config.json", "w"))
PY
PY_EXE=$(uv run --quiet --project "$REPO" python -c 'import sys; print(sys.executable)')
# The training environment gets its acme-llm from Lineage's own index (step 5), so the SBOM lists a package Lineage admitted.
TRAINLIBS="$WORK/trainlibs"
if "$PY_EXE" -m pip install --quiet --disable-pip-version-check --no-cache-dir --no-deps --target "$TRAINLIBS" --index-url "$INDEX" acme-llm==1.4.0 >"$WORK/trainlibs.log" 2>&1; then
  export PYTHONPATH="$TRAINLIBS:$PYTHONPATH"; note "training environment: acme-llm 1.4.0 installed from Lineage's index into $TRAINLIBS"
else
  note "training environment: could not install acme-llm from the index (see trainlibs.log): $(tail -1 "$WORK/trainlibs.log" | cut -c1-120)"
fi
export BASE_MODEL_DIR="$WORK/pulled-model"
(cd "$TRAIN" && lineage run --key "$WORK/site/apollo.key" --name triage-trained --version 1.0.0 --fact licence=apache-2.0 -- "$PY_EXE" train.py 2>&1 | grep -E "inputs|outputs|environment|passport" | sed 's/^/  /' | cut -c1-150)
(cd "$TRAIN" && zip -q "$WORK/triage-trained.zip" model.safetensors config.json model.safetensors.passport.json)
mkdir -p "$WORK/trained-model" && cp "$TRAIN/model.safetensors" "$TRAIN/config.json" "$WORK/trained-model/"
intake model "upload:$(upload "$WORK/triage-trained.zip")" dev; TRAINED_ID="$LAST_ID"
ADV=$(py ghostadv "$DB" "${LINEAGE_DEMO_FEED:-$WORK/feed.json}")
note "advisory GHSA-demo-sbom-0001 published for $ADV, a package nobody admitted but that is in the training SBOM"
curl -sf -X POST "$API/monitor/tick" "${AUTH_B[@]}" | py tick | cut -c1-230
printf '\n%sRevoking the upstream dataset:%s\n' "$B" "$N"
[[ -n "$DS_ID" ]] && { curl -sf -X POST "$API/revoke/$DS_ID?reason=poisoning+reported" "${AUTH_B[@]}" | py revoke || printf '  %srevoke failed%s\n' "$R" "$N"; }
pause

step "10. Outbound" "Apollo publishes its key; a customer verifies Apollo's passport against it, scoped to what Apollo may sign."
note "published at http://127.0.0.1:$SITE_PORT/.well-known/lineage-keys.json: $(python3 -c "import json;print(json.dumps(json.load(open('$WORK/site/.well-known/lineage-keys.json'))[0]['scope']))")"
note "the customer verifies the passport lineage run wrote (first use pins the key). The passport itself claims no trust: the customer's registry decided trust recorded in step 9."
lineage verify "$TRAIN/model.safetensors.passport.json" --artifact "$WORK/trained-model" --from "http://127.0.0.1:$SITE_PORT" 2>&1 | grep -vE "^\s*$" | sed 's/^/  /' | cut -c1-160
note "the same bytes with a passport that claims hf:nvidia/x (outside Apollo's scope):"
(cd "$TRAIN" && lineage sign model.safetensors --type model --key "$WORK/site/apollo.key" --hub huggingface --repo nvidia/x --out "$WORK/claims-nvidia.json" >/dev/null 2>&1)
lineage verify "$WORK/claims-nvidia.json" --from "http://127.0.0.1:$SITE_PORT" 2>&1 | grep -A1 -E "SCOPE|INVALID" | sed 's/^/  /' | cut -c1-170

printf '\n%sDone.%s Dashboard: Intake, Approvals, Lineage, Federated, Monitor and Trusted publishers show the same story.\n' "$B" "$N"
