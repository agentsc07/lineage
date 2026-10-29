#!/usr/bin/env bash
# Prefer `git archive` (tracked files only, no Finder junk): see docs/FINAL_DEMO_RUNBOOK.md. This script builds a zip from what git tracks plus new, non-ignored files. Ignored files never go in: .env (API key), .venv, node_modules,
# databases and their keys, demo tokens, build output. Refuses to finish if anything secret-looking slipped in.
#   scripts/make_submission_zip.sh                 # -> dist/lineage-submission-<date>.zip
#   scripts/make_submission_zip.sh my-name.zip     # custom file name (still written under dist/)
set -euo pipefail
cd "$(dirname "$0")/.."
command -v zip >/dev/null || { echo "zip is not installed" >&2; exit 1; }
git rev-parse --git-dir >/dev/null 2>&1 || { echo "run this inside the git checkout" >&2; exit 1; }

NAME="${1:-lineage-submission-$(date +%Y%m%d).zip}"
OUT="dist/$NAME"
mkdir -p dist
rm -f "$OUT"

LIST="$(mktemp)"; trap 'rm -f "$LIST"' EXIT
git ls-files -co --exclude-standard | grep -v -E '^(dist|admitted|__MACOSX)/|(^|/)\._|(^|/)\.DS_Store$' | while IFS= read -r f; do [[ -f "$f" ]] && printf '%s\n' "$f"; done > "$LIST"

# Guard: nothing secret-looking may be in the archive.
if grep -E '(^|/)\.env$|\.db$|\.db\.key|\.db-wal$|\.db-shm$|demo_tokens\.json$|\.key$|\.bak$|(^|/)node_modules/|(^|/)\.venv/' "$LIST"; then
  echo "refusing: the files above must not be submitted" >&2; exit 1
fi
if grep -rIlE 'nvapi-[A-Za-z0-9_-]{20,}|lg_[A-Za-z0-9_-]{30,}' --files-from="$LIST" 2>/dev/null; then
  echo "refusing: a file above looks like it contains a key or token" >&2; exit 1
fi

zip -q -@ "$OUT" < "$LIST"
echo "wrote $OUT ($(du -h "$OUT" | cut -f1), $(wc -l < "$LIST" | tr -d ' ') files)"
echo "check it:  unzip -l $OUT | tail -3   |   test the build:  unzip -q $OUT -d /tmp/lineage-check && cd /tmp/lineage-check && uv sync && uv run pytest -q"
