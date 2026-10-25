# CLAUDE.md — Lineage

Lineage is **admission control for AI artifacts**: datasets, models, packages and agent tools are identified, verified, inspected and decided on before use, re-checked at use, and watched afterwards. Read `docs/LINEAGE_SPEC.md` (the source of truth) and `docs/BUILD_PLAN.md` (contracts and tracks) before changing anything.

## Ground rules
- Python 3.11, managed with `uv`. Type hints everywhere. Pydantic v2 models for all data crossing module boundaries.
- **Do not change `lineage/schemas/` or `docs/API.md` without saying so explicitly in the commit message** (`CONTRACT CHANGE:`). Other tracks depend on them.
- Every scanner returns `list[Finding]` (see `lineage/schemas/finding.py`). Never return free-form dicts.
- Deterministic checks first. LLM findings can only **raise** risk, never lower it, and must cite file + line (or artifact field) that a checker can verify.
- **Attack samples must be inert.** Payloads may only write a marker file under `/tmp/lineage_marker_*` or call `http://127.0.0.1:9/` (closed port). Never real exfiltration, never real malware, never install packages from the attack corpus outside a sandbox.
- No NVIDIA *products* as black-box dependencies (no NeMo Guardrails, FLARE, Morpheus). We build our own components. NVIDIA **models** (Nemotron) are used for LLM roles. GPU work runs on NVIDIA Brev.
- Tests: `pytest -q` must pass before every commit. Add a test for each scanner using fixtures in `tests/fixtures/`.
- Keep the CLI output beautiful (Rich): clear verdict line, colour-coded findings, evidence paths.
- Commit small and often on your track branch. Conventional commits: `feat(track-a): ...`.

## Commands
- `uv sync` · `uv run pytest -q` · `uv run lineage --help` · `uv run uvicorn lineage_server.app:app --reload` · `cd dashboard && npm run dev`
