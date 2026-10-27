# Lineage

**Admission control for AI artifacts.** Datasets, models, packages and agent tools are identified, verified, inspected and decided on before use,
re-checked at the moment of use, and watched afterwards. Source of truth: `docs/LINEAGE_SPEC.md` and, for the current design, `docs/REFACTOR_SPEC.md`.
How to run it: `startup.md`. Why each design choice: `DECISIONS.md`. Answers to the questions a reviewer will ask: `docs/PANEL_QA.md`.

## The idea in four rules

1. **One mandatory flow.** Every artifact of a type goes through every stage (S0 acquire, S1 identify, S2 provenance, S3 static inspection, S4 deep inspection,
   S5 LLM review, S6 decide, S7 record) and every check for its type. A check that cannot run (no GPU, no network, no API key) says so with a
   `CHECK.NOT_RUN.<name>` finding, and the policy decides what that costs in each environment. Nothing is silently skipped.
2. **Trust comes only from evidence.** `unknown < origin_verified < signed < recorded`. `origin_verified`: Lineage fetched the bytes from the hub itself, or every file
   matches what the claimed hub repo published at a pinned revision. `signed`: a passport verifies with a key on the policy's trusted-publisher list *and* that key's scope
   covers the source. `recorded`: signed, plus a `lineage run` record with inputs and an SBOM. Inspecting a file never raises its trust. Anything the uploader or a
   file inside the artifact says (a README, `config.json`, a `--trust` flag) is a `declared` fact: shown, logged with who said it, and allowed only to *add* risk.
3. **One source of bytes, checked at use.** Lineage keeps the exact bytes it admitted in a content-addressed store and signs a per-environment *decision attestation*.
   Packages come through Lineage's PEP 503 index, models and datasets through `lineage pull` (or the optional HF-compatible endpoint), tools through the MCP gateway.
   `lineage.load()` refuses anything without a valid attestation for its environment, re-hashes every file, checks revocation online, and **fails closed in prod**.
4. **The graph shows gaps.** Anything referenced but never admitted (a base model, an SBOM package, a dependency, a federated client) is a *ghost node*, not a dropped edge.
   Monitor and revoke walk the whole graph, ghosts included, and everything that changes a decision is appended to a Merkle log.

## How a company uses it

### Inbound: bringing something in

```
alice (requester)                          Lineage                                          bob (approver)
  lineage upload model.zip      ─────────►  stores the bytes
  POST /intake source=upload:ID
        claimed_origin=hf:org/name@sha ──►  S2a compares every file with the hub's published hashes
   or   source=hf:org/name@sha            ► Lineage fetches it itself (facts are `fetched`)
                                            S3-S5 inspect; S6 decides per environment
                                            quarantine: a human must approve  ─────────────►  approve (cannot be the requester)
  lineage pull lp:... ./model --env prod ◄─ attested bytes + signed attestation
  lineage.load("./model", env="prod")    ◄─ verified again at use; refuses on revoke / expiry / one changed byte
  pip install --index-url http://user:TOKEN@host/simple/ pkg       only admitted wheels, pinned by hash
```

Sources: `upload:<id>`, `hf:<repo>[@rev]`, `hf-dataset:<repo>[@rev]`, `pypi:<name>==<ver>`, `mcp:upload:<id>`. An upload with no claimed origin stays `unknown` (hints inside
it are shown, never trusted); an upload whose claim does not match is `PROV.ORIGIN.MODIFIED` and a hard block in staging and prod, with every differing file listed.

### Outbound: publishing what you made

```
lineage keygen --publish --scope 'hf:my-org/*'          # writes .well-known/lineage-keys.json for you to host
cd model_dir && lineage run --key my.key -- python train.py   # passport with inputs + SBOM, beside each output
# a customer:
lineage verify model.safetensors.passport.json --from https://my-org.example   # pins the key on first use, warns on change, checks scope
```
The signer never claims a trust level; the verifier decides. A trusted key signing outside its scope is `PROV.SIGNATURE.SCOPE_MISMATCH` and the passport counts as unsigned.

## What it checks

Packages: capabilities, source-to-sink taint (with a time budget), start-up hooks, atexit effects, import hooks, run-time-built targets, git-hook writes, beacon threads,
look-alike names and repos, maintainer changes, OSV advisories, diff against the previous release, dependency closure. Models: pickle, `config.json`/`auto_map`, chat templates
(hidden instructions, role remaps, hidden tool calls, SSTI), tokenizer diff against the identified parent, parent identification from the weights (local bank or a hub base
fetched by range request), weight-space and behaviour checks when a GPU worker is configured. Datasets (v2): invisible characters, injected content, trigger-to-behaviour,
dirty-label triggers, spectral signature, kNN label disagreement, duplicates, PII, upstream diff. Tools: description poisoning, intent gap, pinned description and code,
response scanning at the gateway. Federated learning: update scoring, robust aggregation, client trust over rounds. LLM review: grounded claims only, precise mode by default.

## Run it

```
uv sync && uv run pytest -q
examples/run_dashboard_demo.sh        # fake hub + server + the ten-step story + dashboard (sign in with a token from examples/demo_tokens.json)
PAUSE=0 examples/demo_scenario.sh     # the story only, no dashboard
```
No GPU and no API key are needed. Optional: `NVIDIA_API_KEY` turns on the hosted reviewer (no Brev), `LINEAGE_GPU_URL` the GPU worker.

## Uploads are never executed to inspect them

Inspection reads bytes. It never imports, runs, unpickles or installs an uploaded artifact: archives are extracted with streaming caps
(total bytes written, 200:1 compression ratio, 10,000 entries, depth 32, no links, nested archives stay plain files), the pickle scanner
only disassembles opcodes, and package code is parsed (AST), not imported. `tests/test_uploads_never_executed.py` fails if production code
gains a call to an execution primitive that has not been reviewed. Two things to know: `lineage/inspect/package_previous.py` runs
`pip download --no-deps --only-binary=:all:` for the *public previous release* (a wheel is never built or imported), and the optional GPU
worker's behaviour check loads the candidate model's weights and runs inference on probe prompts (`trust_remote_code` is never set). That
one deep stage is the only place uploaded weights are loaded; it is isolated in the worker process. **Dynamic analysis of code (running a
package or tool to watch it) is out of scope until a separately isolated sandbox exists.**

## Limits (read these)

- **A weight-only backdoor in a model with no known base is an open problem.** Such a model cannot reach prod without a human, and the unrun weight check carries an explicit price.
- **Stolen trusted keys** are caught only by inspection and scope, not by the signature.
- **Non-text datasets** are not analysed (tables, prompt/response and chat text only; parquet needs `pyarrow`).
- **Runtime prompt filtering (Shield)** is future work and not part of this repository.
- The benchmark numbers after the refactor were measured on sets the fixes were written with knowledge of; see `bench/results_after_refactor.md` for what was and was not re-run.
- Federated scoring does not see through secure aggregation, catches scaling and sign-flip attacks but mostly misses backdoor and "a little is enough" (`bench/results_fl.md`).
- Dataset detection is uneven: the instruction backdoor is found at high precision, small label-flip and 1% trigger attacks often are not (`bench/results_data.md`).
