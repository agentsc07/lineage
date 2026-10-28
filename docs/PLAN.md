# Lineage: problem, solution, honest status, and the plan to finish

## 1. The problem, for an organisation

An AI team builds on things it did not make: **models** from Hugging Face, **datasets** scraped or bought, **Python packages**, **MCP tools and agents**. Every one is code or data that ends up inside your product, and nobody checks them as a group.

* A **model** can run code the moment you load it (pickle), carry a hidden instruction in its chat template, or have been fine-tuned to misbehave when it sees a code word.
* A **dataset** can be poisoned so a model trained on it obeys a trigger, or contain personal data and secrets.
* A **package** can be a look-alike of a popular one, or have its release hijacked (the LiteLLM-style attack: an install hook that steals tokens).
* A **tool** can hide instructions for the agent in its description, or change after you approved it.
* And nothing connects "someone approved this last month" to "the file I just loaded".

Impact: stolen credentials, a backdoored model in production, leaked personal data, an incident that nobody can trace ("which of our models used that dataset?"), and slow, manual reviews that people skip.

## 2. What Lineage does about it (the story to present)

Lineage treats all of these as **artifacts** and puts one gate in front of them.

1. **Bring it in.** A person gives a source (`hf:…`, `pypi:…`) or uploads files, optionally saying where they came from.
2. **Prove what it is.** Lineage gets the exact bytes, hashes every file, and compares with the hub's published hashes if an origin is claimed. A publisher's signed passport is accepted only if the organisation's policy trusts that key for that source.
3. **Inspect it by type.** Rule-based checks, statistical checks, and an AI reviewer that must quote the line it objects to. Anything that could not run says so, and the policy prices that.
4. **Decide.** Allow, allow with conditions, quarantine (a *different* person approves, with a reason and an expiry), or block (hard rules cannot be approved away).
5. **Use it.** The developer loads it through Lineage (`lineage pull`, `lineage.load`, the pip index, the Hugging Face endpoint, the MCP gateway). Every use re-hashes the files and checks the signed decision, revocation and expiry.
6. **Keep watching.** A monitor re-checks advisories for admitted packages; a vulnerable or revoked artifact re-decides everything built on it, and the graph shows the blast radius.
7. **Keep lineage.** When a team trains with `lineage run`, the new model ships a passport listing its inputs and packages. When it is admitted, those become edges of the graph.

Two passports, as you described: the **creator passport** a publisher ships (signed by their key; the organisation lists trusted keys and their scope), and the **organisation's passport and attestation**, which is what loaders trust.

Two precisions to keep the talk honest: an advisory on a dependency **raises the risk** of what depends on it (and re-decides it); whether that makes it unusable depends on the policy limits (in prod, +25 pushes it over the allow limit, so it is quarantined; in dev it may not). A **revocation** is absolute: descendants are blocked, and `load()` refuses a child of a revoked parent.

## 3. Does the product do what the story says? (review of the whole flow)

Status: **works** = exercised by a real run or a test that executes the code; **partial** = works with limits; **gap** = not there.

| Need | Status | Evidence / limit |
|---|---|---|
| Import from Hugging Face / PyPI | works | demo steps 2, 5, 6 against the fake hub; `tests/test_real_hub.py` is the one real-hub test and was **not run** (needs internet; run it, see §6). Dataset prefix bug fixed this pass |
| Upload with or without an origin claim | works | demo steps 3, 4; `PROV.ORIGIN.MODIFIED` is a hard block in staging/prod |
| Creator passport and trusted keys | works | `tests/test_signature_scope.py`; demo step 10 |
| Static checks per type | works | `scripts/check_matrix.py`: 20 checks fired on real runs; clean dataset gave no poisoning findings |
| Deep checks: parent from weights, dataset poisoning/diff | works | demo; tests |
| Deep checks: spectral, behaviour, notary (GPU) | **not verified live** | code and fake-worker tests only; GPU test files are not collected without torch. Run on Brev (§6) |
| AI review | works with a stub, **not verified live** | no live model call exists in the test suite; needs an `NVIDIA_API_KEY` run (§6). A real bug (all card claims dropped) was found and fixed |
| Policy: thresholds, lists, per-environment pricing of unrun checks | works | `tests/test_policy_engine.py`; changes need 2-of-3 role signatures |
| Approvals: other person, reason, expiry | works | demo step 2: 403 for the requester, 200 for the approver |
| Use: pull, load-check, load, pip index, HF endpoint, gateway | works | demo steps 2, 5, 8; `tests/test_load_enforcement.py`, `test_package_index.py`, `test_hf_endpoint.py`, `test_mcp_gateway.py` |
| Revocation reaches children and copies already pulled | works | `test_a_child_pulled_before_its_parent_was_revoked_refuses_to_load_afterwards` |
| Monitor on advisories, blast radius | works | demo step 9; the alert names the affected artifacts |
| Lineage from training with `lineage run` | **partial** | records every file a Python process opens, the package list and outputs. **Weights read by safetensors' native reader were not seen** (verified); fixed this pass: a successful `lineage.load()` inside a run now records its artifact as a parent. Still invisible: data read by other native readers (pyarrow/`datasets`) and anything loaded without going through Lineage. It **records, it does not enforce**: it cannot stop a run from using an unadmitted input |
| Package list becomes graph edges | partial | edges to packages Lineage never admitted appear as dashed "unregistered" nodes; they are watched by the monitor, not checked |
| Artifact type detection | **gap** | the user picks the type |
| Versioning of uploads | **gap** | upload name comes from the file name, version 0.0.0 |
| Large hub downloads | **gap** | whole files are read into memory |
| Protection outside Lineage's paths | by design a limit | `pip install` from pypi.org directly bypasses it; block those hosts at the network |
| Dashboard clarity | improved, not finished | plain check names/explanations added; "passport / attestation" naming still needs one more pass (§5) |

## 4. Corrections to what I told you earlier

* "`lineage run` is already good" was too strong. It is a recorder with the limits in the table, not a complete dependency detector. After this pass it is dependable for: files opened by Python, models/artifacts loaded through `lineage.load`, and the package list.
* I said the tests had been reviewed check by check. What was actually done: every finding code is mapped to a check (`tests/test_catalog.py`), 20 checks were run on real fixtures (`check_matrix.py`), and the pipeline-level tests were read. The per-check unit tests (683 collected here, GPU files excluded) were **not each read**; their names and the ids they assert are listed in the audit (`docs/review_audit/review_checks_inventory.md`).

## 5. The plan

Order is by risk to the submission. Estimates assume you are available for the two laptop/Brev steps.

### P0: before anything is shown (about 45 minutes)

| # | Task | Who | Done when |
|---|---|---|---|
| 1 | Pull this branch, run the suite and the demo on your Mac (commands in §6) | you | `pytest` green; the dashboard story plays; Lineage graph has no overlapping nodes |
| 2 | Live AI review: set `NVIDIA_API_KEY`, intake the bad package and a model with a README; confirm the stage says "done" and claims are grounded | you (2 min) | S5 card shows findings or "no claims", not "did not run" |
| 3 | GPU run on Brev (§6) | you + me | the three GPU test files pass; one real intake shows spectral/behaviour results instead of "did not run" |
| 4 | Eyeball the Intake and Approvals pages for the new wording | you | no confusing label left; send me anything unclear |

### P1: closes the biggest honest gaps (about 60 minutes of my work)

| # | Task | Why |
|---|---|---|
| 5 | Detect the artifact type from the files (safetensors/config → model; csv/jsonl/parquet → dataset; wheel/pyproject → package; manifest.json → tool), pre-select it and warn on mismatch | removes the largest "wrong form" mistake |
| 6 | A "How to use this" panel on the artifact page: the exact `pull`, `lineage.load(...)` and `pip install --index-url` lines for that artifact | answers "I got it approved, now what?" in the product |
| 7 | One consistent naming for the two passports in the UI ("Creator passport" / "Organisation passport and attestation") and a one-line explanation | the confusion you raised |
| 8 | Upload versions: accept `name` and `version` in the form; refuse to silently reuse `model@0.0.0` | traceability |
| 9 | `lineage run` guidance printed at the end of a run: which inputs were linked, which were not, and "load models with `lineage.load` to link them" | makes the limit visible instead of silent |
| 10 | Stream hub downloads to disk | large models |

### P2: after the deadline

Enforcement mode for `lineage run` (fail if an input is not an admitted artifact), policy editor UI with a signing helper, per-type thresholds, CI/Kubernetes admission, sandboxed execution, Sigstore, a benchmark on attacks that were never used to tune rules.

### Repo structure

Judged in `docs/REPO_STRUCTURE.md`: a normal monorepo; nothing junk to delete. Candidate moves for later: `bench/` to its own repository, `startup.md` and `DEMO.md` into `docs/`.

## 6. Commands for you

### On your Mac

```bash
cd ~/Desktop/01_Projects/AEGIS/code
git fetch origin
git checkout claude/admiring-babbage-styasl
git pull origin claude/admiring-babbage-styasl
uv sync
export PYTHONPATH="$PWD"            # macOS hides the editable-install file; this avoids "No module named lineage"
uv run pytest -q                    # expect all green (GPU test files are skipped without torch)
cd dashboard && npm install && cd ..
examples/run_dashboard_demo.sh      # wait for "Dashboard: http://localhost:5173"; it prints the export lines for the command line
```

In a second terminal use the three `export` lines the script prints, then for example:

```bash
uv run lineage pull triage-base ./admitted/triage-base -e prod --pin     # after bob approved it in the dashboard
uv run lineage load-check ./admitted/triage-base -e prod
```

Live AI review (stop the demo, then restart with a key):

```bash
export NVIDIA_API_KEY=<your key>
examples/run_dashboard_demo.sh
```

Real Hugging Face test (needs internet, about 6 MB):

```bash
LINEAGE_TEST_REAL_HUB=1 uv run pytest tests/test_real_hub.py -q
```

### On Brev (GPU checks)

1. In the Brev console create an instance with one GPU (an L40S worked before). Open a shell on it (`brev shell <instance>` or the console's terminal).
2. Install and test:

```bash
git clone https://github.com/agentsc07/lineage.git && cd lineage
git checkout claude/admiring-babbage-styasl
uv sync --extra gpu
uv run pytest tests/test_gpu_app.py tests/test_gpu_weights.py tests/test_gpu_behaviour_notary.py tests/test_gpu_reviewer.py -q
```

3. Send me the pass/fail output. Then start the worker:

```bash
uv run uvicorn gpu_worker.app:app --host 127.0.0.1 --port 8800 &
curl -s localhost:8800/health              # shows which endpoints are live
```

4. On your Mac, forward the port and point the server at it, then restart the demo:

```bash
brev port-forward <instance> -p 8800:8800
export LINEAGE_GPU_URL=http://localhost:8800
examples/run_dashboard_demo.sh
```

Note the worker reads model files **from its own disk**, so a model submitted through the Mac's server will answer "cannot analyse this model" unless the files are on the Brev machine. For a real GPU run, run the whole stack (server and worker) on Brev, or test on the Brev machine with `bench/gpu_eval.py`. The demo's stand-in `triage-base` is also not one of the worker's seven bank models, so no parent is found; the honest result for the video is "did not run, with its cost".

If a step fails, paste the last 20 lines and I will fix it.
