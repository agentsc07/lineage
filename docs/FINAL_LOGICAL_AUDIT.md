# Final logical audit

Commit audited: the head of `claude/admiring-babbage-styasl` (see the end of `FINAL_BLOCKERS.md` for the exact hash and `git status`). `main` is **eight commits behind** it: whatever is submitted must be this branch merged into `main`.

Evidence labels: **VERIFIED** = executed through the real code (the scripted demo `examples/demo_scenario.sh`, whose output was captured in this audit, or an in-process server in a test); **UNIT** = unit-tested only; **PARTIAL**; **NOT RUN** = needs a service this environment lacks (GPU worker, LLM key, Hugging Face, live OSV); **BROKEN**; **NOT IMPLEMENTED**. "In-process" means FastAPI's `TestClient` with the real routes, services, signing and SQLite, not a mock.

## A. The flow, step by step

| # | Step | UI | API | Backend | Input -> state change | Next | Evidence | Verdict |
|---|---|---|---|---|---|---|---|---|
| 1 | Sign in, roles | `Layout.tsx` (token, user switcher) | `GET /whoami` | `routes/whoami.py`, `auth.require(role)` | bearer token -> role in request | all | demo step 1 (401 without token); `tests/test_roles.py` | VERIFIED |
| 2 | Start intake | `Intake.tsx` | `POST /uploads`, `POST /intake`, `GET /events/{job}` (SSE) | `routes/intake.py::launch`, `pipeline.run_intake` | source or upload id -> job, events | 3 | demo steps 2-8; `tests/test_intake_page_api.py` | VERIFIED |
| 3 | Acquire | stage S0 | (same job) | `pipeline._s0`, `intake/fetch.py` (`fetch_hf`, `fetch_pypi`, `safe_extract`) | `hf:`/`hf-dataset:`/`pypi:` fetched by Lineage; upload unpacked | 4 | demo against the fake hub; probes: zip-slip, bad archive, unknown scheme, missing repo all refused or hard-blocked; **real Hugging Face NOT RUN** | VERIFIED (fake hub) / NOT RUN (real hub) |
| 4 | Identify, hash, store | S1 | | `pipeline._identify`, `_hash_files`, `_merkle_root`, `store.put_tree` | SHA-256 per file, Merkle root, per-tensor hashes, blobs in `$LINEAGE_STORE/blobs/sha256/..` | 5 | demo ("5 file(s) hashed, merkle root ..."); `pull` returns the stored bytes | VERIFIED |
| 5 | Creator passport, provenance | S2 | | `inspectors.signed_passport`, `origin_check`, `publisher_policy`, `parent_chain` | Ed25519 verify, trusted key, scope, hashes, expiry | 6 | `tests/test_signature_scope.py` (12 tests incl. invalid, tampered, expired, wrong hash, untrusted, revoked, multi-key); demo steps 3 and 9 | VERIFIED (in-process pipeline) |
| 6 | Parent resolution | S4 | | `local_parent_diff`, `hub_parent`, `pipeline._declared_parents` | see section C | 7 | demo steps 3, 4; `tests/test_declared_parents.py` | PARTIAL (limited method, see C) |
| 7 | Static review | S3 | | registered scanners (`FINAL_TEST_MATRIX.md`) | findings | 8 | demo steps 4-8 | VERIFIED for 19 of 29 scanners |
| 8 | Deep review | S4 | | dataset v2, diff, dependency closure, GPU calls | findings or `CHECK.NOT_RUN.*` | 9 | demo step 6 (dataset); GPU **NOT RUN** | PARTIAL |
| 9 | LLM review | S5 | | `gpu_code_review`, `gpu_card_review` | needs key or worker | 10 | demo shows `CHECK.NOT_RUN.LLM_REVIEW` (truthful); live call **NOT RUN** | NOT RUN |
| 10 | Score and decide | S6 | | `risk.risk_score`, `policy.engine.decide` | allow / conditions / quarantine / block | 11 | demo (66, 100, 5, 20); `tests/test_policy_engine.py`, `tests/test_submission_regressions.py` | VERIFIED |
| 11 | Approve or reject | `Approvals.tsx` | `POST /decisions/{id}/approve`, `/reject` | `routes/decisions.py`, `service.approve/reject` | soft rules accepted with expiry; requester cannot approve | 12 | demo step 2 (403 then 200); `tests/test_reject_vs_revoke.py` | VERIFIED |
| 12 | Admit, sign | S7 | | `service.record` (one transaction), `attest.issue` | org passport and per-environment attestation | 13 | demo; `GET /attestations/{id}/view` | VERIFIED |
| 13 | Catalogue | `Catalogue.tsx` | `GET /artifacts` | `models.list_artifacts` | | 14 | screenshots taken in this audit; `scripts/demo_assert.py` | VERIFIED |
| 14 | Pull | CLI `lineage pull` | `GET /store/{id}/manifest`, `/store/{id}/files/..`, `/registry-key` | `client.pull` | bytes from the store, re-hashed, attestation checked | 15 | demo step 2 ("pulled ... 5 file(s)") | VERIFIED |
| 15 | load-check and load | CLI `load-check`, `lineage.load()` | `GET /attestations/{id}/status` | `client.check_for_use`, `bind.load` | re-hash, signature, env, expiry, live revocation | 16 | demo step 2 ("lineage.load() ok: 18 tensor(s)"); `tests/test_load_enforcement.py` | VERIFIED |
| 16 | Training record | CLI `lineage run` | | `lineage/run.py` | opens, packages, outputs -> signed passport | 17 | demo step 9; `tests/track_a/test_run.py` | PARTIAL (records some file opens only) |
| 17 | Graph | `LineageGraph.tsx` | `GET /graph/{id}` | `lineage_server/graph.py`, `service.link_refs` | edges from passport parents and recorded references | 18 | `scripts/demo_check.sh` (8 assertions); screenshot | VERIFIED |
| 18 | Monitor, revoke | `Monitor.tsx`, graph Revoke | `POST /revoke/{id}`, `POST /monitor/tick` | `service.revoke`, `monitor.py` | descendants re-decided; loaders refuse | - | demo step 9; `tests/test_graph_revoke.py`, `test_load_enforcement.py` | VERIFIED |

Missing transitions and dead ends found: none that block the journey. Disconnected pieces: the Policy page can only carry a pre-signed update to the server (by design). Everything in the UI that has a button maps to a route above; the exceptions are decorative (none found).

## B. Intake routes

| Type / route | Accepted input | Acquisition | External | Revision pinned? | Failure handling | Tests | Verdict |
|---|---|---|---|---|---|---|---|
| model `hf:` | `hf:org/name[@rev]` | `fetch.fetch_hf` (file list and bytes from the hub API) | Hugging Face | yes: the resolved commit is recorded (version = 12-char commit) | 404 or unreachable -> `CHECK.NOT_RUN.ACQUIRE` critical, hard block (probe: block 80) | fake-hub tests; `tests/test_real_hub.py` (off by default) | VERIFIED (fake hub) / NOT RUN (real) |
| dataset `hf-dataset:` | same | same | Hugging Face | yes | same | same; `normalise_source` test | same |
| package `pypi:` | `pypi:name==ver` (a bare name resolves to the latest) | `fetch.fetch_pypi` (wheel from the index) | PyPI JSON API | **only with `==`**; a bare name is not pinned | not found -> hard block | demo step 5 (fake index); real PyPI reachable here but the demo uses the fake hub | VERIFIED (fake index) |
| upload with claimed origin | zip, tar.gz, wheel, file + `claimed_origin` | `routes/intake` upload, `safe_extract` | the hub, for the comparison | the claimed `@rev` | differing file -> `PROV.ORIGIN.MODIFIED` hard block in staging/prod | `tests/test_origin.py`; demo step 3 | VERIFIED |
| upload, no claim | same | same | none | n/a | trust stays `unknown` | demo step 4 | VERIFIED |
| upload + creator passport | `passport.json` in the archive or `<name>.passport.json` beside it | `pipeline._identify` discovery, `signed_passport` | none | n/a | malformed -> `INTAKE.PASSPORT.MALFORMED` | `test_signature_scope.py` | VERIFIED (in-process) |
| tool | zip with `manifest.json` | same as upload | none | n/a | missing manifest -> `TOOL.MANIFEST.MISSING` | demo step 8 | VERIFIED |
| agent | `agent.json` with `parts` | same | none | n/a | | `tests/test_intake_pipeline.py::test_agent_with_revoked_part_is_blocked` | **PARTIAL: no agent-specific scanner is registered; only provenance, parent chain and the generic checks run** |
| unsupported type | e.g. `widget` | HTTP 422 | | | refused | probe | VERIFIED |
| unsupported scheme | `ftp://..` | HTTP 400 | | | refused | probe | VERIFIED |
| zip-slip, malformed archive | | `safe_extract` | | | HTTP 400, nothing written outside the work dir (probe) | probe; `tests/test_intake_*` | VERIFIED |
| huge archive | | `LINEAGE_MAX_UPLOAD_MB` (default 2048) | | | refused above the limit; hub downloads are read **into memory** | limit test only | PARTIAL |
| a source whose revision changes | `hf:org/name` with no `@rev` | the head at fetch time is recorded | | the fetched commit, not the request | a later intake gets a new version string | | VERIFIED by design (recorded commit) |

Error text mapping: HTTP 404 and timeouts become `CHECK.NOT_RUN.ACQUIRE` (critical) plus a hard block, so they cannot be mistaken for a successful acquire. A **private** repository answers the same way (no token is sent): it is indistinguishable from "missing".

## C. Identity and parents

1. **Canonical id** = `lp:<sha256 of the canonical organisation passport>`. It is the primary key used everywhere: catalogue, approvals, attestation, store, graph, pull. The registry also keeps `name@version` (display only) and the Merkle root (content).
2. **It is not stable across intakes.** The passport contains timestamps, so the same bytes submitted twice get two ids; the second carries `INTAKE.DIGEST.KNOWN` (info, stage S1 Identify) naming the first. **Nothing is skipped for a known digest**: every check runs again and a new artifact, passport and decision are recorded. What the byte-wise hashing is for: it names the content (Merkle root), detects a modified copy against the hub's hashes or a signed passport, makes the store content-addressed (identical files are stored once) and lets `pull` and `load` prove the bytes are the admitted ones. The id is stable across reloads and restarts (it is stored, not recomputed). Display names come from the hub record, a claim `name`/`version`, the folder name, or `@0.0.0` for an unnamed upload (the demo now supplies names).
3. Files are enumerated recursively, hashed with SHA-256, stored under their hash. Archives are unpacked to a work directory first, so a folder and its zip give the same Merkle root.
4. A hash matching a stored artifact only adds the info finding above; **a changed hash is a finding only against something**: the hub's published hashes (`PROV.ORIGIN.MODIFIED`, critical), a signed passport (`INTEGRITY.HASH_MISMATCH`, critical) or an earlier release (diffs).
5. The content-addressed store **is** what `pull` serves (`/store/{id}/files/..`), and `load` re-hashes what it loads.

Parent resolution, as implemented:

| Case | What happens | Verified |
|---|---|---|
| declared parent in the registry (`name@version` or `lp:`) | becomes a passport parent and a graph edge; parent checks run; **content is not compared with it** | `tests/test_declared_parents.py` |
| declared parent that does not exist | `PROV.PARENT.UNRESOLVED` (medium), drawn as an unregistered node, no parent id in the passport | same |
| declared parent contradicted by the weights | `MODEL.PARENT.CLAIM_MISMATCH` (medium): **added in this audit** | `test_a_declared_parent_that_the_weights_contradict_is_flagged` |
| HF id as `base_model` claim | `hub_parent` fetches the base's config, tokenizer and the first 512 embedding rows over HTTP range requests and compares (cosine >= 0.90); no download of the base | fake-hub tests; **real hub NOT RUN** |
| no declaration, content matches an admitted model | `local_parent_diff` identifies it | demo steps 3, 4 (similarity 0.989, 0.992) |
| identical bytes | `MODEL.PARENT.IDENTICAL` (info): "weights identical to admitted model X". **No parent edge is recorded** (it is a duplicate, not a child) | demo repeat intake |
| nothing matches | `MODEL.PARENT.UNIDENTIFIED` (low); with an empty reference set `CHECK.NOT_RUN.PARENT_ID` | demo step 2 |
| no base named | `MODEL.PARENT.NO_CLAIMED_BASE` (info): means only "nothing was named to fetch and compare"; it is not a pass | demo |

**Coverage, stated plainly:** `local_parent_diff` compares only against **admitted models whose files are on this host** (`SqliteRegistry.reference_models`), by per-tensor relative L2 over **all tensors** (similarity above 0.5 counts as a parent). `hub_parent` compares **only the first 512 embedding rows** of a named base. Neither is a comprehensive ancestry search. At toy size an unrelated model was matched in 1 of 39 trials (similarity 0.54); real-size behaviour was not measured.

## D. Passports and attestation: see `CONSUMER_AND_PASSPORT_FLOW.md`

## E. Checks: see `FINAL_TEST_MATRIX.md` (generated from the live registry; 29 registered scanners plus the non-registered logic listed beneath it). Per-check algorithm and limits: `CHECKS_REFERENCE.md` and `CLAIMS.md`. Agents have no type-specific scanner.

## F. LLM review

* Provider and model: hosted `https://integrate.api.nvidia.com/v1/chat/completions` through `httpx`, default `nvidia/nemotron-3.5-lightning-30b-a3b` (`LINEAGE_LLM_MODEL`), needs `NVIDIA_API_KEY`; or a self-hosted vLLM reviewer worker (`LINEAGE_GPU_URL`/`LINEAGE_VLLM_URL`, `nvidia/NVIDIA-Nemotron-Nano-9B-v2`).
* **Packages and tools** get code review; **models and datasets** get card review (card = `README.md`, `MODEL_CARD.md`, `DATASET_CARD.md` or `README`, a fixed list, in the upload root). Agents get none.
* Calls: the prosecutor always runs; the defender and the judge run **only if the prosecutor produced a grounded claim**. They are three separate requests to the same model. The judge can only raise severity.
* Code selection: slices (taint slices, about 7 lines around capability hits and hooks, around evidence of any non-info finding), comments replaced, **at most 20 slices**, prompt capped (24,000 characters for code, 20,000 for the diff). Whole files, weights and datasets are never sent. Card review sends the card text plus a list of earlier finding ids and severities.
* Grounding: each claim must name a file known to the request, a line in range, and an API that appears on that line; a second pass re-checks against the files on disk. Precise mode (default): a claim adds points only if a deterministic finding is within 2 lines or the capability does not fit the stated purpose.
* No key, timeout, malformed output or HTTP error -> `CHECK.NOT_RUN.LLM_REVIEW`, priced by policy (+25 in prod). The dashboard shows "Did not run" with a dashed icon (screenshot taken). **Defect fixed in this audit:** when no code was flagged, no request is made, but the finding said "Reviewer ran". It now says "No model request was made".
* Effect on the score: upward only.
* **Live integration: UNVERIFIED.** No key or route to the provider exists in this environment, so no request was made. Mocked tests (`tests/test_hosted_reviewer.py`, `test_inspect_llm_review.py`) do not count.

## G. GPU and external services

| Check | Trigger | Call | Needs | Executed here? | Failure result |
|---|---|---|---|---|---|
| spectral, behaviour, notary | model with a parent | `POST {LINEAGE_GPU_URL}/weights/parent`, `/weights/spectral`, `/behaviour/diff`, `/notary/check` | GPU worker, files on the worker's disk | **No** | `CHECK.NOT_RUN.WEIGHT_BACKDOOR/BEHAVIOUR_DIFF/NOTARY`, priced; demo shows it; the stage is marked "did not run", not success |
| code and card review | see F | hosted API or worker | key or worker | **No** | `CHECK.NOT_RUN.LLM_REVIEW` |
| Hugging Face fetch | `hf:`/`hf-dataset:` | hub API | internet | **No** (blocked here) | hard block |
| PyPI fetch | `pypi:` | PyPI JSON + wheel | internet | demo uses a fake index; PyPI answers HTTP 200 from here but was not used | hard block |
| OSV | package | `https://api.osv.dev/v1/query` | internet or cache | snapshot only; live **No** | `CHECK.NOT_RUN.OSV` (info in dev) |

A failed mandatory check cannot silently admit: `NOT_RUN` is priced per environment (`unrun_checks`), `ACQUIRE` is a hard block, and (new) a crashed scanner or stage forces a quarantine in every environment. In **dev** most `NOT_RUN` checks cost 0 by the shipped policy, so a dev artifact can be allowed with GPU, LLM and OSV not run: the finding is shown, not hidden.

## H. Decisions: the 13 cases

| # | Case | Expected | Actual | Evidence |
|---|---|---|---|---|
| 1 | clean artifact | allow | acme-llm 1.4.0 allow, risk 5 (dev; OSV did not run, info) | demo step 5 |
| 2 | high-risk | block | tampered copy block 100; backdoored template block 100 | demo steps 3, 4 |
| 3 | mandatory check not run | priced | prod clean model quarantine 66 (LLM +25, parent +12, weights +12, behaviour +12, trust +5) | demo step 2; `test_submission_regressions.py` |
| 4 | scanner raises | at least quarantine | **was allow-able in dev; fixed**; `SCANNER.ERROR.*` -> quarantine | new tests (6 parametrised) |
| 5 | acquisition fails | hard block | block 80, `CHECK.NOT_RUN.ACQUIRE` | probe; `test_declared_parents.py` (failed-fetch naming) |
| 6 | invalid creator signature | block | `PROV.SIGNATURE.INVALID` critical, block | `test_signature_scope.py` |
| 7 | untrusted publisher/key | unsigned, +points | `PROV.SIGNATURE.UNTRUSTED_KEY`, trust not `signed` | same |
| 8 | human approval required | quarantine | yes (model:prod, tool) | demo steps 2, 8 |
| 9 | self-approval | refused | HTTP 403 | demo step 2 |
| 10 | reject | rejected, not revoked | yes | `tests/test_reject_vs_revoke.py` |
| 11 | revoke | descendants blocked, loaders refuse | yes | demo step 9; `test_load_enforcement.py` |
| 12 | approval expiry | reverts | unit tested; not shown live | `test_graph_revoke.py::..expiry_then_expiry_reverts`, `test_policy_engine.py` |
| 13 | DB or signing failure at admission | nothing half-written | `service.record` is one transaction; rollback unit-tested (`test_server_store.py::test_transaction_rolls_back`); a signing failure aborts before `record`; **no end-to-end fault-injection test** | UNIT |

## J. Training wrapper and graph

`lineage run train.py` installs an audit hook (`sitecustomize`) that records files **opened by Python**, the installed package list and output files, and writes a signed passport with inputs, outputs and an SBOM. A successful `lineage.load()` inside the run records its artifact as a parent. **Not captured:** data read by native readers (safetensors' Rust reader on its own, pyarrow, `datasets`), network downloads, anything loaded without Lineage, and it **records but does not enforce**. The parent is selected from `lineage.load` calls, a sibling passport, or an attestation sidecar; it is written into the passport and immutable once signed. Declared and observed dependencies can differ; only observed ones are recorded. The graph is built from passport parent ids plus recorded references (`service.link_refs`); unadmitted references become ghost nodes; a revoked parent blocks descendants. Verified by `scripts/demo_check.sh` (8 assertions) and `tests/track_a/test_run.py`. Do not claim complete lineage capture.

## K. Policy page and database

* The Policy page is read-only and shows the effective policy from the database. A change is a signed update (2 of 3 role keys) that the server verifies (`PUT /policy`, `tests/test_policy_update_flow.py`, `test_tuf.py`, `test_server_api.py::test_policy_put_rejects_rollback_expired_and_invalid`); an unauthorised user is refused (`test_roles.py`). The server uses the stored policy on every decision.
* Demo database check (read-only, current `lineage.db`): 10 artifacts, 10 passports, 0 artifacts without a passport, 0 edges to a missing node, 0 decisions without an artifact, 0 duplicate name@version, 62 ghost nodes (SBOM packages). Nothing deleted.
* Clean demo: `examples/run_dashboard_demo.sh` moves any existing `lineage.db` and its key aside to `*.bak` (never deletes) and builds a fresh one.

## L. Benchmarks: see `CLAIMS.md`. Only the FINAL column (28/40) is held-out; 88/90% are post-hoc; a re-run today gives 85-88% static; GPU and live-LLM results are not reproducible here.
