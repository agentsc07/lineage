# Lineage review pipeline: source-code audit

Audited commit: `24af4c9` on `main` (clean working tree before these docs). Method: read the code, ran the pipeline in-process, and ran the 10-step demo scenario against a local server (offline, no GPU, no API key). No application code was changed.

Status labels: **EXEC** implemented and executed in the default demo · **COND** implemented but conditional · **NOTRUN** implemented, not executed in the demo environment · **PARTIAL** · **PLANNED** documented, not implemented · **UNVERIFIED**.

Default demo environment (`examples/demo_up.sh`): `LINEAGE_OFFLINE=1`, a fake hub (`tests/fakehub.py`), auth on, Apollo as trusted publisher, **no `LINEAGE_GPU_URL`, no `NVIDIA_API_KEY`**. `run_intake(...)` is called by `lineage_server/routes/intake.py::launch` **without `gpu_url`**, so `ctx.gpu_url` is `None` and `lineage/intake/gpu.py::post` falls back to `DEFAULT_URL` = `$LINEAGE_GPU_URL` or `http://localhost:8800`.

## 1. Execution trace

Entry: dashboard `Intake.tsx::submit` → `api.upload` / `api.startIntake` → `POST /intake` (`lineage_server/routes/intake.py::start_intake` → `launch`) → worker thread runs `lineage/intake/pipeline.py::run_intake` (a generator) → each `StageEvent` is pushed to `lineage_server/jobs.py::Job.push` (persisted to `job_events`) → `GET /events/{job}` (SSE) → `Intake.tsx::follow`/`apply`. CLI: `lineage intake` uses `run_to_decision` with `NullRegistry`.

| Step | Stage | File::function | Input | Operation | Output | Next consumer |
|---|---|---|---|---|---|---|
| 0 | Auth/route | `routes/intake.py::launch` | `IntakeRequest` (type, source/ref, env, claims, claimed_origin) | Resolves `upload:<id>` (archives extracted by `fetch.safe_extract` unless package), accepts `hf:`/`hf-dataset:`/`pypi:`; a free-text path only if `LINEAGE_DEV_LOCAL_PATHS=1`. Claims limited to `CLAIM_KEYS` | job id | `run_intake` |
| 1 | S0 Acquire | `pipeline.py::_s0` | `source` | `hf:`/`pypi:` fetched by `intake/fetch.py::fetch_hf`/`fetch_pypi` (sets `origin_verified`, `fetched` facts). Wheel upload unpacked by `safe_extract`. Uploads already on disk. Failure → `CHECK.NOT_RUN.ACQUIRE` | `ctx.path/ref`, facts | S1 |
| 2 | S1 Identify | `pipeline.py::_s1` → `_identify` | path | Reads shipped passport (`SignedPassport`), `_hash_files` (SHA-256 per file via `hashing/files.py::hash_file`), `store.put_tree`, `_tensor_hashes` (models), card text, name/version/source/parents, `_merkle_root` + `registry.find_by_digest` (`INTAKE.DIGEST.KNOWN`, info) | `ctx.files`, `ctx.tensors` | S2.. |
| 3 | S2 Provenance | `pipeline.py::_stage_scanners("S2")` | ctx | Sequential scanners (below) | findings | S3 |
| 4 | S3 Static | `_stage_scanners("S3")` | ctx | Per-type scanners | findings | S4 |
| 5 | S4 Deep | `_stage_scanners("S4")` | ctx | Per-type scanners (CPU parent diff, hub parent, GPU calls, dataset v2/diff, package deps) | findings | S5 |
| 6 | S5 LLM | `_stage_scanners("S5")` | ctx incl. all earlier findings | `gpu_card_review` / `gpu_code_review` | findings | S6 |
| 7 | S6 Decide | `pipeline.py::run_intake` | all findings | `apply_unrun_costs`, `_trust`, `_build_passport` (`risk_score`), `registry.sign`, `policy/engine.py::decide` | `Decision` | S7, UI |
| 8 | S7 Admit | `registry.record` → `lineage_server/service.py::record` | passport, findings, decision, meta | One transaction: `passports`, `artifacts`, `findings`, `decisions`, `artifact_meta`, `artifact_identity`, `edges`/`ghosts`, `tool_pins`; store manifest | DB rows | dashboard views |

Registered scanners, as executed (`inspectors_for`, printed from the live registry):

| Type | S2 | S3 | S4 | S5 |
|---|---|---|---|---|
| model | origin_check, publisher_policy, signed_passport, parent_chain, licence, release_age | model_pickle, model_config, model_tokenizer, model_chat_template | local_parent_diff, hub_parent, gpu_weights | gpu_card_review |
| dataset | same 6 | dataset_format, dataset_pii, dataset_stats | dataset_v2, dataset_upstream_diff | gpu_card_review |
| package | same 6 + package_provenance | package_osv, package_baseline, package_capabilities, package_taint, package_rules | package_dependency_closure | gpu_code_review |
| tool | same 6 | package_capabilities, package_taint, package_rules, tool_description, tool_intent | none | gpu_code_review |
| agent | origin_check, publisher_policy, signed_passport, parent_chain, licence | none | none | none |

**Sequencing.** Stages run strictly in order in one generator; scanners inside a stage run sequentially, and each sees earlier findings (`ctx.findings = base + found`). Nothing runs concurrently inside `run_intake`. S3–S5 return `skipped` when `ctx.path is None`.

**Failure handling.**
- Scanner raises `NotImplementedError` → `CHECK.NOT_RUN.<NAME>` (`inspectors.py::run_inspector`).
- Scanner raises anything else → `SCANNER.ERROR.<NAME>`, medium (+12), never a silent pass.
- Whole stage raises → `INTAKE.STAGE.ERROR`, high (+25), stage event `failed`; the pipeline still reaches S6.
- Dependency missing (GPU, key, network, pyarrow) → the scanner emits `CHECK.NOT_RUN.*`; `apply_unrun_costs` prices it per environment from `policy.unrun_checks`.
- There is no per-check timeout in `run_intake`; the GPU client uses `timeout=120`, the hosted LLM `180 s`, OSV `10 s`. A hang inside a scanner blocks the job (bench notes a PyPI package that hung `package_taint`: `bench` commit a839172). **UNVERIFIED** whether taint has its own budget beyond `BudgetExceeded` → `CHECK.NOT_RUN.TAINT_PARTIAL`.

**Persisted:** findings (`findings.body`), decision (`decisions.body`), passport, identity panel data (`artifact_identity`), job events. **Displayed:** stage cards from the SSE events (real server events; for a fresh run `Intake.tsx` replays them at one per 380 ms, `follow(..., paced=true)`: pacing is cosmetic, content is not invented), identity/five-checks/attestation from `GET /artifacts/{id}/view` and `/attestations/{id}/view`.

## 2. Findings that matter for the presentation (verified)

1. **Prosecutor/defender/judge is real, but inside the reviewer, not the client.** Intake (`inspectors.py::gpu_code_review`) calls `client.review_to_findings` → one `POST /review/code` (or in-process `gpu_worker/reviewer_api.py::review_code`). With a plain-purpose request this runs `reviewer_api._pipeline`: **prosecutor always; defender and judge only if the prosecutor has at least one grounded claim**. The separate client-side 3-request orchestration `llm_review/client.py::review_package` (prompts in `llm_review/prompts.py`) is **not called by intake**; only tests use it.
2. **Card-review claims are probably all dropped in a real run.** The reviewer cites `card.md`/`measured.json` (`reviewer_api.card_docs`, `CARD_PROSECUTOR`), but `inspectors.py::claims_to_findings` re-grounds against `ctx.root`, which has no `card.md`. Experiment (`claims_to_findings` with a `README.md` card): a claim citing `card.md` → `LLM.CARD.UNGROUNDED` (info, 0); citing `README.md` → `LLM.CARD.CLAIM` (high, +25). The same applies to `LLM.POLICY` (`policy_hosted.check` uses `file="card.md"`). The existing test (`test_intake_pipeline.py::test_card_review_claims_are_grounded...`) uses a fake that cites `README.md`. **A live hosted card review was not run here.** This is a likely defect, not confirmed against the live model.
3. **"Verify passport" overclaims.** `ArtifactDetail.tsx::runVerify` shows "Signature, hashes and chain verified" when `valid` is true, but `routes/passports.py::verify_passport` returns `hashes_ok=None` and never re-hashes. Section 6C.
4. **Finding `stage` field vs the stage that ran it differ.** `dataset_stats` and `tool_intent` are registered in S3 but emit `stage="S4"`; `package_capabilities`/`package_taint` findings carry `S4` though they run in S3. The UI groups by the stage that ran (events), so this only affects the stored field.
5. **Tokenizer diff only happens at S4.** S3 `model_tokenizer` calls `tokenizer.scan(root)` with no base (`MODEL.TOKENIZER.NO_BASE`, info). The real diff runs when a parent is identified (`local_parent_diff` or `hub_parent`).
6. **GPU tests are not collected without torch.** `tests/conftest.py` sets `collect_ignore_glob = ["test_gpu_*.py"]` when torch is missing (it is missing here): `test_gpu_app`, `test_gpu_weights`, `test_gpu_behaviour_notary` and `test_gpu_reviewer` did not run in this audit. Suite result here: all collected tests pass, 9 skipped (`test_real_hub` 1, `test_stubs` 8). I did not obtain the exact pass count (the command was interrupted).
7. **Minor.** `package_provenance` emits `PKG.PROV.COOLDOWN`, but the engine looks for ids starting with `PROV.COOLDOWN` (`_has_id`), so that finding adds score but triggers no engine cooldown quarantine; the engine's cooldown rule uses `released_at`, which is the working path. Code reading only, not executed.

## 3. Hashing and identity (6A)

- **Per-file:** SHA-256, streamed (`hashing/files.py::hash_file`, fallback in `pipeline.py::_hash_file`). Pipeline hashing excludes `passport.json`, `*.passport.json` and `.git` (`_hash_files`); `lineage.meta.json` **is** hashed.
- **Aggregate:** Merkle root over sorted `(name, sha256)` leaves, leaf = `sha256(name || 0x00 || digest)` (`hashing/merkle.py`). Caution: `pipeline.py::_merkle_root` only falls back to a different local construction (duplicate last node) if the import raises `NotImplementedError`; in this build the real module is used.
- **Tensors:** per-tensor hashes for `.safetensors` (`hashing/tensors.py::hash_safetensors`), stored in the passport `contents.tensors`; a bad header → `MODEL.FORMAT.MALFORMED_SAFETENSORS` (high).
- **Artifact identity:** the passport id (`lp:` + sha of canonical passport JSON) of the registry-signed passport; `subject.digest.sha256` = Merkle root. A re-upload of identical bytes gets `INTAKE.DIGEST.KNOWN` (info) but is still a new passport.
- **Content-addressed storage:** `lineage/store.py::Store` keeps `blobs/sha256/<aa>/<hash>` + `manifests/<artifact>.json`; intake writes inspected bytes before inspecting; serving checks the attestation in the server (`routes/store.py`, not read in detail: **UNVERIFIED** beyond the docstring).
- **Archives:** `fetch.safe_extract` refuses absolute/`..` paths, links/devices, >10,000 entries, depth >32, >`LINEAGE_MAX_UPLOAD_MB` (2048 default), ratio >200:1. Wheels are unpacked for inspection and the wheel itself kept.
- **Re-hash:** at pull (`client.pull`) and at use (`client.check_for_use`: missing, mismatch and unattested files are refusals). A changed hash means "bytes differ"; it becomes a security conclusion only where a rule says so: `INTEGRITY.HASH_MISMATCH` (vs a signed passport, critical, hard block), `PROV.ORIGIN.MODIFIED` (vs hub-published hashes, critical, hard block in staging/prod only), `INTEGRITY.FETCH_MISMATCH` (hard block).

## 4. Parent / upstream identification (6B)

| Mechanism | Where | Trust |
|---|---|---|
| Explicit passport parents | `ctx.parents` from shipped passport; `parent_chain` checks registry status (`PROV.PARENT.REVOKED` critical hard block, `UNKNOWN` medium, `NOT_ADMITTED` high) | only meaningful from a verified passport |
| Claimed base (card, hub, uploader) | fact `base_model`; declared claims never change trust | declared = can only add risk |
| Local weight fingerprint | `inspectors.py::local_parent_diff` → `diff/parent.py::fingerprint_parent` (mean of 1/(1+relative L2) over reference tensors; threshold 0.5) against admitted models on this host (`registry.reference_models`) | computed; identified parent is added to `ctx.parents` |
| Hub base without download | `hub_parent` → `diff/hub_parent.py::compare` (HTTP range: config, tokenizer, safetensors header, first 512 embedding rows; cosine ≥ 0.90 = identified, else `MODEL.PARENT.CLAIM_MISMATCH` high) | needs a claimed base and network |
| GPU bank fingerprint | `gpu_worker/weights_api.py::identify_parent` (cosine on embedding slice + first layers vs `models.yaml` bank, threshold 0.90) | needs worker and the model on the worker's disk |

Unknown parent: `MODEL.PARENT.UNIDENTIFIED` (low, +5) or `CHECK.NOT_RUN.PARENT_ID` / `WEIGHT_BACKDOOR` / `BEHAVIOUR_DIFF`. Datasets: upstream diff only against an earlier admitted version of the same name (or `previous_path` in hub record). Packages: previous release from `previous_path` or PyPI wheel (`package_previous.py`, skipped when `LINEAGE_OFFLINE`).

## 5. Verify passport (6C): trace

`ArtifactDetail.tsx` button "Verify passport" → `runVerify` → `api.verifyPassport` (`lib/api.ts`) → `GET /passports/{id}/verify` → `routes/passports.py::verify_passport` → `VerifyResult{valid, signature_ok, hashes_ok, chain_ok, revoked, problems}` → UI prints one sentence.

| Item | Status | Evidence |
|---|---|---|
| Schema/format | CHECKED implicitly | loaded as `SignedPassport` (pydantic) from DB |
| Canonical signed bytes | CHECKED | `trust.verify_signed` |
| Ed25519 signature | CHECKED | against `trust.trusted_key(conn, key_id)` |
| Key discovery/trust | CONDITIONAL | key must be in the registry's `trusted_keys` (the registry's own key is auto-trusted) |
| Publisher identity | NOT CHECKED | this passport is the **registry's** intake passport; the publisher's creator passport is checked at intake (`signed_passport`), not here |
| Artifact file hashes | **NOT CHECKED** (`hashes_ok=None`) | the CLI/library path `lineage/passport/verify.py::verify_passport` can re-hash; the server route does not |
| Parent chain | CHECKED | registered and not revoked ancestors |
| Expiry | CHECKED | `expires_at` |
| Revocation | CHECKED | `models.is_revoked` |
| Registry admission attestation / environment / policy | NOT CHECKED | that is `GET /attestations/{id}`, `/status`, and `lineage load-check` |

A green "verified" guarantees: the stored registry passport is untampered, signed by a key this registry trusts, unexpired, unrevoked, with a registered unrevoked ancestry. It does **not** guarantee: the bytes you hold match, the publisher is who they claim, the artifact is currently allowed in any environment. The four ideas stay separate in code: creator passport (`signed_passport`), key trust (`resolve_signer`, `trusted_publishers`), registry attestation (`lineage_server/attest.py::issue`), and permission to load now (`lineage/client.py::check_for_use`).

## 6. Why S3, S4, S5 are separate

Code-level reasons (not just UI grouping): different registry slots (`INSPECTORS[(type, stage)]`); different costs and dependencies (S3 pure CPU/offline-capable, S4 mixes CPU, network, GPU worker, S5 needs an LLM backend); a stage-level `failed`/`skipped` event; S5 explicitly consumes earlier results (`ctx.findings`: `gpu_code_review` sends file:line refs of every non-info finding and the static findings to the judge/corroboration; `gpu_card_review` sends `measured` = file count, claimed base, and sorted `id:severity` of all earlier findings). S4 reads S3 only incidentally (`ctx.previous` from S3 `package_baseline`; `ctx.findings` to avoid duplicating `MODEL.WEIGHTS.CHANGED_LAYERS`). Policy prices `unrun_checks` by check name, not stage. Merging stages would change event/observability output (one card per stage), the `skipped`-on-no-bytes rule and S5's access to S3/S4 findings; scoring itself is stage-independent (sum of finding scores). The only handoff structure is `IntakeContext` (`inspectors.py`).

## 7. Not verified / not done

- Live hosted LLM request (no API key here). Prompts, parsing and fallback are covered by stubbed tests only.
- GPU worker end to end (no torch, no GPU); worker auth is a shared bearer secret (`serviceauth.py`), tested by `test_service_auth.py` (grep-level only).
- Real Hugging Face artifact: `tests/test_real_hub.py` is off by default and was not run.
- False-alarm rates on real PyPI packages (documented as never measured in the handoff).
- `routes/store.py`, `mcp_gateway/gateway.py`, `lineage_server/monitor.py`, `graph.py`, federated code: not audited here.
- Sigstore/DSSE: not implemented (`lineage/signing/sigstore_opt.py` exists; not traced).
