# Lineage: implementation audit (post-refactor)

Read-only audit of branch `refactor/rigid-flow` at commit `ff88ac7` (27 Oct 2026). Nothing in source, config, tests, the database or Git was changed; this file is the only addition. Line numbers are from that commit.

**How to read the claims.** Status labels: IT = implemented and tested, INT = implemented, not adequately tested, P = partial, S = specified only, M = missing, C = contradicted by code. Where I did not read a function line by line, I say so. Per-check regexes and thresholds are not all reproduced here (see section 6 and Appendix A for what was and was not verified); I did not invent any that I did not read.

**What I executed:** `git status`, `uv run pytest -q -p no:warnings` (exit 0, no failures, real hosted-API tests are off by default), an AST scan to list every finding-ID string (Appendix A). Nothing else (no benchmarks, no downloads). Earlier in this same session (before the audit) I ran the benchmarks and the real Hugging Face test; those results are quoted from `bench/results_after_refactor.md`, not re-run.

---

## 1. Executive summary

Lineage is admission control for AI artifacts (models, datasets, packages, MCP tools). One mandatory flow runs for every request, S0 Acquire, S1 Identify, S2 Provenance, S3 Static, S4 Deep, S5 LLM review, S6 Decide, S7 Record (`lineage/intake/pipeline.py`: `_s0` 418, `_identify` 151, `run_intake` 325). The registry signs a per-environment **attestation**; `lineage.load()`, `lineage pull`, the package index and the MCP gateway trust only that.

| Area | Status |
|---|---|
| One flow, facts with provenance classes, NOT_RUN pricing | IT (`test_facts`, `test_no_silent_skip`, `test_intake_pipeline`) |
| Hash, Merkle root, per-file store, attestation | IT (`test_server_store`, `test_load_enforcement`) |
| Creator passport: signature, trusted-publisher scope, revoked key | IT (`test_signature_scope`, `test_wellknown_keys`) |
| Origin check against HF / PyPI published hashes | IT with a fake hub; real HF once, off by default (`test_real_hub`, needs `LINEAGE_TEST_REAL_HUB=1`) |
| Roles, separation of duties | IT (`test_roles`) |
| Graph, ghosts, scheduled monitor | IT (`test_graph_monitor`, `test_monitor`, `test_graph_revoke`) |
| Package index (PEP 503) | IT (`test_package_index`) |
| MCP gateway: pins, output scan, registry status | IT (`test_mcp_gateway`) |
| Federated gate | IT on synthetic updates (`test_federated`); not integrated with any real FL framework |
| Dataset v2 | IT on generated data (`test_dataset_v2`); one real set (20newsgroups) |
| Hosted LLM reviewer | IT with stubs (`test_hosted_reviewer`, `test_inspect_llm_review`); run live once against the hosted API in the benchmark |
| GPU checks (weights, behaviour, notary) | Code and stubs tested; **not run on a GPU in this refactor** (no GPU) |
| Kaggle, OCI, internal-registry adapters | M. Only `hf` and `pypi` fetchers exist (`lineage/intake/fetch.py`) |
| Sigstore, TUF, transparency log as trust roots | P: optional `--sigstore` signing flag (`signing/sigstore_opt.py`), a TUF-style metadata module (`lineage_server/tuf.py`), and an internal Merkle log (`/log`). None is a trust root for creator passports |
| CI | M. There is no `.github/`; no CI config in the repo |

Important caveats: all benchmark numbers are on in-repo synthetic sets the detectors were written against (upper bound); the hosted reviewer model (`nvidia/nemotron-3.5-lightning-30b-a3b`) differs from the frozen Brev run, so reviewer numbers are not comparable.

**Git state:** branch `refactor/rigid-flow`, no tracked changes. Untracked: `.write_test`, `REFACTOR_SPEC.md`, `docs/REFACTOR_SPEC.md`, eight `lineage.db*.bak` files (backups from demo runs). Nothing unfinished in tracked files.

## 2. Architecture and runtime flow

Components: **dashboard** (`dashboard/`, Vite/React, talks to the API with a bearer token), **API server** (`lineage_server/`, FastAPI, SQLite `lineage.db`), **CLI** (`lineage/cli.py`, Typer), **content-addressed store** (`lineage/store.py`, default root from `default_root()`; `blobs/sha256/<aa>/<sha>` plus `manifests/<artifact>.json`), **inspection** (`lineage/inspect/*`, in-process), **GPU worker** (`gpu_worker/`, FastAPI: weights, behaviour, notary, reviewer, policy), **hosted reviewer** (in-process via `gpu_worker.reviewer_api` when no worker is named and an API key exists), **MCP gateway** (`mcp_gateway/gateway.py`), **scheduler** (`lineage_server/scheduler.py`, thread, every `LINEAGE_MONITOR_MINUTES`, default 60, 0 = off).

Flow for one request: client (`dashboard` or `lineage intake`/`upload`) -> `POST /uploads` (optional) and `POST /intake` (`routes/intake.py:36,74`, role `requester`) -> job -> `run_intake` -> stages -> `policy.engine.decide` -> `service` writes artifact, findings, decision, edges, Merkle log entry -> dashboard follows `GET /events/{job_id}` (SSE) -> human `POST /decisions/{id}/approve` if quarantined -> consumer runs `lineage pull` or `lineage.load()` -> checks `GET /attestations`, verifies Ed25519 signature with the pinned registry key, re-hashes files.

## 3. Commands and API

### CLI (read from `lineage/cli.py`; `uv run lineage --help` lists the same 11)

| Command | Syntax (args, defaults) | Effect |
|---|---|---|
| `intake` (44) | `REF [-t model\|dataset\|package\|tool\|agent] [-e dev] [--policy examples/policy.org.yaml]` and more (see file) | Runs the flow locally, prints verdict |
| `keygen` (71) | `[--dir .] [--name lineage] [--publish] [--scope X ...]` | Ed25519 key pair; `--publish` writes `.well-known/lineage-keys.json` |
| `sign` (95) | `PATH [-t] [--name] [--version 0.0.0] [--key lineage.key] [--out] [--parent ID ...] [--hub] [--repo] [--sigstore]` | Writes a signed creator passport |
| `verify` (151) | `PASSPORT [--artifact PATH] [--pubkey lineage.pub] [--server URL] [--from SITE] [--accept-change]` | Checks signature, hashes, optional revocation; `--from` fetches and pins the signer's well-known keys |
| `diff` (213) | `PARENT CHILD [--all] [--json] [--top 30]` | Tensor-level diff of two safetensors models |
| `run` (256) | `[--key] [--parent ID ...] [--name] [--version] [--fact KEY=VALUE ...] -- <command>` | Runs a command, records inputs/SBOM, writes passport v2 beside each output |
| `load-check` (319) | `PATH [-e prod] [--server] [--allow-pickle]` | `lineage.load()` without loading |
| `pull` (337) | `REF DEST [-e prod] [--server] [--pin]` | Fetch admitted bytes + attestation from the registry, verify, write |
| `upload` (366) | `PATH [--server]` | Sends a file/archive to `POST /uploads` |
| `revoke` (385) | `ARTIFACT_ID [--reason] [--server http://127.0.0.1:8000]` | `POST /revoke/{id}` |
| `bench` (414) | `[hash\|corpus] [--path] [--size-mb 512] [--files 8]` | Hash benchmark |

**Existence check:** `lineage load` as a CLI command: **does not exist** (the equivalent is `load-check`, which does not load). `lineage.load()` as a Python function: **exists** (`lineage/bind.py:113`, also `LineageAutoModel.from_pretrained`). `lineage train`: **does not exist**; the equivalent is `lineage run -- <your training command>`. `lineage run`, `pull`, `sign`, `verify`, `revoke`: exist. Tokens come from `LINEAGE_TOKEN` / `~/.lineage/config.toml` (`client.settings()`, 38); I did not enumerate every environment variable.

### HTTP endpoints (from route decorators)

| Endpoint | Role required | Notes |
|---|---|---|
| `POST /uploads`, `POST /intake` | requester | start an intake (`routes/intake.py`) |
| `POST /passports` | requester | register a signed passport |
| `GET /passports/{id}`, `/passports/{id}/verify` | not seen in route signature | `verify` returns revoked status (used by `check_for_use`) |
| `GET /artifacts`, `/artifacts/{id}`, `/graph/{id}`, `/events/{job}`, `/log`, `/log/proof/{ref}`, `/monitor/status`, `/monitor/latest`, `/trusted-publishers`, `/policy`, `/whoami` | no `require()` in the route; global auth is described in `auth.py` docstring ("every request needs a bearer token") but **I did not trace the middleware** | read endpoints |
| `POST /decisions/{id}/approve` | approver; 403 if the user is the requester (`decisions.py:19-40`) | body: expiry, reason |
| `POST /revoke/{id}` | approver | |
| `POST /monitor/tick` | approver or requester | |
| `PUT /policy` | admin (`policy.py:25`) | the only way to change trusted publishers and revoked keys (no separate POST) |
| `GET /attestations/{id}`, `/attestations?digest=`, `/registry-key` | not seen | consumed by `pull`/`load` |
| `GET /store/{id}/files/{path}`, `/store/{id}/manifest`, `/lookup` | not seen | bytes + manifest |
| `GET /simple/`, `/simple/{name}/`, `/files/{sha256}/{file}` | HTTP basic (token as password) | pip index |
| `GET /api/models/{repo}`, `/revision/{rev}` | | HF-compatible endpoint |
| `POST /fl/rounds` (requester), `GET /fl/rounds`, `/fl/rounds/{id}`, `/fl/clients` | | federated |
| `GET /healthz` | none | |
| gateway `POST /`, `GET /gateway/status` | | MCP JSON-RPC |
| GPU worker `/weights/parent`, `/weights/spectral`, `/behaviour/{diff,claims,triggers}`, `/notary/{certify,check,commitment,cert}`, `/review/{code,card,policy,stats}`, `/health` | none seen | |

Dashboard usage of each endpoint was not enumerated; the dashboard pages are Intake, Approvals, Trusted publishers, Federated, Monitor, graph.

## 4. Acquisition, bytes, hashes, storage

- **Sources:** local path or uploaded archive; `hf:org/name[@rev]` (models and datasets) and `pypi:name[==ver]` (`fetch.py`: `fetch_hf` 172, `fetch_pypi` 217, `parse_origin` 112). Anything else: M.
- **A remote reference downloads bytes** (S0). Max `LINEAGE_MAX_FETCH_MB` (default 4096) and `LINEAGE_MAX_UPLOAD_MB` (2048). Archives are extracted by `safe_extract` (63). If acquisition fails, `CHECK.NOT_RUN.ACQUIRE` is a hard block (`engine.py` hard_blocks); an empty ref no longer inspects the CWD (fixed this session, regression test).
- **Upload with unknown source:** facts about publisher/licence are `declared`; `declared` facts can only add risk. The allow list does not apply (`PROV.PUBLISHER.UNVERIFIED`), no origin is verified (`PROV.ORIGIN.UNCLAIMED`), trust stays `unknown` (+15 points). For models, S2/S3 may still try to identify a parent from weights (`local_parent_diff` against admitted models, `hub_parent` by HTTP Range requests, threshold 0.90) and infer it only as a *computed* fact; no source discovery from the bytes beyond that. Outcome follows the normal score: in prod, `min_trust: origin_verified` makes an unknown-trust artifact quarantine at least.
- **Hashing:** SHA-256, streamed in 8 MiB chunks (`lineage/hashing/files.py:10`), per file, files in parallel threads; Merkle root over `(path, sha)` leaves (`pipeline._merkle_root` 81; `hashing/merkle.py`). Safetensors also get per-tensor hashes (`_tensor_hashes` 95, `hashing/tensors.py`); GGUF supported (`hash_gguf`). Multi-file artifacts are the `files` map plus the root. Memory: one 8 MiB buffer per worker.
- **Storage:** blobs in the store, manifests as JSON, everything else in SQLite `lineage.db` (tables: passports, artifacts, findings, decisions, approvals, edges, revocations, log, policy_state, role_keys, trusted_keys, artifact_meta, ghosts, users, fl_clients, fl_rounds, monitor_ticks, tool_pins). Full bytes are in the store (files), not the DB; hashes, passports and findings are in the DB.
- **Three different comparisons:** (1) *compute* the digest (S1); (2) compare with the **publisher's expected digest**: HF `siblings[].lfs.sha256` / `blobId` (git oid) and PyPI `urls[].digests.sha256` (`published_files` 141, `origin_check` 192) -> `PROV.ORIGIN.VERIFIED` / `MODIFIED` (hard block in staging/prod) / `UNVERIFIABLE`, and `INTEGRITY.FETCH_MISMATCH` when a download differs from what the index published; (3) compare with the **admitted digest at load** (`client.check_for_use` 99: each file re-hashed against `attestation.files`, missing/mismatch/unattested file are problems).
- **Weights changed after admission:** detected at the next `load()`/`pull`/`load-check`, which re-hash every file; refused. Not detected while a process holds the model in memory (the docstring says the check and load are separate reads; use a read-only mount). There is no filesystem watcher.
- **Pagination, gated/private repos, rate limits:** only a single `GET /api/models/{repo}?blobs=true` per revision with `follow_redirects=True`; no pagination handling, no token header for gated repos that I found, no rate-limit handling. Errors become `AcquireError`/`NotFound` -> NOT_RUN.ACQUIRE.

## 5. Passports and trust

- **Creator passport** (`schemas/passport.py`): an in-toto Statement v1 (`subject[{name,digest}]`, `predicateType lineage.dev/passport/v1`, `predicate` = `PassportBody`: artifact_type, name, version, source{hub,repo,commit,url}, contents{merkle_root, files, tensors}, parents, action, trust_level, findings_digest, risk_score, certificates, inputs, sbom, facts, issued_by{name,key_id}, issued_at, expires_at). `SignedPassport` = passport + base64 Ed25519 signature + key_id. **Signed:** the canonical JSON (sorted keys, no whitespace, UTF-8) of the whole `Passport`; id is `lp:` + sha256 of it.
- **Company attestation** (`schemas/attestation.py`): artifact_id, digest (Merkle root), files, outcome, environment, trust, policy_version, issued_at, expires_at, revoked; signed Ed25519 by the registry key. Issued on request, per environment (`lineage_server/attest.py`).
- **Keys:** trusted keys live in the **policy** (`trusted_publishers` {name, key, scope}); only an `admin` can change them (`PUT /policy`). `LINEAGE_TRUSTED_KEYS` is a dev bootstrap, used only when the policy lists none, scope `*`. A key's scope is fnmatch patterns on source ids (`hf:org/*`, `pypi:name`, `upload:*`) (`inspectors.resolve_signer` 307, `in_scope`).
- **Verification order** (`signed_passport` 337): revoked key -> `PROV.SIGNATURE.REVOKED_KEY` (unsigned); unknown key -> `UNTRUSTED_KEY` (unsigned); bad signature -> `PROV.SIGNATURE.INVALID` (critical, **hard block**); out-of-scope -> `SCOPE_MISMATCH` (unsigned); expired -> `PASSPORT.EXPIRED`; file hashes -> `INTEGRITY.HASH_MISMATCH` (critical, hard block) and `UNPINNED_FILE`. Only if everything passes do the passport's facts become `signed` and trust can reach `signed`. A passport carrying its own public key never counts: only keys in the policy do.
- **Missing passport:** nothing signed; facts are `declared`/`fetched`/`computed`; trust at most `origin_verified` (if the origin hashes match) or `unknown`.
- **Attacks:** edit passport -> signature invalid (hard block). Sign with own key -> `UNTRUSTED_KEY`, treated as unsigned (medium). Replace passport and key -> same, unless the admin put the attacker's key in the policy. Rotation/revocation: `policy.revoked_keys`; the monitor also raises revocation alerts for admitted artifacts signed by a revoked key. Key expiry as a concept: M (only passport `expires_at`).
- **Does Lineage create a passport after admission?** The intake builds its own passport (`_build_passport` 295, issued_by Lineage, trust_level, findings digest) which is stored; the usable artifact for consumers is the **attestation**, delivered by `GET /attestations` / `lineage pull` as `<path>.lineage-attestation.json`.
- **Old/blocked/revoked passport at load:** `load()` no longer reads the creator passport; only the attestation (`bind.py` docstring). A blocked or revoked artifact fails `check_for_use` (outcome not allow, `att.revoked`, plus online check `GET /passports/{id}/verify`).
- **Not used as trust roots:** Sigstore (optional signing flag only), OIDC identities, X.509, TUF for passports, public transparency log. The only trust mechanism is policy-pinned Ed25519 keys with scopes plus the well-known key publication (`lineage keygen --publish`, `verify --from`, pin file on first use, `--accept-change` to rotate).

## 6. Inspection matrix

Appendix A lists all 198 finding-ID strings found in code with the file, line and function of their first appearance (script output, not hand-curated; some entries are prefixes, seed/demo data or helper constants rather than distinct checks). Severity, regexes and thresholds were **not** all verified one by one. What I did verify from source:

- **Scoring:** see section 8.
- **Models:** pickle opcode scan (`model_pickle.py`: DANGEROUS_GLOBAL, UNKNOWN/UNRESOLVED_GLOBAL, UNPARSEABLE, PRESENT), config/`trust_remote_code`/`auto_map` (`model_config.py`), chat template and Jinja (`chat_template.py`: SSTI, hidden/embedded instruction, trigger branch, role remap, hidden tool call, invisible unicode, diff from known-good), tokenizer and parent-tokenizer diff (`tokenizer.py`), parent identification (`diff/parent.py`, `diff/hub_parent.py`, `inspectors.local_parent_diff`), spectral weight-backdoor score and behaviour divergence (GPU worker: `weights_api`, `behaviour_api`, called from `inspectors.gpu_weights`, **require a GPU worker**), notary check (`notary_api`, needs a certificate), model-card review (LLM, section 7). If the GPU worker is absent, these emit `CHECK.NOT_RUN.*` priced by the policy (`WEIGHT_BACKDOOR`, `PARENT_ID`, `BEHAVIOUR_DIFF`: info in dev, low in staging, medium in prod).
- **Packages:** OSV lookup (`package_osv.py`; offline = `PKG.OSV.UNAVAILABLE`), look-alike name/repo and maintainer change and cooldown (`package_provenance.py`), previous-release wheel diff (`package_previous.py`, `package_capabilities.diff_findings`: PKG.NEW.*), startup hooks `.pth` (`hook_findings`), capability/combination rules (`package_capabilities.py`), five AST rules (`package_rules.py`: atexit effect, import hook, obfuscated target, git-hook write, beacon thread), taint/data-flow (`package_taint.py`, budget `LINEAGE_TAINT_BUDGET_S`=20, 400k steps, 400 files, `TAINT_PARTIAL` when cut), dependency closure (`inspectors.package_dependency_closure` 464-477, ghosts for unregistered), LLM package review (section 7). I did not verify how the previous wheel is chosen beyond `package_previous.py`.
- **Datasets:** formats via `_tabular.py` readers; PII (`dataset_pii.py`), stats (`dataset_stats.py`: duplicates, near-duplicates, conflicting labels, imbalance, label-error estimate, trigger-token), v2 (`dataset_v2.py`: characters, injection patterns, trigger-behaviour, dirty-label trigger, spectral outliers, kNN label disagreement; TF-IDF+SVD 256-d embeddings or `LINEAGE_EMBED_MODEL`), upstream diff (`dataset_diff.py`). Minimum rows and thresholds are in those files; not reproduced here.
- **MCP tools:** description scan (`tool_description.py`), declared-permission vs code (`tool_intent.py`), taint (shared with packages), LLM review, pinning (`gateway.hash_description`, `hash_code`, `pin_tool`, `tool_pins` table), manifest missing (`TOOL.MANIFEST.MISSING`). **At admission:** the S3-S5 scans. **Each call (gateway):** pin re-check (sticky disable on mismatch; fail closed if code hash unknown), registry status check (`db_status_check`), response scan `TOOL.OUTPUT.*` (`scan_result`, action block/redact). Details of every output pattern not enumerated.
- **Federated learning: exists** (`lineage/federated/*`, `/fl/*`, `fl_clients`/`fl_rounds` tables): robust z-scores of update norm, cosine-to-median, Krum, sign disagreement (`scoring.py`); client trust x0.5 when flagged, +0.05 when clean, quarantine below 0.3 (`gate.py`); aggregators fedavg, coord_median, trimmed_mean, multi_krum, trust_weighted; secure-aggregation demo (`secure_agg.py`: pairwise masks, norm-consistency check). Benchmark: scaling and sign-flip caught, backdoor and "a little is enough" mostly evade (`bench/results_fl.md`).
- **Not implemented:** NVIDIA product dependencies (by rule); dynamic execution of packages (sandboxed install) M; Kaggle/OCI.

## 7. LLM review

Three separate systems; they do **not** share a prompt.

1. **Code review (packages, custom model code, tools)**, prompts in `gpu_worker/reviewer_api.py:73-95` (worker, system prompts `CODE_PROSECUTOR`, `CODE_DEFENDER`, `CODE_JUDGE`, shared `SAFETY` block at line 62) and a second, in-client brief set `lineage/inspect/llm_review/prompts.py` (`ROLE_BRIEF`, `RULES`, data delimited by `<<<UNTRUSTED_DATA ... UNTRUSTED_DATA>>>`; `build_request`). The client sends each role's brief in the request `purpose`; the worker sees `purpose.startswith("ROLE:")` and runs a single pass (`review_code`, line 336-355); otherwise it runs prosecutor -> defender -> judge (`_pipeline`). Judge can keep or **raise** severity, add at most 3 extra claims; lowering is ignored.
2. **Card review** (`/review/card`): same three roles with `CARD_*` prompts comparing the card line by line with `measured.json` (parent, benchmarks) as ground truth.
3. **Policy check** (`lineage/inspect/llm_review/policy_hosted.py`): single call, system prompt built from the policy (licences, personal data, residency, blocked publishers, banned capabilities) + the card numbered by line (first 400 lines); reply `{"violations":[{"line","reason"}]}`; a violation counts only if the line exists and is non-empty; severity fixed `medium`. Default model is the general Nemotron reviewer; `nvidia/nemotron-3.5-content-safety` was tested and rejected (returns only `User Safety: safe|unsafe`).

Provider and transport: hosted OpenAI-compatible endpoint, default `https://integrate.api.nvidia.com/v1` (`LINEAGE_LLM_BASE_URL`), model `nvidia/nemotron-3.5-lightning-30b-a3b` (`LINEAGE_LLM_MODEL`), key `LINEAGE_LLM_API_KEY` or `NVIDIA_API_KEY`. If `LINEAGE_VLLM_URL` is set, a vLLM server on a GPU worker is used instead (model name `reviewer`, by default `nvidia/NVIDIA-Nemotron-Nano-9B-v2` on the Brev run). Parameters: temperature 0, `max_tokens` 1200 default per call, `chat_template_kwargs {enable_thinking: false}` (hosted), JSON-schema constrained output with a plain-JSON fallback and one retry (`reviewer_llm._hosted_json`); timeout 180 s. Review cache: `LINEAGE_REVIEW_CACHE` directory.

Grounding: every claim needs file, line and the exact `api` text on that line; `grounding.ground_claims_with_reasons` drops claims whose line does not contain it (`LLM.REVIEW.UNGROUNDED_DROPPED`); ungrounded findings add 0 points (`risk.finding_points`). Reviewer-bait text is detected deterministically (`bait.py`, `PKG.REVIEW.BAIT`) and removed from the prompt. **Precise mode** (default): a claim adds risk only when a deterministic rule fires in the same file or the judge sets `purpose_mismatch`. The LLM can only add risk: `risk.py` has no subtracting path, and `HARD_FINDING_IDS` cannot be lowered by an LLM verdict.

Fallback: service down, 503, rate limit or invalid JSON after retry -> `ReviewerUnavailable`/`GpuUnavailable` -> `LLM.REVIEW.SKIPPED` / `CHECK.NOT_RUN.*` priced per environment; the intake does not crash. Privacy: **source slices, model-card text and the policy rules are sent to `integrate.api.nvidia.com`** when hosted mode is on; with a vLLM worker they go to your own GPU host. I did not trace exactly which files are selected into slices (`review_package` in `client.py` 251) or the exact truncation sizes beyond the visible `[:4000]` purpose/`[:3000]` context/`[:4000]` diff caps. Tests: injection/bait and malformed output in `test_inspect_llm_review.py`, `test_gpu_reviewer.py`, `test_hosted_reviewer.py` (stubs); the hosted model was exercised live only through the benchmark and a manual policy check.

Purely deterministic: everything not listed above. Needs a GPU: weight spectral, behaviour diff/claims/triggers, notary, and the optional vLLM reviewer.

## 8. Risk, policy, approvals

**Score:** `min(100, sum(finding points) + trust penalty)` (`risk.py:80`). Points: info 0, low 5, medium 12, high 25, critical 40. Trust penalty: unknown 15, origin_verified 5, signed 0, recorded 0. Two or more `PKG.OSV.*` advisories collapse into one `PKG.OSV.GROUP` counted once at the worst severity. Ungrounded LLM findings count 0.

**Hard blocks** (`engine.hard_blocks` 85): `INTEGRITY.FETCH_MISMATCH`, `PROV.ORIGIN.MODIFIED` (staging/prod only), `PROV.SIGNATURE.INVALID`, `INTEGRITY.HASH_MISMATCH`, `PROV.PARENT.REVOKED`, `CHECK.NOT_RUN.ACQUIRE`, `PKG.OSV.MAL*`, pickle when `model_files.allow_pickle` is false (a "policy block"), banned capabilities, publisher block patterns. `risk.HARD_FINDING_IDS` additionally protects PKG.CODE.DECODE_EXEC, PKG.TAINT.ENCODED_EXEC, new startup hooks, dangerous pickle globals from being demoted.

**Soft reasons** (overridable by a live, unexpired approval): cooldown, vulnerability above `max_vuln_severity` for the environment, identity findings (critical = block, high = quarantine), PII when not allowed (block), licence not allowed (quarantine), trust below the environment minimum, risk above the allow limit (quarantine) or above 70 (block), human approval required by policy (`tool`, `model:prod`).

**Environments (`examples/policy.org.yaml`):** dev min_trust unknown, max_risk 70; staging origin_verified, 40; prod origin_verified, 25; thresholds allow 30 / quarantine 70; cooldown days package 3, model 7, dataset 7, tool 7. Effective allow limit = min(30, environment max_risk). The policy examples above are one file; other policies can differ.

**Outcomes:** allow; allow_with_conditions (soft reasons accepted by a live approval, conditions listed); quarantine; block. **Cooldown:** release date must come from a fetched or signed fact; without it `PROV.COOLDOWN.UNVERIFIED` quarantines. **NOT_RUN:** `apply_unrun_costs` converts each `CHECK.NOT_RUN.<name>` into points from `policy.unrun_checks` (per environment; `ACQUIRE` always critical).

**Approvals:** authenticated, role `approver` (admin implies all roles); the approver is the logged-in user, never typed; the requester cannot approve their own request (403, `decisions.py:29`) except when auth is off (`LINEAGE_REQUIRE_AUTH=0` makes everyone an anonymous admin, `auth.py`). Approvals expire; expiry must be in the future; the monitor raises an alert when approvals lapse. A policy that is past its expiry blocks admission (`policy_expired` -> floor quarantine). **Policy signature requirements:** I did not find a signed-policy requirement; the policy lives in the DB and only `admin` can `PUT` it, each change goes in the Merkle log. **Trusted-publisher workflow:** edit the policy (`PUT /policy`, dashboard page "Trusted publishers"), no separate API.

## 9. Use-time enforcement, monitoring, revocation

| Path | Checks at use | Fail closed? | Bypass |
|---|---|---|---|
| `lineage.load()` / `LineageAutoModel.from_pretrained` / `lineage load-check` / `lineage pull` | attestation signature (pinned registry key), environment, outcome, expiry, online revocation (`/passports/{id}/verify`), re-hash every file, pickle refusal | yes; registry unreachable: prod 0 h grace (fails closed), staging 6 h, dev 24 h (`DEFAULT_GRACE_HOURS`) | `transformers.from_pretrained`, `torch.load`, `pip install` from PyPI directly are not intercepted |
| Dataset load | no loader wrapper found; `pull` + `load-check` apply to any directory | n/a | direct file reads |
| `pip install --index-url http://user:token@host/simple/` | only admitted, non-revoked versions are listed; blobs served by sha256 and pip pins the hash | blocked version absent | default PyPI index |
| MCP gateway | per-call pin check (description and code hash), registry status check, response scan | yes (unknown code hash disables the tool) | clients that bypass the gateway |
| `lineage run` | records inputs/SBOM; does **not** enforce admission of its inputs (I did not find a check) | no | n/a |
| CI verification | `lineage verify`/`load-check` exit non-zero on failure; **no CI config or deployment/serving integration in the repo** | | |

A model already loaded in memory is not protected. **Monitor:** automatic thread (default hourly) and `POST /monitor/tick`; covers OSV advisories for admitted packages and ghosts (dependencies/SBOM nobody admitted), expired approvals, hub drift (upstream changed/removed), admitted artifacts signed by a revoked key, policy changes that would flip a decision. **Revocation** (`service.revoke`): marks the artifact revoked, writes the Merkle log, flips the attestation's `revoked`; descendants are re-evaluated through `PROV.PARENT.REVOKED` on their next intake and reported through the graph's blast radius (`graph.blast_radius`); I did not verify an automatic re-decision of existing descendants.

## 10. Lineage graph and training provenance

Edges (`edges` table; kinds `derived_from`, `trained_on`, `built_with`, `depends_on`, `contributed_to`) come from: passport `parents` (declared), `lineage run --parent` and recorded `inputs`/SBOM (observed locally), identified parents (`MODEL.PARENT.IDENTIFIED`, computed from weight similarity or Range-request fingerprints), package dependency closure (`PKG.DEP.*`), SBOM components. Things referenced but never admitted become **ghost nodes** with status `unregistered` (`ghosts` table, `graph._ghost`). Parent claims are declared unless a computed match confirms them (`MODEL.PARENT.CLAIM_MISMATCH` when a claim contradicts the weights). Weights can reveal a likely parent; they cannot reveal datasets, training code, hyperparameters, base revision or package list. `lineage run` records **files it sees the process read** (the `inputs` map) and the Python environment SBOM; network reads and dynamically fetched inputs are not captured as far as I could determine (I read the passport fields, not the tracing mechanism in `lineage/run.py` in full). The graph can look complete while missing edges: only declared/observed edges exist, unknown inputs produce no node.

Example of a harmless run: `lineage run --key lineage.key --parent lp:abc... --fact licence=apache-2.0 -- python train.py data.csv` writes `out/model.safetensors` and `out/model.passport.json` with `inputs {"data.csv": "<sha256>"}`, `sbom [pkg:pypi/torch@...]`, `parents [lp:abc...]`, `facts [licence]`, signed with the key; it is `signed` trust only if the registry's policy lists that key with a covering scope.

## 11. Tests

54 test files (`tests/`), full run now: `uv run pytest -q -p no:warnings`, **exit 0, no failures** (the run printed 2 progress lines of dots and no failures; I did not capture the total count). Groups: schemas/facts/signature (`test_schemas`, `test_facts`, `test_signature_scope`, `test_wellknown_keys`), flow/policy (`test_intake_pipeline`, `test_policy_engine`, `test_no_silent_skip`, `test_origin`, `test_precision`), server (`test_server_api`, `test_server_store`, `test_roles`, `test_load_enforcement`, `test_hf_endpoint`, `test_package_index`, `test_graph_*`, `test_monitor`, `test_tuf`), inspectors (`test_inspect_*`, `test_package_rules`, `test_template_tokenizer_fixes`, `test_hub_parent`, `test_dataset_v2`), LLM (`test_inspect_llm_review`, `test_hosted_reviewer`, `test_gpu_reviewer`), GPU (`test_gpu_weights`, `test_gpu_behaviour_notary`, `test_gpu_app`: stubs, no real GPU), gateway (`test_mcp_gateway`), federated (`test_federated`), bench (`test_bench_*`), real hub (`test_real_hub`, off by default). **Mocked:** hub (`tests/fakehub.py`), LLM (stubs), GPU. **Real network:** only when `LINEAGE_TEST_REAL_HUB=1`. **No CI.**

Benchmarks (`bench/results_after_refactor.md`, measured at/just before `ff88ac7`, synthetic in-repo sets the detectors were developed against): FINAL set TPR 88% (35/40) static / 90% (36/40) with the hosted reviewer, FPR 5% (2/40); in-sample 48/48 and 0/43 (40 LoRA items excluded); dev 40/40, 0/40. Frozen baseline (`bench/results_final.md`): FINAL 68-70% TPR, 5% FPR; in-sample 90-91%, 6%. Reviewer model differs between baseline and now.

**Missing acceptance tests I could not find:** unknown-source upload end to end through the HTTP API with every expected finding; real-FL integration; registry-outage behaviour per environment at the `load()` level beyond `test_load_enforcement` (I did not read it fully); parent-revocation cascade to existing descendants; LLM false-positive rates on real code; GPU/deep-review failure through the full pipeline; blocked package installation against a real `pip`.

**README/spec claims contradicted:** none found that I could prove. Two unverified items: whether global auth middleware covers GET routes; and the claimed "descendant re-evaluation" on revocation.

## 12. Public passport interoperability proposal (design, nothing implemented)

Reuse, in this order: **in-toto Attestation** (already the statement shape), **DSSE** envelope instead of the custom signature field, **SLSA Provenance v1** as the predicate for build provenance of `lineage run` outputs, a thin **`lineage.dev/model-card/v1`** profile only for what has no standard home (multi-file/tensor digests, parents, datasets), **Sigstore** (Fulcio OIDC identity + Rekor) as the preferred signer identity, **TUF** only for distributing a publisher's trusted-key metadata with expiry and rotation. Mandatory: subject digest = Merkle root over `(path, sha256)` leaves plus the file list; DSSE-wrapped statement; verifier-side *expected identity* (issuer + subject, or key id + scope) supplied by the consumer's own policy, never by the uploader; expiry. Optional: Rekor inclusion proof, SLSA predicate, tensor digests. Bootstrap trust through the consumer's policy (what `trusted_publishers` already does) or a publisher's HTTPS well-known key set pinned on first use (already built) or Sigstore identity match. Distribution: attestation next to the artifact (HF repo file `*.lineage.json`, PyPI attestation, OCI referrer). Verification of an uploaded file: recompute digests, check the DSSE signature against the expected identity, check scope covers the claimed source, check freshness/revocation, then run the company's own checks. Of the above, **only the in-toto statement shape, Ed25519, scope matching and well-known keys exist today**; DSSE, SLSA predicate, Sigstore verification, Rekor, TUF distribution and discovery protocol are all work to do.

## 13. Highest-priority gaps (with evidence)

1. No CI and no GPU run in this refactor: GPU checks are NOT_RUN in all measured results (`results_after_refactor.md`).
2. Benchmarks are on author-written synthetic sets; real-world false-alarm rates were not re-measured after the refactor (those sets point at another machine's paths).
3. `GET` routes carry no `require()`; confirm the middleware really enforces auth (not traced).
4. No hosted/gated-repo handling (no HF token, no pagination, no rate limiting) in `fetch.py`.
5. The registry and loader protect only the `load()`/`pull`/index/gateway paths; direct framework loads and the public PyPI index bypass them by design.
6. Loaded-in-memory models are unprotected; check and load are separate reads.
7. `lineage run` records only observed file inputs; no network inputs, and it does not enforce that inputs were admitted.
8. Policy is not signed; trust rests on admin access to `PUT /policy` and the Merkle log.
9. No Kaggle/OCI/internal-registry adapters.
10. Hosted review sends code and cards to an external service; there is no per-artifact opt-out switch beyond not setting the key.

## 14. Glossary

**Admission:** the decision to let an artifact be used in an environment. **Attestation:** registry-signed statement of that decision. **Creator passport:** the publisher's signed claim about an artifact. **Fact / provenance class:** a piece of metadata tagged computed, fetched, signed or declared; only the first three can relax checks. **Ghost:** a referenced thing nobody admitted. **Merkle root:** one hash over all file hashes. **NOT_RUN:** a check that could not run, priced by policy. **Scope:** which sources a trusted key may sign for. **Quarantine:** not usable until a human approves. **Precise mode:** an LLM claim adds risk only with deterministic support.

## 15. Open questions

*Product decisions:* should declared-only facts ever relax anything; should the policy be signed; should hosted code review be opt-in per artifact; what is the acceptable offline grace per environment. *Coding gaps:* auth on read endpoints, HF tokens/pagination, DSSE/Sigstore, descendant re-evaluation on revoke, enforcement of admitted inputs in `lineage run`, real-GPU runs, CI.

---

## Appendix A: finding-ID strings found in code

First occurrence of each ID-shaped string in `lineage/`, `lineage_server/`, `mcp_gateway/`, `gpu_worker/` (generated by an AST scan; trailing-dot entries are prefixes; `seed.py`/`mock.py` entries are demo data, not checks).

| ID | file:line | function |
|---|---|---|
| `CHECK.NOT_RUN.` | lineage/intake/inspectors.py:151 | not_run |
| `CHECK.NOT_RUN.ACQUIRE` | lineage/intake/pipeline.py:206 | _identify |
| `CHECK.NOT_RUN.TAINT_PARTIAL` | lineage/inspect/package_taint.py:356 | scan |
| `DATA.CHARS.` | lineage/inspect/dataset_v2.py:213 | check_characters |
| `DATA.DIFF.ADDED_ROWS` | lineage/inspect/dataset_diff.py:53 | diff |
| `DATA.DIFF.BALANCE_DRIFT` | lineage/inspect/dataset_diff.py:60 | diff |
| `DATA.DIFF.LABELS_FLIPPED` | lineage/inspect/dataset_diff.py:48 | diff |
| `DATA.DIFF.NEW_TOKENS` | lineage/inspect/dataset_diff.py:70 | diff |
| `DATA.DIFF.NO_BASELINE` | lineage/intake/inspectors.py:574 | dataset_upstream_diff |
| `DATA.DIFF.SUMMARY` | lineage/inspect/dataset_diff.py:44 | diff |
| `DATA.FORMAT.PICKLE` | lineage/intake/inspectors.py:533 | dataset_format |
| `DATA.INJECT.EXEC` | lineage/inspect/dataset_v2.py:221 | check_injection |
| `DATA.INJECT.MARKDOWN_IMAGE` | lineage/inspect/dataset_v2.py:222 | check_injection |
| `DATA.INJECT.OVERRIDE` | lineage/inspect/dataset_v2.py:221 | check_injection |
| `DATA.INJECT.SECRET` | lineage/inspect/dataset_v2.py:222 | check_injection |
| `DATA.INJECT.URL` | lineage/inspect/dataset_v2.py:223 | check_injection |
| `DATA.KNN.LABEL_DISAGREE` | lineage/inspect/dataset_v2.py:426 | check_knn_labels |
| `DATA.PII` | lineage/policy/engine.py:208 | decide |
| `DATA.PII.` | lineage/inspect/dataset_pii.py:92 | scan |
| `DATA.SPECTRAL.OUTLIERS` | lineage/inspect/dataset_v2.py:401 | check_embedding_outliers |
| `DATA.STATS.CLASS_BALANCE_MISMATCH` | lineage/inspect/dataset_stats.py:250 | scan |
| `DATA.STATS.CLASS_COUNT_MISMATCH` | lineage/inspect/dataset_stats.py:256 | scan |
| `DATA.STATS.CONFLICTING_LABELS` | lineage/inspect/dataset_stats.py:220 | scan |
| `DATA.STATS.EXACT_DUPLICATES` | lineage/inspect/dataset_stats.py:213 | scan |
| `DATA.STATS.IMBALANCED` | lineage/inspect/dataset_stats.py:259 | scan |
| `DATA.STATS.LABEL_ERRORS` | lineage/inspect/dataset_stats.py:273 | scan |
| `DATA.STATS.LABEL_ESTIMATE_SKIPPED` | lineage/inspect/dataset_stats.py:266 | scan |
| `DATA.STATS.NEAR_DUPLICATES` | lineage/inspect/dataset_stats.py:229 | scan |
| `DATA.STATS.NO_TABLE` | lineage/inspect/dataset_stats.py:185 | scan |
| `DATA.STATS.OK` | lineage_server/seed.py:174 | seed |
| `DATA.STATS.ROW_COUNT_MISMATCH` | lineage/inspect/dataset_stats.py:253 | scan |
| `DATA.STATS.SUMMARY` | lineage/inspect/dataset_stats.py:196 | scan |
| `DATA.STATS.TRIGGER_TOKEN` | lineage/inspect/dataset_stats.py:277 | scan |
| `DATA.TRIGGER.BEHAVIOUR` | lineage/inspect/dataset_v2.py:306 | check_trigger_behaviour |
| `DATA.TRIGGER.LABEL` | lineage/inspect/dataset_v2.py:363 | check_label_trigger |
| `DATA.V2.NO_TEXT` | lineage/inspect/dataset_v2.py:441 | scan |
| `DATA.V2.SUMMARY` | lineage/inspect/dataset_v2.py:450 | scan |
| `INTAKE.DIGEST.KNOWN` | lineage/intake/pipeline.py:257 | _identify |
| `INTAKE.PASSPORT.MALFORMED` | lineage/intake/pipeline.py:193 | _identify |
| `INTAKE.REF.NOT_FOUND` | lineage/intake/pipeline.py:159 | _identify |
| `INTAKE.STAGE.ERROR` | lineage/intake/pipeline.py:373 | run_intake |
| `INTEGRITY.FETCH_MISMATCH` | lineage/intake/fetch.py:242 | fetch_pypi |
| `INTEGRITY.HASH_MISMATCH` | lineage/risk.py:22 |  |
| `INTEGRITY.UNPINNED_FILE` | lineage/intake/inspectors.py:381 | signed_passport |
| `LLM.CARD` | lineage/intake/inspectors.py:900 | gpu_card_review |
| `LLM.CARD.MISSING` | lineage/intake/inspectors.py:887 | gpu_card_review |
| `LLM.CODE.ENCODED_EXEC` | lineage_server/seed.py:214 | seed |
| `LLM.CODE.UNDECLARED_NETWORK` | lineage_server/mock.py:76 |  |
| `LLM.POLICY` | lineage/intake/inspectors.py:906 | gpu_card_review |
| `LLM.REVIEW.CLAIM` | lineage/inspect/llm_review/client.py:207 | _to_finding |
| `LLM.REVIEW.NOTHING_TO_REVIEW` | lineage/intake/inspectors.py:925 | gpu_code_review |
| `LLM.REVIEW.SKIPPED` | lineage/inspect/llm_review/client.py:251 | review_package |
| `LLM.REVIEW.UNGROUNDED_DROPPED` | lineage/inspect/llm_review/client.py:272 | review_package |
| `LLM.REVIEW.UNGROUNDED_VERDICT` | lineage/inspect/llm_review/client.py:276 | review_package |
| `LLM.TOOL.EXFIL_PATTERN` | lineage_server/seed.py:224 | seed |
| `MODEL.BEHAVIOUR.DIVERGENCE` | lineage/intake/inspectors.py:826 | gpu_weights |
| `MODEL.CONFIG.AUTO_MAP` | lineage/inspect/model_config.py:69 | scan |
| `MODEL.CONFIG.AUTO_MAP_MISSING` | lineage/inspect/model_config.py:75 | scan |
| `MODEL.CONFIG.CUSTOM_CODE` | lineage/inspect/model_config.py:79 | scan |
| `MODEL.CONFIG.EXTERNAL_CODE` | lineage/inspect/model_config.py:72 | scan |
| `MODEL.CONFIG.TRUST_REMOTE_CODE` | lineage/inspect/model_config.py:63 | scan |
| `MODEL.FORMAT.MALFORMED_SAFETENSORS` | lineage/intake/pipeline.py:113 | _tensor_hashes |
| `MODEL.FORMAT.PICKLE` | lineage/policy/engine.py:108 | hard_blocks |
| `MODEL.FORMAT.PICKLE_NOT_FETCHED` | lineage/intake/pipeline.py:449 | _s0 |
| `MODEL.NOTARY.MISMATCH` | lineage/intake/inspectors.py:839 | gpu_weights |
| `MODEL.NOTARY.NOT_APPLICABLE` | lineage/intake/inspectors.py:834 | gpu_weights |
| `MODEL.PARENT.CLAIM_MISMATCH` | lineage/intake/inspectors.py:799 | gpu_weights |
| `MODEL.PARENT.IDENTICAL` | lineage/intake/inspectors.py:711 | local_parent_diff |
| `MODEL.PARENT.IDENTIFIED` | lineage/intake/inspectors.py:715 | local_parent_diff |
| `MODEL.PARENT.NO_CLAIMED_BASE` | lineage/intake/inspectors.py:743 | hub_parent |
| `MODEL.PARENT.UNIDENTIFIED` | lineage/intake/inspectors.py:706 | local_parent_diff |
| `MODEL.PICKLE.` | lineage/policy/engine.py:108 | hard_blocks |
| `MODEL.PICKLE.DANGEROUS_GLOBAL` | lineage/risk.py:21 |  |
| `MODEL.PICKLE.PRESENT` | lineage/inspect/model_pickle.py:181 | scan |
| `MODEL.PICKLE.UNKNOWN_GLOBAL` | lineage/inspect/model_pickle.py:204 | _findings |
| `MODEL.PICKLE.UNPARSEABLE` | lineage/inspect/model_pickle.py:189 | _findings |
| `MODEL.PICKLE.UNRESOLVED_GLOBAL` | lineage/inspect/model_pickle.py:200 | _findings |
| `MODEL.TEMPLATE.CONDITIONAL_INSTRUCTION` | lineage/inspect/chat_template.py:319 | scan_template |
| `MODEL.TEMPLATE.CONTENT_CONDITIONAL` | lineage/inspect/chat_template.py:300 | scan_template |
| `MODEL.TEMPLATE.DIFF_FROM_KNOWN_GOOD` | lineage/inspect/chat_template.py:356 | scan_template |
| `MODEL.TEMPLATE.EMBEDDED_INSTRUCTION` | lineage/inspect/chat_template.py:332 | scan_template |
| `MODEL.TEMPLATE.HIDDEN_INSTRUCTION` | lineage/inspect/chat_template.py:329 | scan_template |
| `MODEL.TEMPLATE.HIDDEN_TOOL_CALL` | lineage/inspect/chat_template.py:248 | _hidden_tool_calls |
| `MODEL.TEMPLATE.INVISIBLE_UNICODE` | lineage/inspect/chat_template.py:275 | scan_template |
| `MODEL.TEMPLATE.ROLE_REMAP` | lineage/inspect/chat_template.py:236 | _role_remap |
| `MODEL.TEMPLATE.SSTI` | lineage/inspect/chat_template.py:279 | scan_template |
| `MODEL.TEMPLATE.TRIGGER_BRANCH` | lineage/inspect/chat_template.py:297 | scan_template |
| `MODEL.TEMPLATE.UNPARSEABLE` | lineage/inspect/chat_template.py:267 | scan_template |
| `MODEL.TEMPLATE.URL` | lineage/inspect/chat_template.py:337 | scan_template |
| `MODEL.TOKENIZER.` | lineage/inspect/tokenizer.py:157 | scan |
| `MODEL.TOKENIZER.ADDED_TOKENS` | lineage/inspect/tokenizer.py:148 | scan |
| `MODEL.TOKENIZER.ADDED_TOKENS_UNCHECKED` | lineage/inspect/tokenizer.py:110 | scan |
| `MODEL.TOKENIZER.MERGES_CHANGED` | lineage/inspect/tokenizer.py:152 | scan |
| `MODEL.TOKENIZER.MODEL_FILE_CHANGED` | lineage/inspect/tokenizer.py:161 | scan |
| `MODEL.TOKENIZER.NEW_TOKENS` | lineage/inspect/tokenizer.py:127 | scan |
| `MODEL.TOKENIZER.NO_BASE` | lineage/inspect/tokenizer.py:112 | scan |
| `MODEL.TOKENIZER.REMAPPED` | lineage/inspect/tokenizer.py:124 | scan |
| `MODEL.TOKENIZER.REMOVED_TOKENS` | lineage/inspect/tokenizer.py:130 | scan |
| `MODEL.TOKENIZER.SPECIAL_FLAG_CHANGED` | lineage/inspect/tokenizer.py:144 | scan |
| `MODEL.TOKENIZER.SPECIAL_TOKEN_CHANGED` | lineage/inspect/tokenizer.py:165 | scan |
| `MODEL.TOKENIZER.SPECIAL_TOKEN_REMAPPED` | lineage/inspect/tokenizer.py:138 | scan |
| `MODEL.TOKENIZER.SUSPICIOUS_TOKEN` | lineage/inspect/tokenizer.py:105 | scan |
| `MODEL.WEIGHTS.CHANGED_LAYERS` | lineage/intake/inspectors.py:727 | local_parent_diff |
| `MODEL.WEIGHTS.SPECTRAL_ANOMALY` | lineage/intake/inspectors.py:817 | gpu_weights |
| `MODEL.WEIGHTS.SPECTRAL_OK` | lineage_server/seed.py:184 | seed |
| `PKG.BASELINE.COMPARED` | lineage/intake/inspectors.py:615 | package_baseline |
| `PKG.BASELINE.NONE` | lineage/intake/inspectors.py:616 | package_baseline |
| `PKG.CODE.BAIT_ON_RISKY_CODE` | lineage/inspect/package_capabilities.py:650 | _bait_over_risky_code |
| `PKG.CODE.DECODE_EXEC` | lineage/risk.py:18 |  |
| `PKG.CODE.DELAYED_EXEC` | lineage/inspect/package_capabilities.py:600 | content_findings |
| `PKG.COMBO.CREDENTIAL_EXFIL` | lineage/inspect/package_capabilities.py:658 |  |
| `PKG.COMBO.FETCH_AND_RUN` | lineage/inspect/package_capabilities.py:658 |  |
| `PKG.COMBO.IMPORT_TIME_EXEC` | lineage/inspect/package_capabilities.py:558 | combos |
| `PKG.COMBO.OBFUSCATED_PAYLOAD` | lineage/inspect/package_capabilities.py:551 | combos |
| `PKG.DEP.NONE` | lineage/intake/inspectors.py:464 | package_dependency_closure |
| `PKG.DEP.RESOLVED` | lineage/intake/inspectors.py:477 | package_dependency_closure |
| `PKG.DEP.UNREGISTERED` | lineage/intake/inspectors.py:475 | package_dependency_closure |
| `PKG.HOOK.` | lineage/inspect/package_capabilities.py:584 | hook_findings |
| `PKG.HOOK.STARTUP_HOOK` | lineage/risk.py:20 |  |
| `PKG.NEW.CREDENTIAL_PATH` | lineage/inspect/package_capabilities.py:634 | diff_findings |
| `PKG.NEW.DYNAMIC_EXEC` | lineage/inspect/package_capabilities.py:618 | diff_findings |
| `PKG.NEW.NETWORK` | lineage/inspect/package_capabilities.py:630 | diff_findings |
| `PKG.NEW.NETWORK_HOST` | lineage/inspect/package_capabilities.py:626 | diff_findings |
| `PKG.NEW.SUBPROCESS` | lineage/inspect/package_capabilities.py:617 | diff_findings |
| `PKG.OSV.` | lineage/risk.py:9 |  |
| `PKG.OSV.MAL` | lineage/risk.py:17 |  |
| `PKG.OSV.MALICIOUS` | lineage/inspect/package_osv.py:145 | scan |
| `PKG.OSV.UNAVAILABLE` | lineage/inspect/package_osv.py:137 | scan |
| `PKG.OSV.VERSION_UNKNOWN` | lineage/inspect/package_osv.py:132 | scan |
| `PKG.OSV.VULN` | lineage/inspect/package_osv.py:149 | scan |
| `PKG.PROV.COOLDOWN` | lineage/inspect/package_provenance.py:170 | scan |
| `PKG.PROV.LOOKALIKE_NAME` | lineage/inspect/package_provenance.py:200 | scan |
| `PKG.PROV.LOOKALIKE_REPO` | lineage/inspect/package_provenance.py:188 | scan |
| `PKG.PROV.MAINTAINER_CHANGED` | lineage/inspect/package_provenance.py:223 | scan |
| `PKG.PROV.REPO_INCONSISTENT` | lineage/inspect/package_provenance.py:194 | scan |
| `PKG.PROV.REPO_MISMATCH` | lineage/inspect/package_provenance.py:191 | scan |
| `PKG.PROV.REPO_OWNER_MISMATCH` | lineage/inspect/package_provenance.py:215 | scan |
| `PKG.PROVENANCE.OK` | lineage_server/seed.py:178 | seed |
| `PKG.REVIEW.BAIT` | lineage/inspect/llm_review/bait.py:89 | findings |
| `PKG.RULE.ATEXIT_EFFECT` | lineage/inspect/package_rules.py:93 | scan_file |
| `PKG.RULE.BEACON_THREAD` | lineage/inspect/package_rules.py:114 | scan_file |
| `PKG.RULE.GIT_HOOK_WRITE` | lineage/inspect/package_rules.py:104 | scan_file |
| `PKG.RULE.IMPORT_HOOK` | lineage/inspect/package_rules.py:79 | scan_file |
| `PKG.RULE.OBFUSCATED_TARGET` | lineage/inspect/package_rules.py:98 | scan_file |
| `PKG.SIGNAL.` | lineage/inspect/package_capabilities.py:518 | signals |
| `PKG.SIGNAL.DELAYED_EXEC` | lineage/inspect/package_capabilities.py:602 | content_findings |
| `PKG.SIGNAL.REMOTE_EXEC_POSSIBLE` | lineage/inspect/package_capabilities.py:521 | signals |
| `PKG.STARTUP.PTH_EXEC` | lineage_server/seed.py:212 | seed |
| `PKG.TAINT.CREDENTIAL_EXFIL` | lineage/inspect/package_taint.py:52 |  |
| `PKG.TAINT.ENCODED_EXEC` | lineage/risk.py:19 |  |
| `PKG.TAINT.ENV_EXFIL` | lineage/inspect/package_taint.py:53 |  |
| `PKG.TAINT.FILE_UPLOAD` | lineage/inspect/package_taint.py:54 |  |
| `PKG.TAINT.REMOTE_EXEC` | lineage/inspect/package_taint.py:55 |  |
| `POLICY.LICENCE.NOT_ALLOWED` | lineage/intake/inspectors.py:426 | licence |
| `POLICY.LICENCE.UNVERIFIED` | lineage/intake/inspectors.py:429 | licence |
| `PROV.COOLDOWN` | lineage/policy/engine.py:190 | decide |
| `PROV.COOLDOWN.PACKAGE` | lineage_server/seed.py:208 | seed |
| `PROV.COOLDOWN.UNVERIFIED` | lineage/intake/inspectors.py:444 | release_age |
| `PROV.LOOKALIKE.PUBLISHER` | lineage/intake/inspectors.py:285 | publisher_policy |
| `PROV.LOOKALIKE.SOURCE_REPO` | lineage_server/seed.py:210 | seed |
| `PROV.ORIGIN.HINT` | lineage/intake/inspectors.py:201 | origin_check |
| `PROV.ORIGIN.MODIFIED` | lineage/intake/inspectors.py:239 | origin_check |
| `PROV.ORIGIN.UNCLAIMED` | lineage/intake/inspectors.py:211 | origin_check |
| `PROV.ORIGIN.UNVERIFIABLE` | lineage/intake/inspectors.py:216 | origin_check |
| `PROV.ORIGIN.VERIFIED` | lineage/intake/inspectors.py:204 | origin_check |
| `PROV.PARENT.NOT_ADMITTED` | lineage/intake/inspectors.py:410 | parent_chain |
| `PROV.PARENT.REVOKED` | lineage/intake/inspectors.py:405 | parent_chain |
| `PROV.PARENT.UNKNOWN` | lineage/intake/inspectors.py:407 | parent_chain |
| `PROV.PASSPORT.ABSENT` | lineage_server/seed.py:195 | seed |
| `PROV.PASSPORT.EXPIRED` | lineage/intake/inspectors.py:369 | signed_passport |
| `PROV.PUBLISHER.BLOCKED` | lineage/intake/inspectors.py:277 | publisher_policy |
| `PROV.PUBLISHER.UNLISTED` | lineage/intake/inspectors.py:292 | publisher_policy |
| `PROV.PUBLISHER.UNVERIFIED` | lineage/intake/inspectors.py:288 | publisher_policy |
| `PROV.SIGNATURE.INVALID` | lineage/risk.py:23 |  |
| `PROV.SIGNATURE.REVOKED_KEY` | lineage/intake/inspectors.py:348 | signed_passport |
| `PROV.SIGNATURE.SCOPE_MISMATCH` | lineage/intake/inspectors.py:364 | signed_passport |
| `PROV.SIGNATURE.UNTRUSTED_KEY` | lineage/intake/inspectors.py:352 | signed_passport |
| `TOOL.DESC.` | mcp_gateway/gateway.py:245 | check |
| `TOOL.DESC.AGENT_INSTRUCTION` | lineage/inspect/tool_description.py:97 | _agent_findings |
| `TOOL.DESC.ENCODED_TEXT` | lineage/inspect/tool_description.py:133 | scan_manifest |
| `TOOL.DESC.HTML_COMMENT` | lineage/inspect/tool_description.py:125 | scan_manifest |
| `TOOL.DESC.INVISIBLE_UNICODE` | lineage/inspect/tool_description.py:115 | scan_manifest |
| `TOOL.DESC.MARKDOWN_IMAGE` | lineage/inspect/tool_description.py:149 | scan_manifest |
| `TOOL.DESC.SHADOWING` | lineage/inspect/tool_description.py:100 | _agent_findings |
| `TOOL.DESC.UNREADABLE` | lineage/inspect/tool_description.py:166 | scan |
| `TOOL.DESC.URL` | lineage/inspect/tool_description.py:153 | scan_manifest |
| `TOOL.DESC.VERY_LONG` | lineage/inspect/tool_description.py:156 | scan_manifest |
| `TOOL.DESCRIPTION.CLEAN` | lineage_server/seed.py:220 | seed |
| `TOOL.INTENT.` | lineage/inspect/tool_intent.py:68 | scan |
| `TOOL.INTENT.UNDECLARED_` | lineage/inspect/tool_intent.py:56 | scan |
| `TOOL.INTENT.UNDECLARED_CREDENTIAL_READ` | lineage/inspect/tool_intent.py:63 | scan |
| `TOOL.INTENT.UNDECLARED_NETWORK` | lineage_server/seed.py:222 | seed |
| `TOOL.INTENT.UNUSED_` | lineage/inspect/tool_intent.py:73 | scan |
| `TOOL.MANIFEST.MISSING` | lineage/intake/inspectors.py:654 | tool_description |
| `TOOL.OUTPUT.` | mcp_gateway/gateway.py:245 | check |
| `WATCH.PARENT.ADVISORY` | lineage_server/monitor.py:90 | _flag |
| `WATCH.UPSTREAM.CHANGED` | lineage_server/monitor.py:234 | _hub_drift |
| `WATCH.UPSTREAM.REMOVED` | lineage_server/monitor.py:222 | _hub_drift |
