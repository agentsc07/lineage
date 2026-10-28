# Lineage refactor spec: one mandatory flow, no unverifiable trust

Version 1 · 27 Oct 2026 · for one Claude Code session on `main` (commit 044c18e or later)
Submission is due at the end of the day today. Work in the phase order in section 12 and stop at each cut line if time runs out.
Everything in phases 1 to 3 is required. Phase 4 is required only if time allows. Phase 5 (benchmarks, demo script, README) must always be done.

---

## 0. Rules for the session

1. **Read first:** this file, `CLAUDE.md`, `DECISIONS.md`, `lineage/intake/pipeline.py`, `lineage/intake/inspectors.py`, `lineage/policy/engine.py`, `lineage/bind.py`, `lineage_server/*.py`, `mcp_gateway/gateway.py`. Do not start coding until you have.
2. **Branch:** create `refactor/rigid-flow`. Commit after every numbered task, with the task id in the message (for example `R1.3: fact provenance`). Never commit to `main` directly.
3. **Keep the suite green:** `uv run pytest -q` must pass after every task. Update tests that encode old behaviour this spec removes, and say so in the commit message. Never delete a test just to make the suite pass.
4. **No GPU needed.** The only remote AI call is the LLM reviewer, through NVIDIA's hosted API (section 8.1). The GPU worker on Brev stays optional: if `LINEAGE_GPU_URL` is unset or unreachable, the checks that need it emit `CHECK.NOT_RUN.*` findings (section 4.3). Nothing waits on Brev.
5. **No silent skips anywhere.** Every check either runs or emits a `CHECK.NOT_RUN.<check>` finding saying why. Grep for `return []` in the inspectors and decide for each one.
6. **Keep a decisions log.** Record every decision this spec leaves open in `DECISIONS.md` under a heading `Refactor 27 Oct`.
7. **Keep the demo runnable:** `examples/run_dashboard_demo.sh` must work at the end of every phase (fix it as you go).
8. **Time-box.** If one task takes more than 45 minutes, write what is left into `DECISIONS.md` and move on.

---

## 1. Principles (rigid; every task must obey them)

| # | Principle | Consequence |
|---|---|---|
| P1 | **Every fact has a provenance class**: `computed` (Lineage derived it from the bytes), `fetched` (Lineage read it itself from an authoritative source at a pinned revision), `signed` (it is inside a passport signed by a trusted publisher whose scope covers this artifact), or `declared` (anything else, including the uploader, files inside the artifact such as `config.json`, `README`, `lineage.meta.json`, and `--trust` flags). | Facts are stored with their class and source. Only `computed`, `fetched` and `signed` facts may relax a check or raise trust. `declared` facts are shown and logged with the uploader's identity, and may only *add* risk (for example, a declared base that the weights contradict). |
| P2 | **One mandatory flow.** Every artifact of a type goes through every stage and every check for that type. Nothing depends on the environment or on earlier suspicion. | Remove the `needs_deep` tiering. A check that cannot run emits `CHECK.NOT_RUN.<name>`, and the policy decides what an unrun check costs (section 4.3). |
| P3 | **Trust comes only from evidence.** | New trust ladder (section 2). Inspection is not trust: an inspected unknown file stays `unknown`. |
| P4 | **One source of bytes.** Lineage stores the exact bytes it admitted (a content-addressed store) and is the only place code fetches them from. | Consumption goes through Lineage: the PyPI simple index, `lineage pull` and `LineageAutoModel` for models and datasets, and the MCP gateway for tools. `lineage.load()` refuses bytes without a valid **decision attestation** from the registry. |
| P5 | **What is used is checked against the decision at the moment of use.** | `lineage.load()`, the package index and the gateway check a registry-signed attestation (digest, outcome, environment, expiry) and the revocation status. They **fail closed** in prod: unreachable server plus no fresh cached attestation means refuse. |
| P6 | **The graph shows gaps.** | References to things Lineage has never admitted become `ghost` nodes (status `unregistered`), not dropped edges. Monitor and revoke operate on the whole graph, ghosts included. |
| P7 | **People are identified.** | API tokens with roles. Approvals and key changes are attributed to an authenticated user. A requester cannot approve their own request. |
| P8 | **Everything that changes a decision is logged.** | Decisions, approvals, revocations, trusted-publisher changes and policy changes are appended to the Merkle log. |

---

## 2. Trust model (replace the old enum)

```
TrustLevel = Literal["unknown", "origin_verified", "signed", "recorded"]   # ordered, low to high
```

| Level | Exactly when | Example |
|---|---|---|
| `unknown` | No verified origin and no valid in-scope signature. Covers any upload with no claim, a claim that could not be checked, or a mismatching claim (which also raises a critical finding). | A `.safetensors` someone emailed |
| `origin_verified` | Every file's hash matches what the claimed hub repo published at a pinned revision (section 4.2, S2a), **or** Lineage fetched the artifact itself from the hub. | `hf:meta-llama/Llama-3.2-1B@<sha>` fetched by Lineage |
| `signed` | A creator passport verifies with a key on the trusted-publisher list, **and** that key's scope covers this artifact's source (section 7.2), **and** the hashes match. | A vendor's model signed with its key |
| `recorded` | As `signed`, and the passport's action is `train` or `build` with `inputs` (hashes) and an `sbom` present (produced by `lineage run`). | A model trained by the company's own team through `lineage run` |

- Delete `declared`, `inspected` and `attested` everywhere: schemas, engine, dashboard, tests, policy YAML, seed and demo.
- Human approval is **not** a trust level. It is an exception with an approver and an expiry, as today.
- Risk penalty: `unknown` +15, `origin_verified` +5, `signed` 0, `recorded` 0.
- Default policy: `dev.min_trust: unknown`, `staging.min_trust: origin_verified`, `prod.min_trust: origin_verified`. Prod accepts `unknown` only with a human approval. The soft reason "trust below minimum" stays approvable; signature failure and hash mismatch stay hard blocks.

---

## 3. Data model changes

### 3.1 Facts (new)
`lineage/schemas/fact.py`:
```python
class Fact(BaseModel):
    key: Literal["name","version","publisher","source_repo","source_revision","licence","released_at",
                 "base_model","card_text","maintainers","requires","description"]
    value: str | None
    provenance: Literal["computed","fetched","signed","declared"]
    source: str          # e.g. "huggingface api /api/models/x@sha", "pypi json", "passport lp:..", "upload by alice@apollo"
    at: datetime
```
- `IntakeContext.facts: dict[key, list[Fact]]`. Helper `ctx.fact(key, trusted_only=True)` returns the best fact by class order: signed > fetched > computed > declared. With `trusted_only=True` it never returns a declared fact.
- **Every inspector that reads metadata switches to `ctx.fact(...)`**: publisher policy, licence, cooldown, package provenance, claimed base, card review, and the gateway description.
- If a check needs a fact and only a declared one exists, the check runs on it but emits its finding with `basis: declared` in the evidence detail. A declared fact may never clear a check: an unverified release date means cooldown is treated as **not cleared**.

### 3.2 Remove `lineage.meta.json` as an input
- Intake no longer reads `lineage.meta.json`. If present in an upload, it is hashed like any other file and its content becomes `declared` facts with source `file lineage.meta.json in upload`.
- The upload API takes `claims: {publisher?, licence?, base_model?, released_at?, description?}`. These become `declared` facts attributed to the authenticated user.
- Update the demo, seed and bench fixtures accordingly. Bench fixtures that relied on meta files must pass the same data as `fetched` through a **test-only fake hub** (section 11.2), so benchmark semantics do not change.

### 3.3 Passport v2 (creator passports)
Add to `PassportBody` (all optional, so old passports still parse):
- `inputs: dict[str, str]`: path to sha256 of every file the run read (from `lineage run`'s `run.json`), excluding ignored prefixes.
- `sbom: list[{name, version, purl}]`: from `pip freeze` (keep `env_sbom_digest` too). Use a CycloneDX-style component shape, with `purl` like `pkg:pypi/torch@2.4.1`.
- `facts: list[Fact]`: what the creator asserts (these become `signed` when the signature is in scope).

`lineage run` must:
- write the passport **beside each output** as `<output>.passport.json` (and keep the copy in `.lineage/runs/<id>/`)
- fill `inputs` and `sbom`
- refuse `--trust`. `lineage sign` also loses `--trust`: trust is decided by the verifier, never by the signer.

### 3.4 Company record and decision attestation (new)
The company passport (`_build_passport` at S6) stays: rename it **intake record** in code comments and the UI. It embeds the creator passport verbatim (signed envelope) under `evidence.creator_passport` when there is one.

New **decision attestation**, signed by the registry key, created at S7 and again on every re-decision, approval or revocation:
```json
{"artifact_id": "lp:...", "digest": "<merkle root>", "files": {"path": "sha256"},
 "outcome": "allow|allow_with_conditions|quarantine|block", "environment": "prod",
 "trust": "origin_verified", "policy_version": "...", "issued_at": "...", "expires_at": "<min(approval expiry, +7 days)>",
 "revoked": false}
```
- Endpoint: `GET /attestations/<artifact_id>?env=prod` returns the latest one.
- It is cached on the client at `<artifact>.lineage-attestation.json`.

### 3.5 Content-addressed store (new)
- Folder `LINEAGE_STORE` (default `./lineage-store`), holding `blobs/sha256/<aa>/<hash>`.
- Admitted artifacts have a manifest `{artifact_id, files: {path: sha256}}`.
- Intake writes every file of every artifact it receives (uploads and fetches) into the store before S1. Bytes are never served unless the latest attestation for the requested environment allows them.

---

## 4. Intake: the one flow

### 4.1 Doors
| Door | Input | Notes |
|---|---|---|
| `POST /uploads` (multipart) | a file or a `.zip`/`.tar.gz` (extracted safely: no absolute paths, no `..`, size cap `LINEAGE_MAX_UPLOAD_MB` default 2048) | Returns `upload_id` |
| `POST /intake` | `{artifact_type, source, environment, claimed_origin?, claims?}` where `source` is `upload:<id>`, `hf:<repo>[@rev]`, `hf-dataset:<repo>[@rev]`, `pypi:<name>==<ver>`, or `mcp:upload:<id>` | Replaces the free-text `ref`. Local paths are allowed only when the server runs with `LINEAGE_DEV_LOCAL_PATHS=1` (demo and bench) and are treated exactly like an upload |
| CLI `lineage intake <source>` | same | `lineage upload <path>` then intake |
| Dashboard Intake page | file picker **or** source box, plus claimed origin, claims, environment | Must show each stage live, as now |

### 4.2 Stages (all mandatory, in this order)

**S0 Acquire.** Get the bytes into the store.
- **`hf:`:** resolve `rev` to a commit sha with `huggingface_hub.HfApi().model_info(repo, revision, files_metadata=True)`, then `snapshot_download` with `allow_patterns` for `*.safetensors, *.json, *.txt, *.md, *.model, tokenizer*, *.jinja, *.py, *.gguf`. Refuse `*.bin/*.pt/*.pkl` downloads above 50 MB unless the policy allows pickle; still record that they exist. Size cap `LINEAGE_MAX_FETCH_MB` (default 4096). Facts are `fetched`: publisher (namespace), revision sha, last-modified, card text and YAML metadata (`license`, `base_model`, `datasets`), file list with `lfs.sha256`.
- **`hf-dataset:`:** same, but with `repo_type="dataset"`.
- **`pypi:`:** `GET https://pypi.org/pypi/<name>/<ver>/json`. Download the best wheel (else the sdist) and verify its sha256 against `digests.sha256`; a mismatch is `INTEGRITY.FETCH_MISMATCH`, a hard block. Facts are `fetched`: upload time, maintainers, project URLs, `requires_dist`, summary. Unpack the wheel into the store (do not install it).
- **`upload:`:** already stored. Facts come only from the creator passport (verified at S2) and the `declared` claims.
- **Offline:** if the network is down, `CHECK.NOT_RUN.ACQUIRE` (critical) and the decision is block, since nothing can be inspected.

**S1 Identify (computed).** Per-file sha256, Merkle root, per-tensor hashes for safetensors (keep), format detection per file, and `INTAKE.DIGEST.KNOWN`.

**S2 Provenance.** Each sub-check is mandatory; if it can't run, it emits a NOT_RUN finding.
- **S2a Origin check.**
  - Upload with `claimed_origin`: fetch the hub's published hashes. For HF, use the tree API at the pinned revision: LFS files carry `lfs.sha256`; for non-LFS files compute the git blob id `sha1(b"blob %d\0" % len + bytes)` and compare with `oid`. For PyPI, use the JSON `digests`.
  - Results: all files match gives `PROV.ORIGIN.VERIFIED` (info; trust becomes `origin_verified`; hub facts become `fetched`). Any mismatch, missing or extra file gives `PROV.ORIGIN.MODIFIED` (critical; hard block in staging and prod, listing every differing file). A claim that can't be checked (network, unknown repo) gives `PROV.ORIGIN.UNVERIFIABLE` (high). No claim gives `PROV.ORIGIN.UNCLAIMED` (medium).
  - Also extract **hints** (`config.json:_name_or_path`, README `base_model:`) as `declared` facts and show them as "suggested origin". Never use them for trust.
  - Fetched artifacts (`hf:`, `pypi:`) are `origin_verified` by construction: emit `PROV.ORIGIN.VERIFIED` with source "fetched by Lineage".
- **S2b Creator passport** (if one is in the upload or published in the HF repo as `*.passport.json`): signature, key on the trusted-publisher list, **key scope covers the source** (section 7.2), hashes, expiry. New finding `PROV.SIGNATURE.SCOPE_MISMATCH` (high) when a trusted key signs outside its scope. Passport `facts` become `signed` only if every check passes.
- **S2c Publisher.** From the best trusted publisher fact. Block list, allow list, look-alike (keep). If only a `declared` publisher exists, it's `PROV.PUBLISHER.UNVERIFIED` (medium), and the allow list never applies to it.
- **S2d Licence.** Same rule: an allowed licence needs a trusted fact. Declared only gives `POLICY.LICENCE.UNVERIFIED` (low).
- **S2e Release age (cooldown).** Needs a `fetched` or `signed` `released_at`. Otherwise `PROV.COOLDOWN.UNVERIFIED`, which the engine treats as cooldown **not cleared** (a soft quarantine that a human can approve).
- **S2f Parent chain.** Parents come from the signed passport, from `fetched` `base_model`, and from the weight match (S4). Each parent is resolved in the registry; unknown parents become **ghost nodes** (P6) with `PROV.PARENT.UNREGISTERED` (medium). Revoked gives a hard block (keep); not admitted gives high (keep).
- **S2g Package metadata** (packages): look-alike name, repo-owner mismatch, maintainer change and repo consistency, run **only on `fetched` metadata**. New, from Socket: `PKG.PROV.OUT_OF_ORDER_RELEASE` (a version published after a higher one) and `PKG.PROV.NEW_PUBLISHER` (a maintainer not on the previous release). If metadata isn't fetched, emit `CHECK.NOT_RUN.PKG_METADATA` (medium).

**S3 Static inspection.** As today per type, plus the fixes in section 8.

**S4 Deep inspection.** Now mandatory, and no longer only for models:
- **Models, parent identification:**
  1. Candidate parents are admitted models in the store, plus the `fetched` or `signed` `base_model`.
  2. For a hub base model, fetch only `config.json`, the tokenizer files and the safetensors header plus the embedding tensor, using an HTTP range request (the header gives byte offsets). Do not download the whole base.
  3. Run the CPU fingerprint (keep `lineage/diff/parent.py`), then the changed-tensor diff for tensors that can be compared.
  4. Emit `MODEL.PARENT.CLAIM_MISMATCH` (high) if the weights contradict a claimed base, `MODEL.PARENT.UNIDENTIFIED` (medium) if nothing matches, and `MODEL.PARENT.IDENTIFIED` (info) on a match.
- **Models, tokenizer diff:** pass the identified parent's tokenizer to `tokenizer.scan(root, base)`. Today it is never passed, so this check never runs.
- **Models, template vs parent:** keep.
- **Models, GPU checks** (spectral backdoor score, behaviour diff, Notary): call only if `LINEAGE_GPU_URL` responds; otherwise emit `CHECK.NOT_RUN.WEIGHT_BACKDOOR`, `.BEHAVIOUR_DIFF` and `.NOTARY`. The Notary runs only when the creator passport carries a certificate. Document in the UI that it supports Hugging Face causal LMs only.
- **Datasets:** the dataset v2 checks in section 8.3. The embedding and diff checks run here.
- **Packages and tools:** the dependency closure. Resolve `requires_dist` against admitted packages; each requirement not admitted becomes a ghost node with `PKG.DEP.UNREGISTERED` (low). This feeds the graph (P6).

**S5 LLM review (mandatory for packages, tools, model custom code, model and dataset cards).**
- Backend: NVIDIA hosted API (section 8.1). If unavailable, emit `CHECK.NOT_RUN.LLM_REVIEW` (medium).
- **Precise mode** (default): a claim adds risk only if a deterministic finding exists in the same file, or if the claim is a **purpose mismatch**. The reviewer is given the artifact's purpose from trusted facts (PyPI summary, HF card, tool description) and is asked whether each capability is expected for that purpose. A claim with no rule behind it, outside a purpose mismatch, is shown at `info` with score 0.
- Register the code review for models with `auto_map` or custom `.py` files.

**S6 Decide.** As today (engine), plus:
- trust from section 2
- NOT_RUN costs from section 4.3
- a declared-only fact can never clear a check

Build the intake record (company passport) with `facts`, `evidence.creator_passport` and `trust`.

**S7 Record.**
- Persist the record, findings, decision, and the **decision attestation**.
- Append everything to the Merkle log.
- Pin tools for the gateway (keep).
- Write the graph edges, including ghosts.

### 4.3 What an unrun check costs (policy-driven)
Add to the policy:
```yaml
unrun_checks:            # severity of CHECK.NOT_RUN.<name> per environment
  default: { dev: info, staging: medium, prod: high }
  ACQUIRE: { dev: critical, staging: critical, prod: critical }
  WEIGHT_BACKDOOR: { dev: info, staging: low, prod: medium }
```
- The engine maps each NOT_RUN finding to that severity.
- In prod, a model with no GPU checks therefore carries risk that needs a human approval, unless the policy says otherwise. Being explicit about this is the point.

---

## 5. Consumption: the only ways to get admitted bytes

| Type | Door | Check at the moment of use |
|---|---|---|
| Package | `GET /simple/` and `GET /simple/<name>/` (PEP 503 HTML; PEP 691 JSON optional) serving only versions whose attestation for the token's environment is allow or allow-with-conditions, as links to `/files/<sha256>/<filename>#sha256=<hash>`. `pip install --index-url http://<host>/simple/ <pkg>` works. Requesting a non-admitted version triggers an intake job and returns 404 with the job URL in a header. If a version is blocked, the newest admitted version is listed (Curation's compliant version selection) | Attestation checked by the server per request |
| Model or dataset | `lineage pull <artifact_id or source> <dir> --env prod` downloads from the store, verifies the hashes and writes `<dir>.lineage-attestation.json`. `LineageAutoModel.from_pretrained("hf:org/repo")` does the pull into the cache, then loads | `lineage.load()` (below) |
| MCP tool | Gateway (keep). Add a check of the attestation status per call (block, revoke, expiry), and response scanning (section 8.4) | Per call |
| Any artifact, in CI | `lineage load-check <dir> --env prod` (the same as `load()` without loading) | Exit code 1 on refuse |

**`lineage.load(path, env=...)` new rules:**
- (a) Requires an attestation (cached file, else `GET /attestations/...`).
- (b) Verifies the attestation signature with the **registry public key**, pinned in `~/.lineage/config.toml` or `LINEAGE_REGISTRY_PUBKEY`; it never comes from the artifact.
- (c) Outcome must be allow or allow-with-conditions for `env`. Expiry must not have passed. Online revocation check (`GET /passports/<id>/verify`). If the server is unreachable, accept a cached attestation younger than `offline_grace_hours` (policy; prod default 0, which means fail closed).
- (d) Re-hash every file against the attestation's `files`. Refuse missing, changed or extra files.
- (e) Pickle and remote-code rules as today.
- The creator passport is no longer used at load time; it is evidence inside the record.

Optional, phase 4: an HF-compatible endpoint (`HF_ENDPOINT=http://<host>`) implementing `GET /api/models/{repo}/revision/{rev}` and `GET /{repo}/resolve/{rev}/{file}`, with the `X-Repo-Commit`, `ETag` and `X-Linked-Size` headers that `huggingface_hub` expects. Only if phase 1 to 3 are done.

---

## 6. Graph and monitor

### 6.1 Graph
Nodes are registered artifacts plus ghost nodes (`status: unregistered`, `trust: unknown`, with the reference that created them). Edges come from:
- signed passport parents
- `fetched` `base_model` confirmed by weights (`kind: derived_from`)
- the identified weight parent
- passport `inputs` that match a registered digest (`kind: trained_on`)
- `sbom` components (`kind: built_with`, a ghost if not admitted)
- package `requires_dist` (`kind: depends_on`)
- federated clients to the global model (`kind: contributed_to`)

Blast radius and revoke walk all edge kinds. The dashboard draws ghosts dashed.

### 6.2 Monitor (scheduled)
- **Schedule:** a background thread in the server runs `tick()` every `LINEAGE_MONITOR_MINUTES` (default 60; demo 1). `POST /monitor/tick` stays.
- **A tick covers:**
  - (a) OSV for every package node, **including ghosts from SBOMs and dependencies** (keep plus extend).
  - (b) Hub drift for every `hf:` artifact: has the repo's commit for the tracked branch moved, or has the repo or file disappeared? This raises `WATCH.UPSTREAM.CHANGED` (info, an alert only; admitted bytes are pinned and unchanged) or `WATCH.UPSTREAM.REMOVED` (high, which re-decides).
  - (c) Expired approvals (keep).
  - (d) Expired attestations: re-issue if still allowed.
  - (e) Trusted-publisher key revoked: re-decide everything signed by that key.
  - (f) A policy version changed since the last decision: re-decide everything.
- **Every alert lists its blast radius**, ghosts included.

---

## 7. Identity, roles and keys

### 7.1 Tokens and roles
- New table `users(token_hash, name, email, roles)`. Roles are `requester`, `approver`, `admin`, `auditor`.
- `Authorization: Bearer <token>` on every mutating endpoint. Read endpoints need any valid token.
- `lineage_server/seed.py` creates demo users: `alice` (requester), `bob` (approver), `carol` (admin), `auditor`. Their tokens are printed once and written to `examples/demo_tokens.json`.
- **Separation of duties:** `POST /decisions/<id>/approve` refuses when `user == requester of that intake`, or when the user lacks the approver role. The approval record stores the user identity; it is no longer typed in.
- The dashboard gets a simple token login screen (paste a token, stored in sessionStorage) and shows who is signed in.

### 7.2 Trusted publishers (inside the signed policy)
Move trusted keys into the policy document, so changes need 2 of 3 role signatures (existing TUF flow):
```yaml
trusted_publishers:
  - name: "NVIDIA"
    key: "<ed25519 public key hex>"
    scope: ["hf:nvidia/*", "pypi:nvidia-*"]
  - name: "Apollo ML team"
    key: "..."
    scope: ["upload:*", "hf:apollo-health/*"]
revoked_keys: ["<key id>"]
```
- `LINEAGE_TRUSTED_KEYS` remains only as a dev bootstrap when no policy defines `trusted_publishers`, and logs a warning.
- Add `GET /trusted-publishers` and a read-only dashboard page.
- A key in `revoked_keys`, or a scope miss, means the passport is treated as unsigned, plus a finding.

### 7.3 Outbound key distribution
- `lineage keygen --publish` writes `.well-known/lineage-keys.json` (`[{name, key, scope}]`) for the company to host.
- `lineage verify --from https://example.com` fetches and pins it, warning on first use and on any change.

---

## 8. Detection changes

### 8.1 LLM reviewer backend (no Brev)
- `gpu_worker/reviewer_llm.py` already talks to an OpenAI-compatible endpoint (`LINEAGE_VLLM_URL`). Add `LINEAGE_LLM_BASE_URL` (default `https://integrate.api.nvidia.com/v1`), `LINEAGE_LLM_API_KEY` (from `NVIDIA_API_KEY`) and `LINEAGE_LLM_MODEL` (verify the exact id via `GET /v1/models`; expected `nvidia/nvidia-nemotron-nano-9b-v2`).
- Hosted endpoints may not support vLLM's `guided_json`. Use `response_format` with a JSON schema if accepted; otherwise ask for JSON, validate with pydantic, and retry once.
- Move the review orchestration so `lineage` can call it **without** running the GPU worker: reuse the prompts and grounding from `gpu_worker/reviewer_api.py` and `lineage/inspect/llm_review/`.
- Cache by request hash, as now. Keep the Brev path working when `LINEAGE_VLLM_URL` is set.
- Policy checks with Nemotron-Content-Safety-Reasoning-4B also go through the hosted API if available; otherwise emit NOT_RUN.

### 8.2 Packages
- **`package_taint.py`:** a wall-clock budget per package (`LINEAGE_TAINT_BUDGET_S`, default 20) and a step budget in `_bind`. On budget, return what was found plus `CHECK.NOT_RUN.TAINT_PARTIAL` (low). This fixes the timeouts on `black`, `datasets`, `torch`, `transformers`, `litellm`, `kubernetes` and `google-cloud-aiplatform`.
- **Big packages:** cap the files analysed by size order, and record the cap.
- **New rules:** atexit-registered writes or network; `sys.meta_path` or `sys.path_hooks` insertion; strings built in reverse or by join to form an import or call target; writing into `.git/hooks/`; a daemon thread that loops over a network call (beacon). Each needs a positive and a benign fixture in `tests/`.

### 8.3 Datasets (v2): `lineage/inspect/dataset_v2.py`
- **Formats:**
  - tables: csv, tsv, json, jsonl, parquet
  - prompt and response columns: `prompt`/`response`, `instruction`/`input`/`output`, `question`/`answer`
  - chat `messages` lists
- **Checks** (each returns findings with row references `file:line`):
  1. **Invisible and look-alike characters** in any text: zero-width, bidi controls, Unicode tag characters, mixed-script words. Report the rate, plus rows where they cluster with one label or one response.
  2. **Injected content in responses or texts:** instruction-override phrases, URLs, markdown images, code that executes (`curl|sh`, `eval(`, `os.system`), secrets (reuse the PII and secret regexes).
  3. **Trigger to behaviour (instruction data).** Find rare n-grams (n = 1 to 4) in prompts appearing in 0.1% to 10% of rows. For each, compare the response embeddings of rows with and without the n-gram. Flag when rows with it are much more similar to each other than rows without it, and far from the global response centroid: z-score of within-group similarity above 3 and centroid distance above the 95th percentile. That is the backdoor signature.
  4. **Embedding outliers per label, and spectral signature** (Tran et al. 2018). Embed with TF-IDF + TruncatedSVD (256 dimensions) by default, or the NVIDIA hosted embedding model if `LINEAGE_EMBED_MODEL` is set. For each label, project centred embeddings onto the top singular vector and flag the top 1.5 × expected-poison-rate rows by score. Report the score distribution's separation (bimodality coefficient).
  5. **kNN label disagreement:** a row whose label disagrees with at least 80% of its 10 nearest neighbours. This complements confident learning.
  6. **Keep:** exact and near duplicates, conflicting labels, card vs measured (card from `fetched`), imbalance, confident learning, trigger tokens.
  7. **Upstream diff,** when the dataset is `origin_verified` against a hub dataset at revision A and a previous admitted version or the hub's newer revision is known (or the user claims "modified from X"). Compute row-level diff by normalised-row hash: added, removed and changed rows, labels flipped (same text, different label), class balance drift (total variation distance), new tokens concentrated in added rows. The finding `DATA.DIFF.*` lists counts and examples.
- **Size:** stream up to `LINEAGE_DATASET_MAX_ROWS` (default 200,000). Beyond that, sample and say so (`CHECK.NOT_RUN.FULL_SCAN`, low).

### 8.4 Tools
- **Gateway response scanning:** run `tool_description` patterns (agent-addressed instructions, URLs, markdown images, invisible Unicode, encoded text) over every `tools/call` result. The policy chooses `block` (return an error to the agent) or `redact`, plus an alert. A new finding id `TOOL.OUTPUT.*` is logged against the tool's artifact.
- **Zero-width inside a directive:** raise to high when combined with an agent-addressed pattern (the final-set miss).

### 8.5 Templates and tokenizers
- Enable Jinja `loopcontrols` (`{% continue %}`, `{% break %}`) in the parser. This fixes the unparseable-template miss.
- **Role remap:** a template that renders a message with a role different from the message's own (for example user content under `system`) gives `MODEL.TEMPLATE.ROLE_REMAP` (high).
- **Hidden tool call:** literal `<tool_call>` or function-call markup emitted by the template, not taken from messages, gives high.
- **Tokenizer:** compare the `special` flag of added tokens (the final-set miss).

### 8.6 Federated learning gate (new): `lineage/federated/`
- **API:** `POST /fl/rounds` with `{round_id, global_model_id, updates: [{client_id, update_blob_sha256 or inline npz}], secure_agg: bool}`, then `GET /fl/rounds/<id>`, `GET /fl/clients`.
- **Per round, for each client update (flattened delta):**
  - L2 norm
  - cosine distance to the coordinate-wise median update
  - Krum score (sum of squared distances to the n − f − 2 nearest updates, with f from the policy)
  - sign agreement with the median
- Each score becomes a robust z-score (median and MAD). A client is flagged if any z-score is above 3, or the norm is above `fl.max_norm`.
- **Aggregators:** FedAvg, coordinate median, trimmed mean (β = 0.1), Multi-Krum, and **trust-weighted mean** (default).
- **Client trust score:** start at 1.0. Multiply by 0.5 when flagged, add 0.05 per clean round (cap 1.0). Below 0.3 the client is quarantined: excluded, with an alert and reasons. Clients are graph nodes (`kind: contributed_to` the round's global model), so revoking a client flags the global models it fed.
- **Secure aggregation:** a demo of pairwise additive masks from a seeded key per client pair; the server recovers only the sum. Clients submit a **norm bound proof surrogate**: the norm is computed client-side, sent in the clear and checked against the bound, and its honesty is checked after unmasking by comparing the sum's norm. Document honestly that per-client anomaly scores need either unmasked updates or a trusted aggregator, and that our gate runs in "trusted aggregator" mode by default.
- **Simulation and benchmark** (`bench/fl_bench.py`, CPU, numpy and scikit-learn only):
  - Data: `sklearn.datasets.load_digits`, a softmax regression model, 20 clients with non-IID Dirichlet(0.5) splits, 30 rounds.
  - Attackers: 2, 4 and 6 clients.
  - Attacks: label flip, sign flip, scaling ×10 (model replacement), backdoor (a 2×2 pixel trigger to class 0), and "a little is enough" (mean − 1.5σ per coordinate).
  - Report per attack: flag precision and recall over rounds, clean accuracy, and backdoor success rate, for FedAvg vs median vs Multi-Krum vs trust-weighted.
  - Output to `bench/results_fl.md`.
- **Dashboard:** a Federated page with a rounds table, a clients table (trust score, flags) and a per-round score chart.

### 8.7 Datasets benchmark
`bench/data_bench.py`:
- **Clean bases:** the scikit-learn `20newsgroups` subset if it can be downloaded, else a generated corpus. Also a generated instruction set of 2,000 prompt-response pairs from templates.
- **Eight attacks at 1, 5 and 10%:**
  - random label flip
  - targeted flip
  - rare-word trigger with a forced label
  - sentence trigger
  - invisible-character trigger
  - instruction backdoor (trigger phrase to a fixed malicious response)
  - injected instructions or links in responses
  - duplicated poison
- **Report** to `bench/results_data.md`:
  - row-level recall and precision per attack and rate
  - dataset-level detection (flagged at medium or higher)
  - false alarms on 5 clean datasets
- Keep generation seeded.

---

## 9. Dashboard changes
- **Login** with a token. Show the user and roles.
- **Intake:**
  - a file picker, or a source (`hf:`, `hf-dataset:`, `pypi:`)
  - a claimed origin field
  - an optional claims form
  - environment
  - live stages S0 to S7, with every `CHECK.NOT_RUN` shown in amber
  - the fact table showing each fact's provenance class (computed, fetched, signed, declared) with its source
- **Artifact page:** the decision, the attestation (status, expiry), the facts, the findings grouped by stage, the creator passport evidence, and the graph.
- **Approvals:** the approver is the logged-in user. The button is disabled with a reason for self-approval or a missing role.
- **Graph:** edge kinds coloured, ghosts dashed, blast radius highlight.
- **New pages:** Trusted publishers (read-only), Federated, Monitor (last tick, next tick, alerts).

---

## 10. Remove or rename
- Trust levels `declared`, `inspected` and `attested`.
- `needs_deep` tiering.
- `lineage.meta.json` as an input.
- The `--trust` option on `sign` and `run`.
- The free-text `ref` in `POST /intake`, kept only behind `LINEAGE_DEV_LOCAL_PATHS`.
- `lineage.load()` using the creator passport.
- Any "Shield" mentions in the UI. Shield is future work.

---

## 11. Tests and acceptance

### 11.1 Unit and integration tests (must exist and pass)
1. **Facts:** a declared publisher never satisfies the allow list. A declared `released_at` never clears cooldown.
2. **Origin:**
   - an upload matching a fake hub tree gives `origin_verified`
   - one changed byte gives `PROV.ORIGIN.MODIFIED` and a hard block in prod
   - no claim gives `unknown` + `UNCLAIMED`
3. **Signature scope:** a trusted key signing outside its scope gives `SCOPE_MISMATCH` and the passport is treated as unsigned.
4. **No silent skip:** for every artifact type, with the network and GPU off, every registered check either emits findings or a `CHECK.NOT_RUN.*`. Parametrise over the inspector registry.
5. **Load:**
   - a blocked artifact refuses even with a valid creator passport
   - revoked refuses
   - expired attestation refuses
   - a server down in prod refuses (grace 0)
   - one changed byte refuses
6. **Package index:** `pip download --index-url` gets an admitted wheel, and gets nothing for a blocked one. Pin hashes are present.
7. **Graph:**
   - SBOM components appear as ghost nodes
   - an OSV advisory on a ghost package flags the model trained with it
   - revoking a client flags its global model
8. **Roles:** self-approval returns 403; a requester approving returns 403; the approver identity is recorded.
9. **Monitor:** the scheduled tick runs; hub drift on a fake hub gives an alert; a policy change re-decides.
10. **Gateway:** an injected instruction in a tool response is blocked and logged.
11. **Federated:** under the scaling attack, trust-weighted aggregation keeps clean accuracy within 3 points of no-attack, and FedAvg drops by more than 10.
12. **Dataset v2:** for the instruction backdoor at 5%, row recall is at least 0.8 with precision at least 0.5. Clean sets raise no high finding.

### 11.2 Fake hub for tests and bench
`tests/fakehub.py`: a small FastAPI app serving `/api/models/...`, `/api/datasets/...`, `/{repo}/resolve/...` and `pypi/<name>/<ver>/json` from fixture folders. Fetchers take a `base_url` setting so tests and the bench never need the internet.

### 11.3 Re-run the benchmarks (phase 5)
- `bench/run_bench.py` static-only, plus the reviewer through the hosted API if `NVIDIA_API_KEY` is set. Write `bench/results_after_refactor.md`.
- Never overwrite `results_final.md`. Report the **frozen final numbers and the after-refactor numbers side by side**, and state that after-refactor numbers were measured on sets the fixes were written with knowledge of.

---

## 12. Phases, order and cut lines

| Phase | Tasks | Must be true at the end | Rough time |
|---|---|---|---|
| **1 Trust core** | R1.1 trust enum and penalties · R1.2 facts with provenance (3.1) · R1.3 remove meta.json (3.2) · R1.4 NOT_RUN everywhere and remove tiering (4.3) · R1.5 trusted publishers in policy with scope (7.2) · R1.6 fake hub (11.2) | Tests 1, 3, 4 pass. Demo runs with the new trust words | 2 h |
| **2 Intake and enforcement** | R2.1 store (3.5) · R2.2 uploads and the new `POST /intake` (4.1) · R2.3 fetchers `hf:`, `hf-dataset:`, `pypi:` (S0) · R2.4 origin check (S2a) · R2.5 decision attestation (3.4) · R2.6 new `lineage.load` and `lineage pull` (5) · R2.7 `/simple` index (5) · R2.8 tokens and roles (7.1) · R2.9 dashboard Intake, Approvals and login (9) | Tests 2, 5, 6, 8 pass. In the demo, a modified Hugging Face file is blocked, a blocked artifact won't load, and pip installs only admitted wheels | 3 h |
| **3 New detection** | R3.1 hosted LLM backend and precise mode (8.1, S5) · R3.2 dataset v2 and its benchmark (8.3, 8.7) · R3.3 federated gate and its benchmark (8.6) · R3.4 graph edges and ghosts (6.1) · R3.5 scheduled monitor (6.2) | Tests 7, 9, 11, 12 pass. `results_data.md` and `results_fl.md` exist | 3 h |
| **4 Fixes (if time)** | R4.1 taint budget · R4.2 new package rules · R4.3 template, tokenizer and gateway output fixes · R4.4 parent fetch by range request · R4.5 HF endpoint · R4.6 well-known keys | Test 10 passes | 2 h |
| **5 Always** | R5.1 re-run the benchmarks · R5.2 rewrite `examples/run_dashboard_demo.sh` (section 13) · R5.3 README "How a company uses Lineage" (inbound and outbound) · R5.4 update `DECISIONS.md` | Demo script runs end to end with no GPU | 1 h |

**Cut lines:**
- If it's 21:00 and phase 3 is not finished, skip phase 4 and do phase 5.
- If phase 2 is not finished by 19:00, drop R2.9's claims form and the HF endpoint; keep uploads and the picker.

---

## 13. Demo script v2 (what the video shows; every step must work without a GPU)

1. Log in as alice (requester).
2. **Inbound, fetched:**
   - Intake `hf:<small public model>@<sha>` into prod. Facts shown as fetched; trust `origin_verified`.
   - Quarantined by policy (`model:prod` needs a human).
   - Bob approves; alice's self-approval is refused.
   - `lineage pull` then `lineage.load()` succeeds.
3. **Inbound, tampered upload:** download the same model, change one tensor byte, and upload it with claimed origin `<repo>@<sha>`. The result is `PROV.ORIGIN.MODIFIED`, a block, and the dashboard lists the changed file.
4. **Inbound, no claim:** upload a fine-tune with no claim. Trust `unknown`; the suggested origin comes from hints; the parent is identified from the weights; the template backdoor is found. Block.
5. **Package:** `pip install --index-url http://localhost:8000/simple/ litellm==<bad fixture>` fails; the admitted version installs.
6. **Dataset:** upload an instruction dataset with a 5% trigger backdoor. The trigger and the poisoned rows are listed, and the diff against the upstream fixture shows the injected rows.
7. **Federated:** run 10 rounds with 4 attackers. Trust scores fall and the clients are quarantined; the accuracy chart compares FedAvg and Lineage.
8. **MCP tool:** a tool returns an injected instruction, and the gateway blocks the response.
9. **Monitor:**
   - An advisory lands for a package in the training SBOM, and the model trained with it is flagged (blast radius through a ghost node).
   - Revoke the dataset, and its model and fine-tune are blocked.
10. **Outbound:**
    - The Apollo team runs `lineage run` and `lineage sign`, and publishes `.well-known/lineage-keys.json`.
    - A customer server with the Apollo key (scope `hf:apollo-health/*`) verifies it with trust `recorded`.
    - The same passport claiming `hf:nvidia/x` gets `SCOPE_MISMATCH`.

---

## 14. Questions this refactor must let us answer (keep `docs/PANEL_QA.md` updated with the final answer and evidence path)

| Question | Answer after the refactor | Evidence |
|---|---|---|
| I uploaded a file. How do you know which repo it came from? | The uploader names a claimed origin, and Lineage compares every file hash with what that repo published at a pinned revision, using the hub's API. No claim means trust `unknown`. Hints are shown but never trusted | S2a, test 2, demo step 3 |
| Is any metadata user-editable? | Every fact carries its provenance class. Declared facts never raise trust or clear a check | 3.1, test 1 |
| Can someone edit a passport? | The signature covers every byte. Re-signing needs a key on the trusted list, and that key's scope must cover the source | S2b, test 3 |
| Where does the public key come from? | From the signed policy's trusted-publisher list, which needs 2 of 3 roles to change. The client pins the registry key | 7.2, 5 |
| What does `lineage.load()` trust? | Only a registry-signed attestation for this environment, re-checked against revocation, plus a re-hash. Fail closed in prod | 5, test 5 |
| How does a package get controlled? | pip installs only through Lineage's index, which serves admitted wheels pinned by hash | 5, test 6 |
| Is your graph complete? Monitor and revoke depend on it | Every reference becomes a node: unknown ones as ghosts. SBOMs, dependencies, data inputs and federated clients are edges. The monitor runs on a schedule over all of them | 6, test 7 |
| What happens when a check cannot run? | It is recorded as NOT_RUN, and the policy decides its cost per environment. Never a silent pass | 4.3, test 4 |
| How do you detect dataset poisoning? | Nine checks (8.3), benchmark at 1, 5 and 10% | `results_data.md` |
| Federated learning? | Update scores, robust aggregation, client trust over rounds, secure-aggregation demo, benchmark across 5 attacks | `results_fl.md` |
| Backdoor in a model with no known base? | Template, tokenizer and code checks; the parent is identified from the weights against a fetched base. A weight-only backdoor with no base is an open problem: such a model cannot reach prod without a human, and the cost of the unrun check is explicit | S4, 4.3 |
| Who approved this, and could they approve their own request? | The authenticated approver is in the log; self-approval is refused | 7.1, test 8 |
| What does the LLM add over rules? | It judges whether a capability fits the artifact's stated purpose. Only claims backed by a rule, or a purpose mismatch, add risk | S5 |
| Why not just use Trivy or JFrog? | They cover known CVEs, package code and pickle formats. We reuse OSV and the same proxy pattern. We add lineage across data, model, fine-tune and package; fine-tune vs base; templates and tokenizers; dataset poisoning; MCP pinning; federated updates | `docs/PRIOR_ART.md` |
| What can't you do? | Weight-only backdoors with no base; stolen trusted keys (caught only by inspection and scope); non-text datasets; runtime prompt filtering (Shield) | README limits |
