# How an artifact moves through Lineage

Written from the code and from real runs (the 10-step demo scenario, `scripts/check_matrix.py`), not from the design documents. Where something is not true or not done, it says so. Per-check detail with source snippets: `CHECKS_REFERENCE.md`. Scoring: `review_audit/risk_scoring_reference.md`.

## 0. Words, so the rest is unambiguous

| Word | Meaning | Where it comes from |
|---|---|---|
| **Artifact** | A model, dataset, package, MCP tool or agent definition | You pick the **Type** in the intake form. **The type is not detected**; a wrong choice runs the wrong checks. |
| **Fact** | One piece of information about the artifact, with a class: `signed` (a verified passport says so), `fetched` (the hub told Lineage), `computed` (Lineage measured it), `declared` (a person or a file inside the artifact says so) | `lineage/schemas/fact.py` |
| **Creator passport** | A JSON file (`passport.json` or `<file>.passport.json`) that the *publisher* ships with the artifact, signed with their private key. It lists file hashes, parents, and what the publisher says about it | Written by `lineage sign` or `lineage run --key` |
| **Registry passport** | The record **Lineage** creates at S6 after inspecting the bytes: file hashes, tensor hashes, parents, trust level, risk score, digest of the findings. Signed with the **registry's** key | `pipeline.py::_build_passport` |
| **Attestation** | A short signed statement from the registry: "artifact X, with exactly these file hashes, is `allow` for environment E until time T". It is what `pull`, `load()`, the pip index and the gateway trust | `lineage_server/attest.py` |
| **Decision** | allow / allow with conditions / quarantine / block, with reasons and a risk score | `policy/engine.py::decide` |

### Identifiers (all of them)

| Looks like | Is | Stable? |
|---|---|---|
| `lp:84732c31…` (64 hex) | **The artifact id**: the SHA-256 of the registry passport. The passport contains the issue time, so **ingesting the same bytes twice gives two different ids** (verified: the same hub model gave `lp:4f22…` then `lp:91dd…`) | per intake |
| `triage-base@67d0bdf167ed` | **Name and version**. For a hub fetch: the repo name and the first 12 characters of the commit. For an upload: the folder or file name (an archive `tiny.zip` is named `tiny`), unless a shipped passport or a `lineage.meta.json` says otherwise, version `0.0.0` | shown the same everywhere now (the Approvals page used to show whatever you typed) |
| Merkle root (64 hex) | Identifies the *content*: hash over `(file name, file sha256)` pairs. Two intakes of identical bytes share it (`INTAKE.DIGEST.KNOWN`) | by content |
| `key_id` (16 hex) | First 16 hex characters of the SHA-256 of a public key | by key |
| Job id (12 hex) | One intake run; used in `/intake/<job>` and the event stream | per run |

Use the artifact id when you need to be exact (`lineage pull lp:… ./dest`), name@version when you read it.

## 1. Four ways in

| Way | You give | What Lineage does | Origin check | Trust it can reach |
|---|---|---|---|---|
| **From a hub** | `hf:org/name[@rev]` (model), `hf-dataset:org/name[@rev]`, `pypi:name==1.0` | Fetches the bytes **itself** in S0 | none needed: it fetched them, so the origin is verified and hub metadata (release date, licence, publisher, card base model) is `fetched` | `origin_verified`; `signed`/`recorded` if the repo also ships a passport signed by a trusted key |
| **Upload + claimed origin** | file or archive, plus `hf:org/name@<commit sha>` | Compares **every file's SHA-256** with the hash the hub published for that revision | all match → `origin_verified`; any difference → `PROV.ORIGIN.MODIFIED` (critical, **hard block in staging and prod**); hub unreachable or repo unknown → `PROV.ORIGIN.UNVERIFIABLE` (high) | `origin_verified` or lower |
| **Upload, no claim** | file or archive | Inspects it | none: `PROV.ORIGIN.UNCLAIMED` (medium), trust stays `unknown` (+15 risk) | `unknown`, or `signed` with a passport |
| **Upload + passport inside** | any of the above, with `passport.json` in the folder | Verifies the signature (section 3) | n/a | `signed` / `recorded` |

Fixed this pass: `hf:` means a **model** repo and `hf-dataset:` a **dataset** repo on Hugging Face. Typing `hf:nvidia/simready-assets` for a dataset asked the models API and answered HTTP 404 ("Did not run: acquire"; "claimed origin could not be checked"). The server now takes the prefix from the artifact Type (`fetch.normalise_source`).

### The intake form, field by field

| Field | Required | Used for | Never used for |
|---|---|---|---|
| Type | yes | choosing which checkers run | |
| Source (hub) **or** File | one | the bytes | |
| Environment | yes | which thresholds and which unrun-check prices apply (dev / staging / prod) | |
| Claimed origin (uploads only) | no | comparing every file's hash with the hub | |
| Name, Version (uploads) | no | the catalogue name and version (declared). Without them: the file/folder name and `0.0.0` | trust |
| Publisher | no | allow/block lists and look-alike check | trust. It is a **name, not a key**. |
| Base model | no | `hub_parent` fetches that repo's embedding rows and compares with your weights; a mismatch is `MODEL.PARENT.CLAIM_MISMATCH`. **Enter a Hugging Face repo id** (`org/name`), not a passport id | the lineage graph edge (that needs a trusted source) |
| Licence | no | allow-list check (declared licences never count as allowed) | |
| Released at | no | shown | clearing the cooldown (needs a hub or signed date) |
| What it is for | no | stated purpose for the AI code review | |

All seven are stored as `declared` facts. They can add risk; they can never lower it.

**The publisher key is not entered by the uploader.** The organisation's administrator lists trusted publishers in the policy (`trusted_publishers`: name, Ed25519 public key, `scope` patterns such as `hf:apollo-health/*` and `upload:*`). Keys can also be published at `/.well-known/lineage-keys.json` (`lineage keygen --publish`). An uploader cannot supply a key; a passport signed by an unlisted key is treated as unsigned (`PROV.SIGNATURE.UNTRUSTED_KEY`, medium).

## 2. The eight stages (`pipeline.py::run_intake`)

Strictly in order; every stage emits real `started` and `completed` events (the dashboard shows them as they arrive; for a fresh run it replays them 380 ms apart, which only slows the display).

| Stage | Does | Output |
|---|---|---|
| **S0 Acquire** | Hub sources are fetched into a work folder (`LINEAGE_FETCH_DIR`). Uploaded archives are extracted safely (no `..`, links, bombs, > 10,000 files); wheels are unpacked for inspection and the wheel is kept for the pip index | a folder or file on disk. Failure: `CHECK.NOT_RUN.ACQUIRE` (critical, hard block) |
| **S1 Identify** | Hashes every file (SHA-256), builds the Merkle root, hashes each tensor of `.safetensors`, copies every file into the content-addressed store (`$LINEAGE_STORE/blobs/sha256/…`), reads the card, name, version, parents. **No passport yet**; the registry passport is built at S6 | `ctx.files`, `ctx.tensors`, stored bytes |
| **S2 Provenance** | origin vs hub hashes, publisher lists, creator passport, parents, licence, release age, package name/repo checks | findings + facts |
| **S3 Static inspection** | rules and parsers over the files, nothing run | findings |
| **S4 Deep inspection** | parent from weights, GPU checks, dataset poisoning and diff, package dependencies | findings |
| **S5 LLM review** | AI review of code or the card | findings |
| **S6 Decide** | adds up risk, applies the policy, signs the registry passport | decision |
| **S7 Admit** | writes passport, findings, decision to the database in one transaction. **Every outcome is recorded**; only allow / allow-with-conditions artifacts are later *served* | rows |

"Decide" and "Admit" differ only in this: Decide computes the verdict; Admit records it. A blocked artifact is recorded too (so it can be reported and revoked), but nothing serves it.

### Base model: what is compared, and how

1. You (or the hub card) name a base model → fact `base_model` (class `declared`, or `fetched`/`signed` if it came from the hub or a verified passport).
2. `hub_parent` (S4) fetches from the hub: base `config.json`, tokenizer files, the safetensors header and the **first 512 rows of the embedding matrix** (HTTP range requests; the whole base is never downloaded). It compares the child's matching rows by cosine similarity: ≥ 0.90 → `MODEL.PARENT.IDENTIFIED`; below → `MODEL.PARENT.CLAIM_MISMATCH` (high). Different hidden size / vocab → similarity 0.
3. `local_parent_diff` (S4) separately compares the child with **every admitted model stored on this machine**, with no claim needed, by per-tensor relative L2 distance. A match adds that model to the artifact's parents and reports which tensors changed. If it contradicts the declared base: `MODEL.PARENT.CLAIM_MISMATCH` (medium).
4. If a parent is found either way, the child's tokenizer and chat template are diffed against the parent's.

Limits: the hub comparison uses embedding rows only; fine-tunes that freeze embeddings still match, an unrelated model with the same shape does not.

## 3. How a creator passport and its key are checked (S2, `signed_passport`)

The check runs for any artifact, hub-fetched or uploaded, **if a passport file is in the folder** (for hub fetches `.json` files are downloaded, so `passport.json` in the repo is seen).

1. Find the file: `<artifact>.passport.json`, else `passport.json` inside the folder, else the first `*.passport.json`. It is not hashed as part of the artifact.
2. Look up `key_id` in the policy's `trusted_publishers`. Revoked key → `PROV.SIGNATURE.REVOKED_KEY`; not listed → `UNTRUSTED_KEY`; both are "treated as unsigned", not a block.
3. Verify the Ed25519 signature over the canonical JSON of the passport. Fails → `PROV.SIGNATURE.INVALID` (critical, **hard block**).
4. The key's `scope` must cover the claimed source and where the bytes came from (`hf:org/*`, `upload:*`). Otherwise `SCOPE_MISMATCH` (high), unsigned.
5. Expiry; then every file hash in the passport must equal the hash Lineage computed (`INTEGRITY.HASH_MISMATCH`, critical, hard block); files not in the passport: `INTEGRITY.UNPINNED_FILE`.
6. Only if everything passes do the passport's facts become `signed` and trust reaches `signed` (or `recorded`, if the passport is a `lineage run` record with inputs and package list).

Then the publisher allow list (`PROV.PUBLISHER.UNLISTED`, low, and look-alikes `PROV.LOOKALIKE.PUBLISHER`, high) runs on the publisher name from the best trusted fact.

## 4. How files are found (no intelligence, fixed names)

Nothing here guesses. Files are found by **fixed names and suffixes** (`lineage/intake/inspectors.py`, the scanners, `lineage/catalog.py` lists each):

| Used for | Looked up as |
|---|---|
| Model/dataset card | first existing of `README.md`, `MODEL_CARD.md`, `DATASET_CARD.md`, `README` (exact, case-sensitive) |
| Pickle risk | suffix `.pkl .pickle .pt .pth .bin .ckpt .joblib` (a `.bin` is skipped unless it looks like a pickle) |
| Weights | `*.safetensors` (hashed per tensor; parent comparison reads them) |
| Config risk | `config.json`, `tokenizer_config.json`, `preprocessor_config.json`, `processor_config.json`, `generation_config.json`, `adapter_config.json` |
| Tokenizer | `tokenizer.json`, `tokenizer_config.json`, `vocab.json`, `merges.txt`, `tokenizer.model`, `spiece.model` |
| Chat template | the `chat_template` field of `tokenizer_config.json`, `chat_template.json`, `processor_config.json`, and any `*.jinja` |
| Dataset rows | `.csv .tsv .json .jsonl .ndjson` (and `.parquet` when pyarrow is installed). The text column is the first of `text, sentence, content, prompt, input, review, body, message, question, instruction`; prompt/response pairs are recognised as `prompt/response, instruction/output, question/answer, prompt/completion, input/output`, or a `messages` list |
| Package code | every `*.py`, `*.pth`, `setup.py`/`hatch_build.py`/… , `sitecustomize.py`, npm lifecycle scripts |
| Tool | `manifest.json` (required: no manifest is `TOOL.MANIFEST.MISSING`, high); `agent.json` for agents |
| Package metadata | for `pypi:` sources, PyPI's JSON API; for wheels, the `*.dist-info` folder name |
| Sidecars | `passport.json`, `*.passport.json`, `lineage.meta.json` (its fields become `declared` facts) |

A card with another name (`Model Card.md`) is not read. Files outside these rules are hashed and stored but inspected by no content check.

## 5. Are the checks really running? (evidence)

* `scripts/check_matrix.py` runs the real `run_to_decision` offline on inert fixtures and records which check fired. Last run: **20 of the catalogued checks fired** on 8 fixtures (clean/pickle/remote-code/backdoored-template models, malicious package, poisoned tool, clean and poisoned dataset); results in `docs/check_matrix.json`, and each check's section in `CHECKS_REFERENCE.md` lists where it fired. The clean dataset produced **no** poisoning findings; the 5% trigger dataset produced `DATA.TRIGGER.BEHAVIOUR`.
* The 10-step demo (`examples/demo_scenario.sh`) was run end to end against a fresh database after the changes in this pass: same outcomes (tampered copy block 100, fine-tune with hidden template block 100, clean fetched model quarantine 66 → approved by a different person → pulled and loaded, bad package block 100 with pip resolving to 1.4.0, poisoned dataset block 100, tool quarantine 52, trained model quarantine 22).
* **Not exercised for real in this environment:** the GPU worker checks (spectral, behaviour, notary: no torch/GPU here; `tests/test_gpu_*.py` are not collected without torch), a live LLM call (no API key), a real Hugging Face model (`tests/test_real_hub.py` is off unless `LINEAGE_TEST_REAL_HUB=1`). Their logic is tested with fakes (`tests/test_intake_pipeline.py`, `test_hosted_reviewer.py`, `test_inspect_llm_review.py`). **To run them for real**, start the Brev GPU machine and run: `uv run pytest tests/test_gpu_app.py tests/test_gpu_weights.py tests/test_gpu_behaviour_notary.py tests/test_gpu_reviewer.py -q`, start the worker (`uv run uvicorn gpu_worker.app:app --port 8800`, `LINEAGE_GPU_TOKEN` if exposed) and the reviewer (`scripts/serve_reviewer.sh`), then run intake with `LINEAGE_GPU_URL` set. The worker reads model **paths from its own disk**, so the server and worker must share the store/fetch folder.

## 6. LLM review: exactly what goes in

Model: `nvidia/nemotron-3.5-lightning-30b-a3b` at `https://integrate.api.nvidia.com/v1` (override `LINEAGE_LLM_MODEL`, `LINEAGE_LLM_BASE_URL`), key `NVIDIA_API_KEY` or `LINEAGE_LLM_API_KEY`; or a self-hosted vLLM (`LINEAGE_VLLM_URL`, `nvidia/NVIDIA-Nemotron-Nano-9B-v2`). Temperature 0, thinking off, JSON-schema constrained output. Without a key and without a worker the stage says **did not run** and the policy prices it.

**Code review (packages, tools)** sends one request containing:
1. *Stated purpose* (≤ 4000 chars): the trusted description (PyPI summary / hub card), else the one you typed, else the manifest description, else the name.
2. *Capabilities*: names such as `network, subprocess, startup_hook` found by the AST scanner.
3. *Code slices*: for each of (a) data-flow slices from the taint analysis, (b) ±2/+4 lines around each start-up or install hook, (c) ±3 lines around **every file:line cited by any earlier non-info finding**, (d) ±3 lines around each capability hit (filesystem hits last, they are most common) — at most **20 slices**, comments replaced by `# [comment removed]`, numbered lines, ≤ 24,000 characters. The "20" is a cap, not a target.
4. *Diff vs the previous release* (≤ 20,000 chars) when one exists.

The reviewer then runs *prosecutor* (always). Only if it makes a claim that quotes a real line, a *defender* and a *judge* call follow. A claim has `file, line, api, severity, text`. Lineage re-checks each claim against the real file: the file exists, the line is in range, it is not a comment, and the `api` text appears on that line. Others are dropped (`LLM.REVIEW.UNGROUNDED_DROPPED`). By default a grounded claim scores only if a rule-based finding is within 2 lines of it or the capability does not fit the stated purpose. It can add points; it cannot lower any.

**Card review (models, datasets)** sends the card text plus a summary of the earlier findings (their ids and severities), file count and declared base model. It does **not** send weights, dataset rows or code. Claims cite `card.md` or `measured.json`. **Bug fixed this pass:** these names were checked against the real files and so every card claim was dropped; they are now checked against exactly what the reviewer was shown (test added).

The model never sees: weights, dataset rows, files that nothing flagged, or anything outside the slices.

## 7. Decision and policy

`decide` order: hard blocks first (cannot be approved away) → cooldown, vulnerability limit, identity, PII, licence, trust minimum, risk threshold, human approval → a live approval turns the *soft* reasons into `allow_with_conditions`.

| Policy field (`examples/policy.org.yaml`) | Controls |
|---|---|
| `environments` (dev/staging/prod: `min_trust`, `max_risk`) | the allow limit and the minimum trust |
| `thresholds` (allow, quarantine) | allow limit = min(allow, env.max_risk); above `quarantine` = block |
| `publishers` allow / block | publisher lists (glob patterns for block) |
| `licences_allowed`, `data.pii_allowed`, `model_files.allow_pickle` | licence / PII / pickle rules |
| `cooldown_days` per type, `max_vuln_severity` per environment | release-age and vulnerability rules |
| `banned_capabilities`, `require_human_approval` (`tool`, `model:prod`) | hard block on capabilities; who must approve |
| `unrun_checks` per check per environment | what "did not run" costs |
| `trusted_publishers`, `revoked_keys` | whose passports count |
| `exceptions`, `compliance_map`, `fl`, `offline_grace_hours` | pre-approved exceptions; control tags; federated gate; offline grace |

Changes require a policy update signed by 2 of 3 role keys (`python -m lineage_server.tuf`); the dashboard Policy page shows the policy and can submit a signed update but never signs.

**Not configurable (hard-coded):** severity weights (`risk.py`: 0/5/12/25/40), the trust penalties (15/5/0/0), which checks exist and what triggers each, the AI model. **Missing and worth adding later:** per-artifact-type thresholds, per-check severity overrides, per-publisher scoring. Whether "everything required" is there: for the claims we make, yes; these are enhancements, not gaps in what is claimed.

## 8. After approval: what a developer does

You submit a model, a different person (role *approver*) approves it (you cannot approve your own; this is enforced by the server). It appears in the Catalogue. Then:

| You want to | Do |
|---|---|
| Get the approved bytes | `lineage pull <name or lp:id> ./models/x -e prod --pin` (first time pins the registry's public key). Downloads the registry's stored copy, verifies the attestation and every hash, writes `./models/x.lineage-attestation.json` beside it |
| Check a copy you already have | `lineage load-check ./models/x -e prod` (re-hash, attestation signature, expiry, **live** revocation and current decision) |
| Load it in code | `lineage.load("./models/x", env="prod")` (refuses unless the check above passes; then loads) or `LineageAutoModel.from_pretrained("hf:org/name")` (pulls and verifies) |
| Install a package | `pip install --index-url http://user:<token>@host/simple/ name`: only admitted versions are listed; a blocked version simply does not exist, pip resolves the newest admitted one |
| Use Hugging Face tooling | set `HF_ENDPOINT=http://host` and `HF_TOKEN=<token>`; only admitted models resolve |
| Use an MCP tool | go through the gateway (`mcp_gateway`): it pins description and code hashes, re-checks every call, hides a tool that changed or was revoked |

Honest limit: enforcement exists **only on those paths**. Someone who downloads directly from huggingface.co or pypi.org bypasses Lineage; the intended deployment blocks those at the network.

The registry passport is a JSON file, but its value is the signature plus the hashes it pins: it is what lets anyone later prove *which exact bytes* were inspected and what was found, and the attestation derived from it is what loaders refuse to run without. On its own, unverified, it is just a JSON file; that is why `pull` and `load` verify it against a key you pinned.

## 9. Lineage graph and training

* Nodes are artifacts in the registry. Edges: `derived_from` (a parent in a verified passport, or a parent identified from weights), `trained_on` / `built_with` (inputs and package list recorded by `lineage run` in a **verified** passport), `depends_on` (a package's Requires-Dist). Anything referenced but never admitted appears as a dashed "unregistered" node, grouped when there are many (SBOM packages).
* **`lineage run -- python train.py` is the capture mechanism.** It injects an audit hook into the child Python process, records every file opened (reads = inputs, hashed; writes = outputs), runs `pip freeze` (the package list), and writes a creator passport beside each output. Optionally `--key` signs it. There is **no** `lineage.import()`; nothing needs to change in `train.py`.
* **Parents are found three ways:** `--parent lp:…` (explicit); an input whose hash is pinned by a sibling `passport.json`/`<file>.passport.json`; and, **new this pass**, an input whose bytes are exactly a file of an artifact fetched with `lineage pull` (its attestation sits beside the folder). Before this pass a pulled artifact left no passport, so a training run that used it was not linked; now it is (test added).
* When the trained model is submitted, its shipped passport is verified like any creator passport (section 3). If the signing key is trusted and every hash matches, the recorded inputs and packages become graph edges; if not, they stay `declared` and are not used. The passport is machine-written (`lineage run` never claims a trust level; trust is decided by the verifier), but it is only as strong as the signing key, and a process can lie to the audit hook by reading data some other way (for example over a network socket), which is not recorded. The graph says "only what passed through Lineage or `lineage run`".
* Other artifacts used (datasets, tools) are recorded automatically **if read as files** during the run. There is no manual "declare I also used X" field, apart from the base-model claim and `--parent`.

## 10. Benchmarks: how far to trust them

Corpora are in `bench/` (inert fixtures built by `bench/build_*.py`; real PyPI wheels and 50 hub chat templates fetched by `bench/fetch_*.py`). Reported (`bench/results_final.md`): on the unseen final set the full system detected 70% of malicious items (28/40, 95% CI 55–82%) with 5% false alarms; on the set the rules were tuned on, 100%; on the first corpus, 91%. After the refactor the team measured 88% (static) and 90% (with the hosted reviewer), but those fixes were written after seeing the misses, so they are an **upper bound**, not an unseen result. Datasets: 5–10% poisoning is caught; 1% mostly is not. LoRA backdoor detection: AUROC 0.81 / 0.78 (small bank, GPU, not re-run since the refactor). Real-package false-alarm rate was measured at 5–6% on 399 PyPI wheels before the latest rule changes. What the benchmark is not: a measurement of detection on attacks in the wild, or of the post-refactor system on data it has not been tuned on.

## 11. What changed in this pass

| Change | Where | Test |
|---|---|---|
| Findings show a plain name, what the check looks for, how, what it read, and the kind of check; codes moved to a footnote | `lineage/catalog.py`, `GET /catalog/checks`, `dashboard/src/lib/catalog.ts`, `pages/intake/panels.tsx` | `tests/test_catalog.py` (every finding id has an entry; every entry points at real code) |
| Intake claim fields explain themselves; "publisher is not a key" stated | `pages/Intake.tsx` | |
| Same name@version + short id on Approvals as everywhere else | `pages/Approvals.tsx` | |
| Card-review claims were all dropped (checked against files the reviewer never saw) | `inspectors.py::claims_to_findings`, `_card_slices` | `tests/test_intake_pipeline.py::test_card_claims_citing_the_reviewers_own_file_names_are_grounded` |
| `hf:` for a dataset gave HTTP 404 | `fetch.normalise_source`, `routes/intake.py` | `tests/test_intake_page_api.py` |
| `lineage run` now links inputs pulled with `lineage pull` | `lineage/run.py::_attested_parent` | `tests/track_a/test_run.py` |
| "Verify passport" no longer says hashes were verified | `pages/ArtifactDetail.tsx` | |
| Lineage graph: fixed node width, wider columns, columns centred, so nodes no longer overlap | `pages/LineageGraph.tsx` | visual (not automated) |
| Check matrix and generated checks reference | `scripts/check_matrix.py`, `scripts/gen_checks_doc.py` | |

## 12. Known gaps, stated plainly

1. The artifact **Type is not auto-detected**.
2. Hub fetch reads each file fully into memory before writing (`fetch_hf`); very large model files need a streaming change.
3. The GPU worker and live LLM paths were not run here (section 5).
4. `PKG.PROV.COOLDOWN` is scored but the engine only quarantines on `PROV.COOLDOWN*`; the release-age rule that works is `released_at`-based.
5. Graph overlap fix is visual and unverified in a browser here; the graph page is the one to eyeball first.
6. Without a typed Name and Version an upload is named after its file and is `0.0.0`; two such uploads look alike in the catalogue (use the artifact id).


## 13. Versions: how they work today

| Source | Name | Version | Where decided |
|---|---|---|---|
| `pypi:name==1.4.0` | the package name | the release you asked for (`1.4.0`) | `pipeline.py::_identify` (name from the source, version from `==`) |
| `hf:org/name[@rev]`, `hf-dataset:` | repo name without the org (`triage-base`) | the first 12 characters of the **commit** (`67d0bdf167ed`). Hugging Face has no semantic versions, so the commit is the only exact one | `_identify`, from `Acquired.record["source_revision"]` |
| Upload | what you typed in **Name**, else the file/folder name (`tiny.zip` is `tiny`) | what you typed in **Version**, else `0.0.0` | `_identify`: `ctx.fact_value("name"/"version", trusted_only=False)` |
| Upload with a verified passport | the passport's name and version | the passport's | `_identify`: `ctx.claimed` overrides |
| `lineage run --name --version` | whatever you pass; version defaults to `0.0.0` | | `lineage/cli.py::run` |

Each intake is a **new artifact with a new id**, even for identical bytes; `INTAKE.DIGEST.KNOWN` says when the content was seen before. Two artifacts with the same name and version are allowed (the catalogue lists both); the dataset diff and the package "previous release" check pick the newest admitted artifact of the same name. A name is a label and **never trusted**: a declared name cannot make an artifact more trusted, it only changes what it is called and which earlier version it is compared with.

## 14. When an input is missing, what does not run

| Missing | What happens | Code |
|---|---|---|
| Claimed origin (upload) | no hash comparison; `PROV.ORIGIN.UNCLAIMED` (medium); trust stays `unknown` (+15) | `inspectors.py::origin_check` |
| Hub unreachable / repo unknown | `PROV.ORIGIN.UNVERIFIABLE` (high); no facts promoted | `origin_check` |
| Creator passport | `signed_passport` returns nothing; trust cannot reach `signed` | `signed_passport` |
| Trusted key for the passport | `PROV.SIGNATURE.UNTRUSTED_KEY`; its facts stay `declared`; its **inputs and package list are not used** for the graph, but its listed parents still are (they are checked by `parent_chain`: revoked parent = hard block) | `signed_passport`, `pipeline._graph_refs` |
| Release date from hub or signed passport | cooldown cannot be cleared: `PROV.COOLDOWN.UNVERIFIED` (score 0, quarantines) | `release_age`, `engine.decide` |
| **Parent model** (none admitted on the host, none named) | `CHECK.NOT_RUN.PARENT_ID`; then **parent-dependent checks cannot run**: tokenizer diff vs parent, chat-template diff vs parent, `MODEL.WEIGHTS.CHANGED_LAYERS`, spectral score and behaviour diff (`CHECK.NOT_RUN.WEIGHT_BACKDOOR`, `BEHAVIOUR_DIFF`: "no parent was identified"). What still runs: pickle, config, tokenizer *content* checks, template AST, everything in S2/S5 | `local_parent_diff`, `gpu_weights` |
| Declared base model, no match found | the declaration is just a claim; `hub_parent` compares with the named base (needs the hub); no base named → `MODEL.PARENT.NO_CLAIMED_BASE` (info) | `hub_parent` |
| Parent in a passport but not in the registry | `PROV.PARENT.UNKNOWN` (medium); the graph shows an unregistered node | `parent_chain`, `service.link_refs` |
| GPU worker | `CHECK.NOT_RUN.WEIGHT_BACKDOOR` / `BEHAVIOUR_DIFF` / `NOTARY`, priced per environment | `gpu_weights`, `apply_unrun_costs` |
| AI backend (no key, no worker) | `CHECK.NOT_RUN.LLM_REVIEW` (prod high, +25); card policy check `CHECK.NOT_RUN.POLICY_CHECK` | `gpu_code_review`, `gpu_card_review` |
| Model/dataset card | `LLM.CARD.MISSING` (low, +5); no card-based claims | `gpu_card_review` |
| Earlier dataset version | `DATA.DIFF.NO_BASELINE` (info); no diff | `dataset_upstream_diff` |
| Earlier package release (offline, first release, not a wheel) | `PKG.BASELINE.NONE`; `PKG.NEW.*` ("new in this release") cannot fire; capabilities judged by combination only; hooks keep full severity | `package_baseline`, `package_capabilities.scan` |
| PyPI metadata (uploaded wheel) | `CHECK.NOT_RUN.PKG_METADATA` (prod high); name look-alike, repo-owner and maintainer checks skipped | `package_provenance` |
| OSV unreachable and nothing cached | `CHECK.NOT_RUN.OSV` | `package_osv` |
| Manifest (tool) | `TOOL.MANIFEST.MISSING` (high); no description or intent checks | `tool_description` |

A parent is therefore **declared** (by the hub card, the uploader, or a passport) or **found** (from weights on this host, or recorded by `lineage run`). A declared parent is checked against the weights when the hub is reachable; an unfound parent only costs points. It never blocks by itself.
