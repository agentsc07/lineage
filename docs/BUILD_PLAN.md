# Lineage — Build Plan

This plan takes us from now to submission, about 36 hours. It works together with `LINEAGE_SPEC.md`, which defines *what* Lineage is; this file defines *how we build it*.

## 0. How to run this with Claude Code

**Session 0 (sequential, about 45 minutes).** Run it in the main checkout. It creates the repo layout, the schemas, the API contract and stub modules, then commits to `main`. Nothing runs in parallel until this is merged.

**Then four parallel sessions**, each in its own git worktree:

```bash
git worktree add ../lineage-a -b track-a   # Prove core + CLI + SDK binding
git worktree add ../lineage-b -b track-b   # Server: registry, policy, gate, monitor, MCP gateway
git worktree add ../lineage-c -b track-c   # Inspector: static scanners + grounded LLM review client
git worktree add ../lineage-e -b track-e   # Dashboard UI + demo scenario
# Track D runs on the Brev GPU machine (clone repo there, branch track-d)
```

**Merging.** Merge into `main` at each checkpoint (§7). Every track rebases on `main` after each merge.

**Starting each session.** Paste the track prompt from §6, and tell it to read `CLAUDE.md`, `docs/LINEAGE_SPEC.md` and this file first.

---

## 1. Repo layout

```
lineage/
  CLAUDE.md
  docs/  LINEAGE_SPEC.md  BUILD_PLAN.md  API.md
  pyproject.toml                     # package "lineage" + "lineage_server"
  lineage/                           # pip package (CLI + SDK)
    schemas/   passport.py finding.py policy.py decision.py artifact.py
    hashing/   files.py tensors.py merkle.py           # parallel, streamed SHA-256
    signing/   keys.py ed25519.py sigstore_opt.py
    passport/  build.py verify.py chain.py
    diff/      layers.py parent.py                     # per-tensor diff, parent fingerprinting
    intake/    pipeline.py                             # S1–S7 orchestration per artifact type
    inspect/                                           # scanner plugins → list[Finding]
      model_pickle.py model_config.py tokenizer.py chat_template.py
      package_osv.py package_provenance.py package_capabilities.py package_taint.py
      tool_description.py tool_intent.py dataset_stats.py dataset_pii.py
      llm_review/ client.py prompts.py grounding.py   # calls GPU worker; verifies citations
    risk.py                                            # findings → score
    policy/    engine.py                               # PolicyPack + evidence → Decision
    bind.py                                            # lineage.load(): re-check at use
    run.py                                             # `lineage run`: record inputs/outputs → child passport
    cli.py                                             # Typer + Rich
  lineage_server/
    app.py db.py models.py log.py graph.py monitor.py tuf.py
    routes/ artifacts.py passports.py intake.py decisions.py policy.py graph.py events.py
  mcp_gateway/  gateway.py
  gpu_worker/                                          # runs on Brev (Track D)
    serve_llm.sh  reviewer_api.py  weights_api.py  behaviour_api.py  notary_api.py
    train_lora_bank.py  calibrate_weightspace.py
  bench/  corpus/  build_corpus.py  run_bench.py  report.py
  dashboard/  (Vite + React + TypeScript + Tailwind + react-flow)
  examples/  policy.org.yaml  demo_scenario.sh
  tests/  fixtures/
```

---

## 2. Data contracts (Session 0 writes these; frozen afterwards)

### 2.1 Finding

```python
class Finding(BaseModel):
    id: str                      # e.g. "MODEL.PICKLE.DANGEROUS_GLOBAL"
    title: str                   # human sentence
    severity: Literal["info","low","medium","high","critical"]
    category: Literal["provenance","integrity","code","model","data","tool","policy","behaviour","llm"]
    stage: Literal["S1","S2","S3","S4","S5"]
    evidence: list[Evidence]     # Evidence(kind="file_line"|"tensor"|"field"|"url"|"metric", ref=str, detail=str)
    score: int                   # contribution 0–40
    source: Literal["deterministic","statistical","llm","human"]
    grounded: bool = True        # llm findings: True only if citation check passed
```

### 2.2 Passport (in-toto Statement)

```python
class Subject(BaseModel): name: str; digest: dict[str,str]        # {"sha256": ...}
class Passport(BaseModel):
    _type: str = "https://in-toto.io/Statement/v1"
    subject: list[Subject]
    predicateType: str = "https://lineage.dev/passport/v1"
    predicate: PassportBody
class PassportBody(BaseModel):
    artifact_type: Literal["dataset","model","package","tool","agent"]
    name: str; version: str; source: SourceRef            # hub, repo, commit/url
    contents: Contents                                    # merkle_root, files{path:sha256}, tensors{name:sha256}|None
    parents: list[str]                                    # passport ids
    action: Action | None                                 # kind ("train","fine-tune","quantize","intake","publish"), command, env sbom digest
    trust_level: Literal["unknown","declared","inspected","recorded","attested"]
    findings_digest: str; risk_score: int
    certificates: list[str]                               # notary cert ids
    issued_by: Signer; issued_at: datetime; expires_at: datetime | None
class SignedPassport(BaseModel): passport: Passport; signature: str; key_id: str
# passport_id = "lp:" + sha256(canonical_json(passport))
```

### 2.3 Policy pack (`examples/policy.org.yaml`)

```yaml
org: "Apollo Health AI"
environments: { dev: {min_trust: declared, max_risk: 70}, staging: {min_trust: inspected, max_risk: 40}, prod: {min_trust: inspected, max_risk: 25} }
publishers: { allow: ["nvidia","meta-llama","BerriAI"], block: ["*-official-mirror"] }
licences_allowed: ["apache-2.0","mit","bsd-3-clause","llama3.1","nvidia-open-model-license"]
cooldown_days: { package: 3, model: 7, dataset: 7, tool: 7 }
banned_capabilities: ["network_at_install","startup_hook","dynamic_exec_of_remote_code"]
max_vuln_severity: { prod: "medium", dev: "high" }
require_human_approval: ["tool", "model:prod"]
model_files: { allow_pickle: false }
data: { pii_allowed: false, residency: ["IN","EU"] }
thresholds: { allow: 30, quarantine: 70 }       # >70 block
exceptions: []                                  # {artifact, approver, reason, expires}
compliance_map: { "NIST-AI-RMF:MAP-4.1": ["provenance"], "ISO42001:A.7.5": ["data"] }
```

### 2.4 Decision

`Decision{artifact_id, environment, outcome: allow|allow_with_conditions|quarantine|block, reasons[], conditions[], risk_score, trust_level, findings[], policy_version, decided_at, approver?}`

### 2.5 Server API (`docs/API.md`)

| Method | Path | Purpose |
|---|---|---|
| POST | `/intake` | `{artifact_type, ref, environment}` → job id, then streams stage events (SSE `/events/{job}`) |
| GET | `/artifacts` · `/artifacts/{id}` | Catalogue + detail (passport, findings, decision) |
| POST | `/passports` · GET `/passports/{id}` · `/passports/{id}/verify` | |
| GET | `/graph/{id}?direction=up\|down` | Lineage graph (react-flow nodes/edges) |
| POST | `/revoke/{id}` | Revoke, then returns the blast radius |
| GET/PUT | `/policy` | Policy pack (PUT requires 2-of-3 role signatures, TUF-style) |
| POST | `/decisions/{id}/approve` | Human approval (approver, reason, expiry) |
| GET | `/log` · `/log/proof/{id}` | Append-only Merkle log + inclusion proof |
| POST | `/monitor/tick` | Re-check advisories, then emit alerts + blast radius |

### 2.6 GPU worker API (Track D, on Brev; served on `:8800`)

| Method | Path | Body → returns |
|---|---|---|
| POST | `/review/code` | `{purpose, capabilities[], slices[{file,start,end,code}], diff?}` → `{claims[{text, file, line, api, severity}], verdict}` |
| POST | `/review/card` | `{card_text, measured{}}` → claims |
| POST | `/weights/parent` | `{model_path}` → `{parent, similarity, changed_layers[]}` |
| POST | `/weights/spectral` | `{model_path, parent}` → `{score, per_layer{}}` |
| POST | `/behaviour/diff` | `{child, parent, probe_set}` → divergence report |
| POST | `/behaviour/claims` | `{model, claims[]}` → measured vs claimed |
| POST | `/notary/certify` · `/notary/check` | Hidden-test certificate / spot-check |

**Fallback.** If the GPU worker is unreachable, Inspector modules return an `info` Finding ("deep check skipped") and the pipeline continues. The demo must never crash.

---

## 3. Risk score

`score = min(100, Σ finding.score)`, with typical weights:

| Severity | Weight |
|---|---|
| critical | 40 |
| high | 25 |
| medium | 12 |
| low | 5 |
| info | 0 |

A hard block applies regardless of score for: pickle when not allowed, banned capability, blocked publisher, signature failure, hash mismatch, revoked parent.

Trust level caps:
- *unknown* adds +15.
- *declared* adds +5.

---

## 4. Demo scenario (the story the UI plays)

Organisation: **Apollo Health AI**, building a radiology triage agent.

1. **Known source:** intake of a signed dataset passport, then a model passport that chains to it → **Allow** (green, seconds).
2. **Unknown model from a hub:**
   - no passport,
   - parent identified from its weights,
   - layers 28–32 changed,
   - spectral score high,
   - child-vs-parent divergence on probes,
   - chat-template scan finds conditional hidden instruction

   → **Block**, with evidence.
3. **Package intake, LiteLLM-style:**
   - version 2 hours old (cooldown),
   - source repo look-alike,
   - new `.pth` start-up file,
   - LLM review cites `x.pth:1 exec(base64…)`

   → **Block**.
4. **MCP tool:** description clean, but the code opens network connections it never declares (intent gap) → **Quarantine** for a human; the reviewer approves with an expiry.
5. **Use time:** someone swaps `tokenizer.json` after approval → `lineage.load()` refuses.
6. **Watch:** a new advisory is published for an admitted package → Monitor raises risk → **blast radius** shows two models and one agent affected.

---

## 5. Brev (Track D) setup

- **Instance A (training and serving):** one A100 80GB or H100.
  - Trains the LoRA bank on a small open model, Qwen2.5-1.5B or Llama-3.2-1B (fast): 20 benign LoRAs on varied instruction sets, and 20 backdoored LoRAs (trigger phrase → fixed inert payload, BackdoorLLM-style).
  - Then serves the Nemotron reviewer with vLLM.
- **Instance B (experiments):** L40S or A10G. Runs behavioural tests, claim checks, the Notary and hashing benchmarks.
- **Models:**
  - **Reviewer:** an NVIDIA Nemotron model served with vLLM. Prefer Nemotron 3 Nano; if it doesn't fit or load, use the largest Nemotron Nano that does.
  - **Policy/safety checks:** `nvidia/Nemotron-Content-Safety-Reasoning-4B`, which supports a custom policy, for card and template checks against the org policy.
- **Running it:** install Claude Code on the instance, clone the repo, check out `track-d`, and run the Track D prompt. Stop instances when idle. Log GPU-hours to `bench/cost_log.csv` for the cost slide.

---

## 6. Track prompts (paste one per session)

### Session 0: Foundations

> Read CLAUDE.md, docs/LINEAGE_SPEC.md and docs/BUILD_PLAN.md.
>
> Create the repo layout in BUILD_PLAN §1 with `uv`.
>
> Implement exactly the schemas in §2 (Finding, Passport, PolicyPack, Decision) with canonical JSON + passport_id. Write `docs/API.md` from §2.5 and §2.6.
>
> Create stub modules with typed signatures and `NotImplementedError` for every file in §1. Also write:
> - `examples/policy.org.yaml`
> - a Typer CLI skeleton with commands `intake`, `verify`, `sign`, `diff`, `run`, `load-check`, `revoke`, `bench`
> - a FastAPI app skeleton with all routes returning mock data that matches the schemas
> - pytest fixtures: a tiny safetensors model (2 layers), a tiny dataset CSV, a toy package dir, a toy MCP tool manifest
>
> Commit to main. Keep it minimal but correct; other sessions build on it in parallel.

### Track A: Prove core, CLI, binding (local)

> Read CLAUDE.md, docs/LINEAGE_SPEC.md §2–4 and BUILD_PLAN §2–3. You own `lineage/hashing`, `signing`, `passport`, `diff`, `run.py`, `bind.py` and `cli.py`.
>
> Implement:
> 1. Parallel streamed hashing: files, per-tensor for safetensors (read the header offsets; don't load into RAM) and GGUF, and a Merkle root. Benchmark GB/s with `lineage bench hash`.
> 2. Ed25519 key management and signing of canonical passports; optional Sigstore if available.
> 3. Passport build, verify and chain-walk, including revocation status from the server when reachable.
> 4. Layer diff between two models: changed tensors and relative L2 change.
> 5. `lineage run -- python train.py`: record files opened, via sys.addaudithook in a sitecustomize injected through PYTHONPATH, plus `pip freeze` as an SBOM and outputs. Emit a child passport at trust level "recorded".
> 6. `lineage.load(path)`: re-hash against the passport, refuse on mismatch, refuse pickle per policy. Ship a `transformers`-compatible wrapper.
> 7. A beautiful Rich CLI.
>
> Tests for each. Commit often.

### Track B: Server, policy, gate, monitor, MCP gateway (local)

> Read CLAUDE.md, the spec §3–6 and BUILD_PLAN §2–4. You own `lineage_server/`, `lineage/policy/`, `lineage/risk.py`, `lineage/intake/pipeline.py` and `mcp_gateway/`.
>
> Implement:
> 1. SQLite models for artifacts, passports, findings, decisions, edges and revocations.
> 2. An append-only Merkle log with inclusion proofs.
> 3. A policy engine applying the PolicyPack, including hard blocks, cooldown, environments, exceptions with expiry, and compliance-map tags on decisions.
> 4. TUF-style policy updates requiring 2-of-3 role signatures, with metadata expiry.
> 5. An intake pipeline orchestrating stages S1–S7 per artifact type, calling Inspector plugins by registry and the GPU worker with fallback, streaming stage events over SSE.
> 6. Graph queries up and down, using a recursive CTE.
> 7. Revoke → blast radius.
> 8. Monitor tick: re-query OSV for every admitted package, then alert and update decisions.
> 9. An MCP gateway proxy that pins tool description and code hashes, re-checks on every call, and disables a tool on change.
>
> Seed script loads the demo scenario data. Tests for each.

### Track C: Inspector (local, CPU)

> Read CLAUDE.md, the spec §4–5 and BUILD_PLAN §2–3. You own `lineage/inspect/`.
>
> Every scanner returns `list[Finding]` with evidence. Implement:
> - **Model:** a pickle-opcode scanner (pickletools: GLOBAL/STACK_GLOBAL/REDUCE to os/subprocess/builtins/etc.); a config scanner (trust_remote_code, auto_map → collect the .py files for code review); a tokenizer diff vs claimed base; a chat-template scanner (Jinja AST: conditionals on message content, hidden instructions, URLs, diff vs known-good template).
> - **Package:**
>   - OSV client with cache (vulns + MAL advisories);
>   - provenance (release age vs cooldown, source-repo vs metadata, look-alike names via Damerau-Levenshtein against a top-5k list, maintainer change);
>   - capability extractor over Python AST (network, fs, subprocess, env/secrets, exec/eval, base64/encoded blobs, obfuscation), with **install-time and start-up hooks** (setup.py, .pth, sitecustomize);
>   - a simple intra-procedural taint slicer (source → sink) for Python;
>   - a version diff of capabilities.
> - **Tool:** description scan (instructions aimed at the agent, invisible Unicode, URLs); intent gap = capabilities vs declared permissions.
> - **Dataset:** duplicates/near-duplicates (MinHash), label-error estimate (confident learning with sklearn cross-val), class balance vs card, PII regex.
> - **llm_review client:**
>   - builds prompts per spec §5 (prosecutor, defender, judge);
>   - calls the GPU worker `/review/code`;
>   - the **grounding checker** keeps only claims whose cited file:line contains the cited API;
>   - reviewer-bait detection;
>   - findings can only add score.
>
> Unit tests with fixtures, including inert malicious fixtures (marker files only).

### Track D: GPU worker + bench corpus (on Brev)

> Read CLAUDE.md, the spec §4, §5, §8 and BUILD_PLAN §2.6 and §5. You own `gpu_worker/` and `bench/corpus`. Log GPU time to `bench/cost_log.csv`.
>
> Order:
> 1. **`train_lora_bank.py`:** 20 benign + 20 backdoored LoRAs on a small base model (trigger phrase → inert fixed payload). Run in the background immediately.
> 2. Serve a Nemotron reviewer with vLLM, plus `reviewer_api.py` implementing `/review/code` and `/review/card` (JSON-schema constrained output with file+line citations).
> 3. **`weights_api.py`:**
>    - parent fingerprinting against a small bank of base models (cosine similarity on embedding and early layers);
>    - changed-layer detection;
>    - spectral scoring of ΔW (energy concentration, kurtosis, spectral entropy, Frobenius norm, top singular value);
>    - `calibrate_weightspace.py` z-scores against the benign bank and fits a logistic regression. Report AUROC/TPR/FPR.
> 4. **`behaviour_api.py`:** child-vs-parent differential probes; a simple trigger hunt (sample generations, candidate n-grams, test output-entropy collapse); claim check on a small benchmark subset.
> 5. **`notary_api.py`:** sealed hidden test set; random subset per request; signed certificate; spot-check.
> 6. `bench/build_corpus.py` builds LineageBench (spec §8, inert payloads); `run_bench.py` + `report.py` produce `bench/results.md` + JSON (detection, TPR/FPR, latency, cost).
>
> Expose everything on `:8800` and give the local machine a URL (Brev port forward).

### Track E: Dashboard + demo (local)

> Read CLAUDE.md, the spec and BUILD_PLAN §2.5 and §4. You own `dashboard/` and `examples/demo_scenario.sh`.
>
> Build a professional dark/light enterprise UI: Vite + React + TS + Tailwind + react-flow + Recharts, using the mock server data first. Pages:
> 1. **Overview:** KPIs, recent decisions, alerts.
> 2. **Catalogue:** artifacts with type, trust level, risk, decision, environment.
> 3. **Intake:** submit an artifact; live stage-by-stage progress via SSE; Prove/Inspect/Review/Decide columns.
> 4. **Artifact detail:** passport card, findings with evidence (code snippet with the cited line highlighted), decision + reasons, compliance tags.
> 5. **Lineage graph:** react-flow, colour by trust level; revoke button animates the blast radius.
> 6. **Policy:** YAML view/editor with 2-of-3 approval state.
> 7. **Approvals queue:** approve with reason + expiry.
> 8. **Bench:** results charts.
>
> Then `demo_scenario.sh` runs §4 end to end. Polish matters: consistent spacing, clear verdict colours, no clutter.

---

## 7. Timeline and checkpoints (IST)

| When | Checkpoint |
|---|---|
| Sun 23:59 – Mon 00:45 | Session 0 merged. **Brev instance A launched; LoRA bank training started.** |
| Mon 00:45 – 04:00 | A, B, C, E in parallel. **CP1 at 04:00:** hashing, sign/verify, policy engine, three scanners, UI shell on mock data. Merge. |
| Mon 09:00 – 13:00 | Grounded LLM review end to end; weight-space calibration; intake pipeline wired to real scanners. **CP2 at 13:00:** demo steps 1–3 work. Merge. |
| Mon 13:00 – 18:00 | Demo steps 4–6, MCP gateway, monitor/blast radius, bench run. **CP3 at 18:00:** full demo + `bench/results.md`. |
| Mon 18:00 – 22:00 | Deck update with real numbers + scalability/cost slide; record the demo video; README. |

**Cut order if behind** (cut the first item first):
1. Notary
2. Trigger hunt
3. Federated-learning simulation
4. Claim check
5. Sigstore (keep Ed25519)
6. Policy 2-of-3 UI (keep the API)
