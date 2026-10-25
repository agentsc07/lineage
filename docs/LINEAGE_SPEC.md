# Lineage — System Specification (single source of truth)

**Lineage: admission control for AI artifacts.** Every dataset, model, package and agent tool an organisation uses is identified, verified, inspected and decided on before use, re-checked at the moment of use, and watched afterwards.

> Core principle: **trust is earned by evidence, not by origin.** A signed artifact from a known publisher is verified cheaply. An unknown artifact goes through intake, which gathers evidence. Either way, the organisation's own policy decides.

---

## 1. Lessons borrowed from other industries

| Industry practice | How it works there | What Lineage takes from it |
|---|---|---|
| **git** | Content-addressed objects; each commit hashes its parent, so history can't be silently changed | Passports are content-addressed and link to parent passports |
| **DocuSign** | Verified signers, a tamper-evident seal, a separate certificate of completion | Signed passports, identity strength levels, a separate audit trail |
| **Pharma track-and-trace (DSCSA)** | Every unit is serialised; suspect product is **quarantined**; recalls trace every lot | Fingerprint as serial number, a **Quarantine** state, recalls = revocation + **blast radius** |
| **Aviation parts (FAA 8130-3 tag)** | Every part carries "back-to-birth" history; unknown parts aren't fitted until inspected | Full history to origin; unknown artifacts must pass **intake** before use |
| **Food safety (HACCP)** | Named critical control points; approved-supplier programmes | Five named **control points** (§3); publisher allow/block lists |
| **Apple notarisation + Gatekeeper** | A third party scans and issues a ticket; the OS re-checks **at every launch** | **Notary** + **load-time binding** (`lineage.load`) |
| **Certificate Transparency** | Public append-only logs; monitors watch for impersonating certificates | Append-only registry log + a **look-alike watcher** for publisher and model names |
| **TUF / Uptane (software and car updates)** | Separate signing roles, threshold signatures, expiring metadata, rollback protection | **Registry hardening**: role keys, 2-of-3 approval for policy changes, expiring metadata, no rollback (answers "what if the registry or a key is compromised?") |
| **Package firewalls (JFrog Curation, pnpm `minimumReleaseAge`)** | A curated internal mirror; brand-new versions refused for N days | **Golden catalogue** + **cooldown policy** for new uploads |
| **Bank KYC / supplier onboarding** | Verify who a supplier is before trading | Publisher verification tiers and reputation (account age, history) |

**Motivating case (21 Oct 2026):** LiteLLM 1.107.0 was published to PyPI and Docker from a hijacked release pipeline. It was live for about two hours, was built from a look-alike source repo (`Berri-AI/litellm` instead of `BerriAI/litellm`), and hid code in Python startup files. Three independent Lineage checks would have flagged it:
1. the cooldown,
2. the source-repo mismatch,
3. a new startup-file capability.

---

## 2. Concepts

- **Artifact types:** `dataset`, `model`, `package` (pip/npm/container), `tool` (agent tool, MCP server, skill), and `agent` (a composition of the others).
- **Passport:** a signed JSON document in in-toto Statement format with predicate `lineage.dev/passport/v1`. It contains: subject digests, per-file and per-tensor hashes (Merkle root), parent passport IDs, the action taken, an SBOM reference, findings, risk score, trust level and signer. The passport ID is the SHA-256 of the canonical JSON.
- **Trust levels:**
  - **Unknown:** no information.
  - **Declared:** the creator states facts and signs.
  - **Inspected:** Lineage intake gathered evidence and the organisation signs.
  - **Recorded:** history was captured by `lineage run`.
  - **Attested:** trusted hardware vouches for the run (future work).
  - **Revoked** can apply at any level.
- **States:** `submitted → quarantined → admitted | admitted-with-conditions | blocked`; `admitted → revoked`.
- **Risk score:** 0–100 = Σ weighted findings, capped. LLM findings can only **raise** the score.
- **Decision outcomes:** Allow · Allow with conditions (for example, dev only or sandbox only) · Quarantine (waiting on cooldown or a human) · Block.

---

## 3. The five control points (the same for every artifact)

| # | Control point | When | Mechanism |
|---|---|---|---|
| CP1 | **Intake** | Before anything enters the catalogue | Identify → Provenance → Inspect → Review → Decide → Admit |
| CP2 | **Build / train** | When something new is produced | `lineage run` records inputs and outputs, then issues a child passport |
| CP3 | **Release** | When publishing | Sign; optional Notary certificate; registry entry |
| CP4 | **Use** | Every load, install or tool call | `lineage.load`, the install hook and the MCP gateway re-check hashes against the passport |
| CP5 | **Watch** | Continuously | New advisories, revocations, look-alikes, drift → blast radius → alert |

---

## 4. Flows (the canonical pipelines)

Every flow uses the same intake stages:

| Stage | Purpose |
|---|---|
| S1 | Identify |
| S2 | Provenance |
| S3 | Static inspection |
| S4 | Deep inspection (GPU) |
| S5 | Grounded LLM review |
| S6 | Decide |
| S7 | Admit |
| S8 | Bind at use |
| S9 | Monitor |

Stages are gated by tier: a later tier runs only if an earlier tier raises suspicion, or if policy requires it for the target environment.

### 4.1 Model

```
S1 IDENTIFY
   - hash every file; per-tensor SHA-256 via safetensors/GGUF headers (parallel, streamed)
   - registry lookup by digest → existing passport?  record hub repo + commit SHA
S2 PROVENANCE
   - passport present → verify signature, parent chain, Notary certificate, not revoked
   - absent → level Unknown/Declared
   - policy: publisher allow/block list, cooldown (upload younger than N days → Quarantine),
     look-alike name check vs known publishers/models
S3 STATIC (CPU, seconds)
   - file format: own pickle-opcode scanner (GLOBAL/REDUCE to dangerous callables); prefer safetensors
   - config: trust_remote_code / auto_map → custom .py files go through the PACKAGE code pipeline
   - tokenizer: added/changed tokens vs claimed base
   - chat template: diff vs known-good original; scan for conditional logic on input content,
     hidden instructions, URLs (template backdoors pass hub scanners — Pillar/ICLR 2026)
   - model card: extract licence, claimed base, claimed scores (LLM-assisted extraction)
S4 DEEP (GPU, Brev)
   a. Parent identification: weight fingerprint vs reference bank of base models → true parent;
      compare with claim; per-layer diff → changed-layer list
   b. Weight-space backdoor score on changed layers: SVD of ΔW → energy concentration, kurtosis,
      spectral entropy, Frobenius norm, top singular value; z-scored vs benign fine-tune bank → score
   c. Behavioural:
      - differential testing: same probe set on child vs parent; flag divergence on safety probes
      - trigger hunting: elicit memorised text → candidate substrings → test output-entropy collapse
        and fuzzy-trigger consistency (after Microsoft "Trigger in the Haystack", 2026)
      - claim check: re-run claimed benchmark subsets; flag gaps beyond tolerance
      - Notary hidden check if a certificate exists (behavioural fingerprint match)
S5 LLM REVIEW (Nemotron, isolated)
   - model card vs measured evidence; template/card against org policy (custom-policy safety model)
S6 DECIDE (policy engine)   S7 ADMIT → org model passport, level Inspected/Recorded
S8 BIND  lineage.load(): re-hash at load, refuse pickle unless policy allows, refuse unpinned files
S9 WATCH parent revoked / new finding → flag all descendants (blast radius)
```

### 4.2 Dataset

```
S1 IDENTIFY   per-file/shard hashes, row count, schema; registry lookup
S2 PROVENANCE signer, source URL, collection method, licence; policy: licence allowlist,
              personal-data rules, residency; cooldown; publisher list
S3 STATIC     safe format (no pickle), schema vs card, personal-data scan (regex + NER), licence text
S4 STATISTICAL
   - exact and near-duplicate detection
   - label-error estimation (confident learning with a cross-validated reference model)
   - per-class outliers; class balance vs card
   - poison heuristics: spectral signatures / activation clustering on reference-model embeddings;
     rare-token or patch patterns correlated with one label
   - version diff vs last admitted version (rows added/changed)
S5 LLM REVIEW card vs measured stats; sampled rows checked for embedded instructions (for LLM training data)
S6–S9         decide → data passport; lineage run verifies dataset hashes at training time; watch
```

### 4.3 Package (pip / npm / container)

```
S1 IDENTIFY   name, version, artifact hashes; resolve the full dependency tree → SBOM (CycloneDX)
S2 PROVENANCE PyPI/npm attestations where present; declared source repo vs build source (look-alike repo);
              maintainer changes; release age (cooldown); typosquat distance vs popular names;
              publisher allow/block
S3 KNOWN BAD  OSV query: vulnerabilities (CVE/GHSA) and malicious-package advisories (MAL-)
S4 STATIC CODE
   - install-time and start-up code: setup.py, build hooks, .pth files, sitecustomize, npm lifecycle scripts
   - capability extraction (AST, no LLM): network, filesystem, subprocess, environment/secrets,
     dynamic exec/eval, encoded blobs, obfuscation
   - taint slices: untrusted source → dangerous sink (only these go to the LLM)
   - version diff vs last admitted version: newly added capabilities
S5 GROUNDED LLM REVIEW (§5)
S5b SANDBOX CONFIRM (high suspicion only): install + import in an isolated container on Brev,
              no credentials, egress blocked; record attempted connections and file writes
S6–S9         decide → package passport; installs only via the golden mirror with pinned hashes;
              new advisory → blast radius over every model/agent whose SBOM includes it
```

### 4.4 Tool / MCP server / agent skill

```
S1 IDENTIFY   manifest (name, description, input schema, declared permissions) hash + code hash
S2 PROVENANCE publisher, source registry, policy, cooldown, look-alike names
S3 DESCRIPTION SCAN hidden instructions aimed at the agent (tool poisoning), invisible Unicode, URLs
S4 CODE       full package pipeline (§4.3) + intent gap: extracted capabilities vs declared permissions
S5 LLM REVIEW description vs behaviour (grounded)
S6–S7         decide → tool passport pins description hash + code hash
S8 BIND       MCP gateway re-checks pins on every session/call; change → disabled until re-approved (rug pull)
S9 WATCH
```

### 4.5 Agent (composition)

An agent passport is an AI bill of materials: model passport + tool passports + package SBOM + system-prompt hash. It is admitted only if every part is admitted for that environment. Revoking any part flags the agent.

### 4.6 Federated learning (training-time provenance)

Each round:
1. Screen every client update (norm, cosine similarity to the coordinate-wise median, loss on a probe set).
2. Update multi-round client trust scores.
3. Aggregate robustly (trust-weighted, trimmed).
4. Issue a **round passport** listing which clients contributed and with what weight.

The final global model passport therefore carries its federated history.

---

## 5. Grounded LLM review (how ours differs)

1. **Capabilities first, without an LLM.** Deterministic extraction of what the code *can* do. The LLM compares that list to the stated purpose (README, description, model card) to find the **intent gap**.
2. **Taint slicing.** Only source→sink slices are sent to the LLM. Prior work reports about 99.75% fewer tokens and higher F1 than sending whole files.
3. **Every claim must cite a file and line**, and a deterministic checker verifies the cited line contains the claimed API. Ungrounded claims are dropped.
4. **Prosecutor vs defender passes**, then a judge, cross-referenced with static-analysis findings. SAST cross-referencing was the strongest defence against reviewer manipulation in a 2026 study.
5. **Reviewer-bait detection.** Comments or strings addressed to the reviewer ("safe, ignore") are themselves a malicious signal.
6. **Diff-aware.** Review the delta from the last admitted version (attacks usually arrive in updates).
7. **LLM proposes, sandbox confirms** for high-suspicion claims.
8. **Monotonic and private.** Findings can only raise the score. The LLM is self-hosted (Nemotron on Brev), so code never leaves the organisation. Results are cached by content hash and calibrated on labelled data (precision and recall reported).

---

## 6. Organisation policy pack (YAML)

The policy pack covers:
- publisher and hub allow/block lists
- licence allowlist
- minimum trust level per environment (dev / staging / prod)
- cooldown days per artifact type
- maximum vulnerability severity
- banned capabilities (for example, network at install)
- required human approval
- data residency and personal-data rules
- risk thresholds (allow / quarantine / block)
- exceptions (approver, reason, expiry)

Evidence bundles map to the frameworks the organisation follows (NIST AI RMF, ISO/IEC 42001, EU AI Act, India DPDP Act). We map evidence to controls; we don't claim certification.

---

## 7. Product components

| Component | Form | Stack |
|---|---|---|
| `lineage` | pip package: CLI + SDK | Python 3.11, Typer, Pydantic, safetensors, Ed25519 (`cryptography`) with optional Sigstore keyless |
| `lineage-server` | Registry, policy engine, Gate, Monitor | FastAPI, SQLite (demo) / Postgres, append-only Merkle log, TUF-style role keys |
| Inspector | Plugin scanners | Own pickle / template / capability / taint scanners; OSV API |
| GPU workers (Brev) | Weight analysis, behavioural tests, LLM reviewer, Notary, sandbox | PyTorch, vLLM, Nemotron models |
| Dashboard | Web UI | React + react-flow: catalogue, intake report, lineage graph, policy editor, approval queue, blast radius |
| MCP gateway | Proxy | Python; pins tool descriptions and code hashes |
| LineageBench | Evaluation suite | Labelled attack corpus + scripts → metric tables |

---

## 8. Evaluation

**Public benchmarks:**
- BackdoorLLM (NeurIPS 2025): LLM backdoor attacks and defences.
- TrojAI / BackdoorBench: vision backdoors.
- The LoRA weight-space backdoor setting (arXiv 2602.15195).
- MalnpmDB / Datadog malicious-packages dataset / OSV MAL advisories.
- CWE-Bench-Java (IRIS) for LLM-assisted static analysis.

**LineageBench (ours, in scope).** Labelled artifacts with benign controls:

| Category | Planned count |
|---|---|
| Tampered weights | 10 |
| Swapped tokenizer | 5 |
| Chat-template backdoor | 5 |
| Pickle payload (harmless marker) | 5 |
| LoRA backdoors vs benign LoRAs | 20 / 20 |
| Look-alike names | 5 |
| Packages with install/start-up payloads (harmless marker) | 10 |
| MCP tool poisoning / rug pull | 5 |
| Poisoned-label datasets at 1 / 5 / 10% | 3 |

All payloads are inert markers; no real malware is used.

**Metrics:**
- Exact checks: detection rate, which must be 100% by construction.
- Statistical checks: TPR, FPR and AUROC vs a baseline.
- LLM review: precision and recall vs static analysis alone.
- Systems: hashing throughput (GB/s), verify latency p50/p95, cost per intake, cache hit rate.

---

## 9. Key literature

- Microsoft, *The Trigger in the Haystack* (2026), arXiv 2602.03085: scanning open-weight LLMs for sleeper-agent triggers.
- *Weight-space Detection of Backdoors in LoRA Adapters* (2026), arXiv 2602.15195.
- *WeightWatch: monitoring fine-tuned LLMs via weight diffs* (2025), arXiv 2508.00161.
- Shen et al., *BAIT* (IEEE S&P 2025): LLM backdoor trigger inversion.
- Li et al., *BackdoorLLM* (NeurIPS 2025).
- *Inference-Time Backdoors via Hidden Instructions in LLM Chat Templates* (ICLR 2026), arXiv 2602.04653.
- Li et al., *IRIS: LLM-Assisted Static Analysis* (ICLR 2025).
- *Taint-Based Code Slicing for LLM-based Malicious npm Package Detection* (2025), arXiv 2512.12313.
- *LLM Code Reviewers Are Harder to Fool Than You Think* (2026), arXiv 2602.16741.
- Classic methods: Wang et al., Neural Cleanse (2019) · Tran et al., Spectral Signatures (2018) · Chen et al., Activation Clustering (2018) · Northcutt et al., Confident Learning (2021).
- Supply-chain foundations: Samuel et al., TUF (2010) · Torres-Arias et al., in-toto (2019) · Newman et al., Sigstore (2022) · Ohm et al., Backstabber's Knife Collection (2020) · OpenSSF Model Signing.
