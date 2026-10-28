# Presentation cheat sheet (commit `24af4c9`)

## The pipeline in one breath
`POST /intake` → `pipeline.py::run_intake`, one generator, stages in order, scanners in order, nothing concurrent:
**S0 Acquire** (`_s0`: fetch `hf:`/`pypi:` ourselves or take the upload) → **S1 Identify** (`_identify`: SHA-256 per file, Merkle root, per-tensor hashes) → **S2 Provenance** (origin vs hub hashes, signed passport, publisher, licence) → **S3 Static** (pickle opcodes, config, tokenizer, chat-template AST, PII, package AST/taint, tool manifest) → **S4 Deep** (parent from weights, hub parent, GPU checks, dataset poisoning, dataset diff) → **S5 LLM** (card or code review) → **S6 Decide** (`risk_score` + `policy.engine.decide`, registry signs) → **S7 Admit** (`service.record`, one DB transaction).

Rule to repeat: **every check runs or says why it did not** (`CHECK.NOT_RUN.<name>`), and the policy prices that per environment.

## Score in 20 seconds
`risk = min(100, sum of finding points + trust penalty)`. Points: info 0, low 5, medium 12, high 25, critical 40. Trust penalty: unknown 15, origin_verified 5, signed/recorded 0. Prod allow limit = `min(thresholds.allow 30, prod max_risk 25)` = 25; above 70 = block. Hard blocks and human-approval rules decide **regardless of the number**.

Worked example (executed): clean fetched model in prod, no GPU, no API key: PARENT_ID 12 + WEIGHT_BACKDOOR 12 + BEHAVIOUR_DIFF 12 + LLM_REVIEW 25 + origin_verified 5 = **66**, quarantined because prod models need a human. With a parent found, 54. With the LLM actually running and finding nothing, 29 (arithmetic from the code; **not run here**), still above 25 and still needs a human.

## Say this (all verified in code or by running it)
- "Nothing a user can edit is trusted": claims, `lineage.meta.json`, README and `config.json` become `declared` facts and can only add risk (`pipeline.py::add_dict_facts`, `Fact` classes).
- "We fetch the bytes ourselves or compare every file with the hub's published hash": `fetch_hf`, `origin_check` → `PROV.ORIGIN.MODIFIED` (critical, hard block in staging/prod).
- "Static review is real analysis, not just regex": pickle opcode walk without unpickling (`model_pickle.py`), Jinja AST for chat templates (`chat_template.py`), Python AST + taint for packages (`package_capabilities.py`, `package_taint.py`), Luhn/Verhoeff-validated PII (`dataset_pii.py`), MinHash and confident learning for datasets (`dataset_stats.py`).
- "Parent from weights on a laptop": `local_parent_diff` fingerprints against admitted models on disk; `hub_parent` compares the first 512 embedding rows over HTTP range requests.
- "Dataset backdoors": `dataset_v2.py` finds a rare prompt phrase whose responses are near-identical (the demo's `cf 7391` at 5%), plus spectral-signature and kNN checks; `dataset_diff.py` shows the added rows.
- "The LLM can only add risk": `risk.finding_points` never subtracts; claims must cite a real `file:line` containing the cited API (`grounding.py`); by default a claim scores only if a deterministic finding is within 2 lines or the capability does not fit the stated purpose (`_to_finding`, precise mode).
- "Three roles": prosecutor always runs; defender and judge run only when the prosecutor has a grounded claim; the judge can only raise severity (`reviewer_api.py::_pipeline`).
- "Signed decision is what loaders trust": `attest.py::issue`, `client.py::check_for_use` re-hashes, checks the signature against the pinned registry key, environment, expiry and live revocation.
- "A hash mismatch alone is not an accusation": it matters when compared with something (signed passport, hub, previous release).

## Do not say
- "All three LLM roles are separate model providers or the client orchestrates them": they are separate **calls to the same model** inside the reviewer; the client-side `review_package` is not used by intake.
- "The GPU checks ran": in the demo they are **NOT_RUN** (no `LINEAGE_GPU_URL`), priced +12 each in prod. Say: "implemented, benchmarked earlier on a Brev L40S (handoff numbers), priced as not run here." Their tests were not collected in this environment (no torch).
- "The LLM reads the whole artifact": it reads code slices around flagged lines, or the card text plus a summary of earlier finding ids. Never weights or full datasets.
- "The Verify passport button proves the bytes": it checks the registry's stored passport (signature by a trusted key, expiry, revocation, ancestors). `hashes_ok` is not checked, though the UI text says "hashes ... verified".
- "Card review is validated end to end with a live model": not run; and there is a probable grounding mismatch (below).
- "Production-grade for private code": hosted mode sends slices and card text to `integrate.api.nvidia.com`.

## Honest limitations (one line each)
1. No live hosted-LLM run in this audit; prompts and parsing are covered by stubbed tests.
2. Probable defect: card-review claims cite `card.md`/`measured.json` but are re-grounded against real files, so they are dropped (reproduced with a unit-level experiment; fix not made).
3. GPU path (spectral, behaviour, notary) not executed; worker reads model paths from its own disk and only knows a 7-model bank.
4. Dataset checks miss ~1% poisoning (handoff); false-alarm rate on real PyPI packages never measured.
5. Enforcement holds only on Lineage's paths (pull/load/index/gateway).
6. Tokenizer diff and template-vs-parent only run after a parent is identified.
7. No Sigstore/DSSE; no sandboxed dynamic analysis.

## Demo-safe claims
| Claim | Evidence | Tested here? | Caveat / wording to avoid |
|---|---|---|---|
| Every check runs or reports "did not run", priced by policy | `inspectors.run_inspector/not_run`, `engine.apply_unrun_costs`; `tests/test_no_silent_skip.py` | yes (suite green) | say "priced", not "penalised"; dev prices most at 0 |
| Tampered copy of a hub model is hard-blocked in prod | `origin_check`, `engine.hard_blocks`; demo step 3 executed → BLOCK 100 | yes | modified-origin is a hard block in staging/prod only |
| Parent found from weights, changed layers listed | `local_parent_diff`; `MODEL.PARENT.IDENTICAL` seen on a repeat intake | yes (CPU, tiny model) | needs an admitted reference on the host; not the GPU bank |
| Hidden chat-template trigger is caught | `chat_template.py`; `test_inspect_tokenizer_template.py` | yes | regex plus AST; tested on fixtures, not on a corpus of real hub templates here |
| Poisoned instruction dataset blocked | demo step 6 executed: `DATA.TRIGGER.BEHAVIOUR` + `DATA.DIFF.NEW_TOKENS` → BLOCK 100 | yes | the IP-address PII hit also contributes to the block reasons; 1% poisoning mostly missed |
| Compromised package blocked, pip resolves to last admitted | demo step 5 executed (`PKG.CODE.DECODE_EXEC`, `PKG.HOOK.STARTUP_HOOK`) | yes | OSV ran from snapshot (`LINEAGE_OFFLINE=1`); LLM review not run |
| Clean model needs a different person to approve | demo step 2 executed: alice 403, bob 200 | yes | after approval the risk number stays; the outcome changes |
| `load()` re-hashes and checks the signed decision and revocation | `client.check_for_use`; demo step 2 `lineage.load() ok`; `tests/test_load_enforcement.py` | yes | fails closed in prod when the registry is unreachable; stale pinned key gives an explicit message |
| LLM review is grounded and add-only | `grounding.py`, `risk.finding_points`; tests with stubs | yes (stubbed) | do not claim live accuracy; do not claim the card review works end to end |
| GPU weight-space / behaviour / notary checks | code in `gpu_worker/*` | **no** (not run, tests not collected without torch) | say "implemented, priced as not run in this demo" |
| Verify passport button | `routes/passports.py::verify_passport` | partly | do not say it re-verifies file hashes |
| Real Hugging Face artifact | `tests/test_real_hub.py` | **no** (off by default, not run) | demo uses the fake hub unless `LINEAGE_DEMO_REAL_HUB=1` |
| Sigstore / SBOM-in-toto export | not implemented | n/a | planned only |
