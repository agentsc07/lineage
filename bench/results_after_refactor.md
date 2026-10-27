# After-refactor results

Static-only generated 2026-10-27T12:01:14.295975+00:00; reviewer-through-the-hosted-API generated NOT RUN (see below). The frozen numbers are `bench/results_final.md` (never overwritten).

## Read this first

- **After-refactor numbers were measured on sets the fixes were written with knowledge of** (the detection rules for atexit, import hooks, reversed names, git hooks, beacons, hidden tool calls, zero-width directives and tool-output scanning were written after the final-set misses were known). They are not unseen-data numbers; the frozen FINAL column is the only unseen measurement.
- **Only the in-repo synthetic sets were re-run.** The real-world sets (PyPI top 200 and 201-400, 100 HF templates) are not on this machine (their manifests point to `/home/ubuntu/...`), so their false-alarm rates are not re-measured; the frozen values stay in `results_final.md`. The taint hang was re-checked on the real `black`, `datasets` and `kubernetes` wheels instead (below).
- **The frozen run's 'full system' used the Brev GPU worker** (reviewer `nvidia/NVIDIA-Nemotron-Nano-9B-v2` on vLLM plus weight/behaviour checks). The hosted API does not list that model, so this run's reviewer is `nvidia/nemotron-3.5-lightning-30b-a3b (not run)`, a different and larger model, in precise mode. **Reviewer numbers are not directly comparable with the frozen run**, and there is no GPU, so weight, behaviour and Notary checks are `CHECK.NOT_RUN.*` here.
- Two policies per run: *as shipped* prices every unrun check (a model without the GPU checks carries risk in staging) and *unrun = info* prices them at 0 so the detectors can be compared with the frozen run, where those checks were simply absent. Flagged = `block` or risk above 30 (staging), as before.

## Detection on the synthetic sets

| set | frozen full system (Brev worker) | frozen static only | after: static only, unrun = info | after: static only, as shipped | after: hosted reviewer, unrun = info | after: hosted reviewer, as shipped |
|---|---|---|---|---|---|---|
| **in-sample (bench/corpus)** | TPR 91% (62/68; 82-96%) / FPR 6% (4/63; 2-15%) | TPR 90% (61/68; 80-95%) / FPR 6% (4/63; 2-15%) | TPR 56% (38/68; 44-67%) / FPR 0% (0/63; -0-6%) | TPR 56% (38/68; 44-67%) / FPR 16% (10/63; 9-27%) | not run | not run |
| **dev (bench/corpus_holdout)** | TPR 100% (40/40; 91-100%) / FPR 0% (0/40; -0-9%) | TPR 100% (40/40; 91-100%) / FPR 0% (0/40; -0-9%) | TPR 100% (40/40; 91-100%) / FPR 0% (0/40; -0-9%) | TPR 100% (40/40; 91-100%) / FPR 15% (6/40; 7-29%) | not run | not run |
| **FINAL synthetic (bench/corpus_final)** | TPR 70% (28/40; 55-82%) / FPR 5% (2/40; 1-17%) | TPR 68% (27/40; 52-80%) / FPR 5% (2/40; 1-17%) | TPR 88% (35/40; 74-95%) / FPR 5% (2/40; 1-17%) | TPR 92% (37/40; 80-97%) / FPR 20% (8/40; 10-35%) | not run | not run |

Frozen TPR/FPR cells are `TPR x (tp/n) / FPR y (fp/n)`; intervals are Wilson 95%. Benign pickles refused only by `allow_pickle: false` are policy blocks and excluded from FPR in every column.

## Static only: latency and reviewer cost

| set (unrun = info) | intake p50 / p95 | timeouts | errors | reviewer calls | reviewer wall s | reviewer tokens |
|---|---|---|---|---|---|---|
| in-sample (bench/corpus) | 3 / 135 ms | 0 | 55 | 0 | 0 | 0 |
| dev (bench/corpus_holdout) | 7 / 162 ms | 0 | 0 | 0 | 0 | 0 |
| FINAL synthetic (bench/corpus_final) | 7 / 149 ms | 0 | 0 | 0 | 0 | 0 |

## Reviewer through the hosted API

Not run.

## Every miss and false alarm on the FINAL synthetic set (static only, unrun = info)

**Missed malicious: 5**
- `f_pkg_mal_git_hook_plant`: allow, risk 10; PROV.PUBLISHER.UNLISTED
- `f_tool_mal_undeclared_delete`: quarantine, risk 22; PROV.PUBLISHER.UNLISTED, TOOL.INTENT.UNDECLARED_FILESYSTEM
- `f_tool_mal_output_injection`: quarantine, risk 10; PROV.PUBLISHER.UNLISTED
- `f_tool_mal_markdown_beacon`: quarantine, risk 10; PROV.PUBLISHER.UNLISTED
- `f_tpl_mal_user_as_system`: allow, risk 15; LLM.CARD.MISSING, PROV.PUBLISHER.UNLISTED

**False alarms: 2**
- `f_pkg_ok_keyed_client`: block, risk 90; PKG.COMBO.CREDENTIAL_EXFIL, PKG.TAINT.ENV_EXFIL, PROV.PUBLISHER.UNLISTED
- `f_pkl_ok_purepath`: block, risk 60; LLM.CARD.MISSING, MODEL.PICKLE.DANGEROUS_GLOBAL, MODEL.PICKLE.PRESENT, PROV.PUBLISHER.UNLISTED

## Taint hang re-check on real wheels

Wheels downloaded with `pip download --no-deps` on this machine and scanned with `package_taint.scan` (budget 20 s, step cap 400k, file cap 400):

| package | before (frozen run, `results_final.md`) | after |
|---|---|---|
| black 26.10.1 | >30 min in `package_taint._bind` (hung) | 0.2 s |
| datasets 5.1.0 | timed out at 120 s in `_bind` | 0.6 s |
| kubernetes 37.0.1 | still parsing at 100 s | 7.2 s, `CHECK.NOT_RUN.TAINT_PARTIAL` (file cap) |

Root cause: an assignment like `x = f(x)` repeated thousands of times created one new taint with a longer path per assignment (quadratic work). R4.1's loop-nesting and budget fixes were necessary but did not fix it; the per-variable taint merge in `_bind` did.


