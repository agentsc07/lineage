# Reviewer ablation

Generated 2026-10-26T06:36:43+00:00 · worker `http://127.0.0.1:8800` · reviewer `nvidia/NVIDIA-Nemotron-Nano-9B-v2` · **SAMPLE RUN, not final** · flagged = block or risk > allow threshold · Wilson 95% intervals.

Static-only = GPU worker off (deterministic scanners). Static+reviewer = worker on (reviewer LLM and the other deep checks the worker serves).

| set | n | static TPR | static FPR | +reviewer TPR | +reviewer FPR | decisions changed | latency added (mean / p95) | GPU-s per artifact |
|---|---|---|---|---|---|---|---|---|
| corpus | 10 (5 mal / 5 ben) | 100% (57%–100%) | 0% (0%–43%) | 100% (57%–100%) | 0% (0%–43%) | 0 | -0.02 s / 0.00 s | 0.00 |
| corpus_holdout | – | not available: missing (bench/corpus_holdout/manifest.json not found) | | | | | | |
| pypi_top200_dev | – | not available: missing (bench/corpus_pypi_top200_dev/manifest.json not found) | | | | | | |
| hf_templates | – | not available: missing (bench/corpus_hf_templates/manifest.json not found) | | | | | | |
| corpus_final | – | not available: final set: pass --include-final to run it | | | | | | |
| pypi_201_400 | – | not available: final set: pass --include-final to run it | | | | | | |

> **Warning: the reviewer LLM was never called by intake in this run** (0 calls on the worker). Any difference between the two modes comes from the worker's other deep checks, not from the reviewer. Intake must call `/review/code` (`lineage.inspect.llm_review`) for this ablation to measure the reviewer.

## corpus

- Reviewer called on 0 of 10 intake items; 0 LLM calls, 0 generated tokens; 0.0 GPU-s total (0.00 per reviewed artifact); latency added on reviewed items 0.00 s on average.
- Risk scores changed on 2 items; lowered on 0 (must be 0: the worker may only raise).
- Flag raised (static: not flagged → with reviewer: flagged): none
- Flag lowered (static: flagged → with reviewer: not flagged): none
- Outcome changed, flag unchanged: none
