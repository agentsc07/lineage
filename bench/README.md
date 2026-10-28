# Benchmark

Evidence for the detection numbers, not part of the running application (but `bench/data_bench.py` is imported by the demo and some tests, so the folder stays here).

* `corpus/`, `corpus_holdout/`, `corpus_final/`: **inert** synthetic attack and benign samples built by `build_*.py`. Payloads only write a marker under `/tmp/lineage_marker_*` or call the closed port `127.0.0.1:9`; nothing exfiltrates or installs anything. They look malicious on purpose: they are what the scanners must catch. Never install them outside a sandbox.
* `results_*.md` / `results_*.json`: the reports. **Read `docs/CLAIMS.md` before quoting any number**: only the frozen FINAL column of `results_final.md` (28/40 on our own synthetic set) is held-out; in-sample and dev sets were tuned on; after-refactor numbers are post-hoc; GPU (LoRA AUROC) and live-reviewer numbers were not re-run on the current version.
* `run_*.py`, `report_*.py`: how the numbers were produced. Real PyPI wheels and Hugging Face templates are fetched by `fetch_*.py` and are not in the repository.
