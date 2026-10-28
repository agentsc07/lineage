# Roadmap (not in the submission)

Future work, one line each. None of it is implemented.

- **Stream tickets:** the dashboard still passes the bearer token in the SSE URL; replace it with a short-lived single-job ticket (`POST /jobs/{id}/stream-ticket`).
- **GPU worker auth:** the worker has no authentication; require a shared bearer token (`LINEAGE_GPU_TOKEN`).
- **Creator passport and key at intake:** let an uploader attach a passport and a public key in the form. A supplied key must never become trusted; trust stays with the policy's `trusted_publishers` and their scope. (The five-check panel already reports signature, key status and bytes separately.)
- **Sigstore:** `lineage sign --sigstore` is hidden and experimental; nothing verifies the bundle. Verification (identity matching, Rekor proofs) is future work, and no Sigstore support is claimed.
- **Reviewer cost:** measure 20 direct hosted-reviewer calls (p50/p95 latency, tokens); the benchmark's subprocess counters read zero.
- **Real hub on a laptop:** run `LINEAGE_TEST_REAL_HUB=1 uv run pytest tests/test_real_hub.py`.
- in-toto / DSSE / SLSA export of passports
- CI/CD and Kubernetes admission integrations
- controlled training execution or traced package use
- new roles (publisher, security reviewer, platform admin)
- browser folder upload
- streaming hash progress for multi-GB files
- replacing the OSV checks with external scanners
