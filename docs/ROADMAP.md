# Roadmap (not in the submission)

Future work, one line each. None of it is implemented.

- **Not done from the final-pass brief (Block 3/4):** stream tickets instead of a bearer token in the SSE URL; a bearer token for the GPU worker (`LINEAGE_GPU_TOKEN`); `--sigstore` verification or hiding the flag (until then do not claim Sigstore support); optional creator passport and key at intake (the passport report is already shown, a supplied key never becomes trusted); graph evidence on click; re-measuring real-world false alarms; 20 direct hosted reviewer calls for latency and tokens; step 10 wording.
- in-toto / DSSE / SLSA export of passports
- Sigstore verification beyond the above (identity matching, Rekor proofs)
- CI/CD and Kubernetes admission integrations
- controlled training execution or traced package use
- new roles (publisher, security reviewer, platform admin)
- browser folder upload
- streaming hash progress for multi-GB files
- replacing the OSV checks with external scanners
