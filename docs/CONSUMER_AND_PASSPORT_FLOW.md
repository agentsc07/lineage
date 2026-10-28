# Consumer and passport flow

Everything marked **live** was run in this audit against a real server started by `examples/run_dashboard_demo.sh` (real CLI, real signing, real SQLite, fake hub), with the outputs below copied from the run.

## 1. Two passports, three different questions

| | Creator passport | Organisation passport | Attestation |
|---|---|---|---|
| Written by | the publisher (`lineage sign`, `lineage run`) | the registry, at every intake (`pipeline._build_passport`, signed by `registry.sign`) | the registry, per environment, when the decision allows use (`attest.issue`) |
| Signed with | publisher's Ed25519 key | the registry key | the registry key |
| Says | "these bytes are mine, from this source" | what Lineage found: files, hashes, findings digest, trust level, parents | "usable in env X until T under policy P" |
| Who trusts it | only if the key is in `policy.trusted_publishers` and the source is in its scope | the registry's own record (`lp:<sha256 of it>` is the id) | **the loader**: this is the only statement `pull` and `load` trust |

Five different guarantees, not to be confused: *valid signature* (the bytes of the JSON were signed by that key) is not *trusted key* (the policy lists it for this source), is not *verified content* (the files hash to what the passport pins), is not *organisation admission* (an attestation exists), is not *current permission to load* (not expired, not revoked, right environment, files unchanged at load time).

## 2. Creator passport path (source: `inspectors.signed_passport`, `pipeline._identify`)

1. **Discovery:** `<artifact>.passport.json` beside the file, or `passport.json` or `*.passport.json` inside the folder or archive. Hub fetches (`hf:`, `pypi:`) carry no creator passport: their trust comes from hashes Lineage fetched itself (`origin_verified`), never from a signature.
2. **Schema:** parsed as `SignedPassport` (Pydantic). A parse failure is `INTAKE.PASSPORT.MALFORMED` (medium).
3. **Signed bytes:** canonical JSON (sorted keys, no spaces) of the `passport` statement; **algorithm:** Ed25519; the signature carries a `key_id` (first 16 hex of the SHA-256 of the public key).
4. **Key source and trust:** the public key is **not taken from the passport**. It must be a `trusted_publishers` entry in the policy (name, key, scope globs). A key arriving with an upload is never trusted. If the policy lists no publishers, a dev-only `LINEAGE_TRUSTED_KEYS` fallback applies.
5. **Publisher mapping:** the policy entry gives the publisher name and scope; the passport's own `source.repo` / `issued_by.name` are displayed as "claimed" and decide nothing. A publisher may have several keys (several entries with one name).
6. **Checks in order:** revoked key (`revoked_keys`) -> unknown key -> signature -> scope (`fnmatch` of the passport's and the intake's source id against the key's scope) -> expiry -> every pinned file hash equals the hash computed from the bytes -> unpinned files.
7. **Outcomes:** all pass: facts become `signed`, trust `signed` (or `recorded` with inputs and an SBOM from `lineage run`). Any failure: trust stays below `signed` plus a finding: `PROV.SIGNATURE.INVALID` (critical, hard block), `INTEGRITY.HASH_MISMATCH` (critical, hard block), `PROV.SIGNATURE.REVOKED_KEY` (high), `SCOPE_MISMATCH` (high), `UNTRUSTED_KEY` (medium), `PASSPORT.EXPIRED` (medium), `INTEGRITY.UNPINNED_FILE` (medium).
8. **Parent chain** in the passport: each parent id is looked up in the registry (`parent_chain`): revoked = critical hard block, unknown = medium, not admitted = high.

Tests (all run the real pipeline in-process; result: pass): `tests/test_signature_scope.py` covers valid, out-of-scope publisher, unknown key, revoked key, invalid signature, **modified signed payload, expired, file changed after signing**, one publisher with two keys, malformed passport, bootstrap keys (12 tests; 4 were added in this audit). The uploaded passport **is consumed** by the pipeline (it is not merely detected): `signed_passport` runs on every intake and demo step 9 reaches trust `recorded` only through it.

## 3. Organisation passport and attestation

* Created at S7 (`service.record`, one transaction) for every outcome, including blocks; the attestation is issued per environment when the outcome allows use or a human approves (`service.approve`).
* Stored in SQLite (`passports`, `decisions`, `approvals`); bytes in the content store.
* Verified by: `lineage pull` (attestation signature against the **pinned** registry key, every file hash), `lineage load-check` and `lineage.load()` (the same, plus environment, expiry and a **live** revocation check), `lineage verify` (a passport file: signature, contents re-hashed, chain, revocation, scope).
* **Dashboard "Verify passport"** (`GET /passports/{id}/verify`): signature by a trusted key, id equals content, every ancestor registered and not revoked, not revoked, not expired. **It does not re-hash any files**; the UI message was corrected earlier so it no longer says it did. It is a check of the registry's record, not of the bytes on a laptop. Use `lineage load-check` for the bytes.

## 4. Live consumer journey (outputs copied from the run)

```
$ lineage pull triage-base ./m -e prod --pin
✓ pulled lp:388c01022173264c… (5 file(s)) into m: allow_with_conditions for prod, expires 2026-11-04 16:13 UTC
$ lineage load-check ./m -e prod
✓ load allowed
$ lineage pull lp:doesnotexist ./x -e prod
✗ the registry refused to attest (404): {"detail":"unknown artifact lp:doesnotexist"}
$ (corrupt one byte of ./m/model.safetensors in place) lineage load-check ./m -e prod
  ✗ hash mismatch: model.safetensors
✗ REFUSED: lineage.load() would raise LoadRefused
$ LINEAGE_TOKEN=<alice, requester> lineage revoke lp:388c…
✗ the registry at http://127.0.0.1:8011 refused (403): set LINEAGE_TOKEN to a token with the approver or admin role
$ LINEAGE_TOKEN=<carol, admin> lineage revoke lp:388c… --reason "audit test"
3 affected   (the last table row was triage-trained@1.0.0, blocked)
$ lineage load-check ./m -e prod        # the copy pulled BEFORE the revoke
  ✗ registry reports the artifact revoked
✗ REFUSED: lineage.load() would raise LoadRefused
$ python -c 'lineage.load("./m", environment="prod")'
LoadRefused refusing to load m: - registry reports the artifact revoked
$ lineage pull triage-base ./m4 -e prod        # after the revoke
✗ triage-base: not admitted for prod (404: no artifact usable in prod matches triage-base)
```

Also from the scripted demo: `lineage.load() ok: 18 tensor(s) loaded from the attested bytes` after approval; a tampered upload is blocked and never served; `pip download acme-llm==1.4.1` (blocked) fails and `acme-llm` resolves to the admitted 1.4.0.

Boundaries to state:
* The API **checks permission and bytes**; `lineage.load()` then loads the tensors (falling back to the verified tensors when `transformers` does not know the architecture). `load-check` is the dry run: it loads nothing.
* **Direct framework loading is a bypass**: `transformers.from_pretrained`, `torch.load`, `safetensors.load_file` on a path are not intercepted by Lineage. Protection holds only on Lineage's paths (`pull`, `load`, the pip index, the Hugging Face endpoint, the MCP gateway).
* A **copy pulled earlier is refused only through those paths**, and only while the registry is reachable: in `prod` an unreachable registry fails closed (`offline_grace_hours.prod = 0`), in `dev` a cached attestation is honoured for up to 24 hours, so a revoked artifact stays loadable in dev for that long if the server is down.
* With the attestation sidecar deleted, `load-check` still allowed the load: the loader looks the attestation up by content digest on the server (`test_attestation_by_digest_for_a_directory_without_cache`). That is by design; a file that is not in the registry has no digest to find and is refused (`no attestation for ...`).

## 5. Identifier consistency

`lp:<sha256>` appears unchanged in the intake result, approvals, catalogue, attestation, pull command, store paths and graph nodes (read from the same `artifacts.id`). Display names (`name@version`) differ per intake; the id is the key. The same bytes submitted twice receive two ids (timestamps are inside the passport); the second is flagged `INTAKE.DIGEST.KNOWN`. Hub revisions are shown shortened to 7 characters in the graph and in full in the catalogue.

## 6. Defect found and fixed in this flow

`lineage revoke` sent no token and ignored `LINEAGE_SERVER`, so against an auth-enabled server it could never succeed. It now reads the server and token the same way `pull` does and explains a 401/403 (`lineage/cli.py`; `tests/test_cli.py::test_revoke_uses_the_configured_server_and_sends_the_token` is a mocked-transport test; the live run above is the end-to-end proof).
