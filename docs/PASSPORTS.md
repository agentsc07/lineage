# Passports, signatures and the database

## The two passports

| | **Creator passport** | **Organisation passport** |
|---|---|---|
| Who makes it | the publisher or the team that trained the model (`lineage sign`, or `lineage run --key`) | the Lineage registry, at stage S6, for every artifact it processes |
| Signed with | the publisher's private key | the registry's private key (`lineage.db.key`) |
| Describes | the files the publisher released, its parents, inputs and package list, and what the publisher says (licence, ...) | the exact bytes Lineage inspected, the trust Lineage established, the risk score, a digest of the findings |
| Travels with | the artifact (`passport.json`, or `<file>.passport.json`) | stays in the registry; what leaves is the **attestation** |
| Who trusts it | an organisation, only if its policy lists the signing key (`trusted_publishers`) and the source is in that key's scope | clients that pinned the registry's public key (`lineage pull --pin`) |
| If edited | signature fails: `PROV.SIGNATURE.INVALID`, hard block | the attestation signature fails: `load-check` refuses |

Your understanding is right: a company publishes its public key (`lineage keygen --publish` puts it at `/.well-known/lineage-keys.json`) and ships a passport; the organisation's policy decides whether to trust that key and for which sources. The registry then makes its own passport, and from it its own signed **attestation**, which is the thing loaders actually trust.

## Fields of a passport (both kinds share this body)

Real example below is the creator passport that `lineage run --key` wrote in the demo (long values shortened). The wrapper is an in-toto-style statement:

```
passport.subject[0]            { name, digest.sha256 }        what the passport is about; sha256 = the Merkle root of the files
passport.predicateType         "https://lineage.dev/passport/v1"
passport.predicate:
  artifact_type, name, version
  source        { hub, repo, commit, url }                    where it came from ("local-run" for lineage run; "huggingface"/"pypi" from a hub)
  contents      { merkle_root, files{path: sha256}, tensors{name: sha256} }
  parents       [ "lp:…" ]                                    artifact ids it derives from
  action        { kind: train|fine-tune|build|intake, command[], env_sbom_digest }
  inputs        { path: sha256 }                              (lineage run) every file the process read
  sbom          [ { name, version, purl } ]                   (lineage run) the Python packages present
  facts         [ { key, value, provenance, source, at } ]    licence, base model, ... with their class
  trust_level   unknown | origin_verified | signed | recorded  (the verifier decides; a creator passport claims none)
  findings_digest, risk_score, certificates[]
  issued_by     { name, key_id }
  issued_at, expires_at
signature   base64 Ed25519 signature over the canonical JSON of `passport`
key_id      first 16 hex characters of the SHA-256 of the signer's public key
```

The artifact id `lp:…` is the SHA-256 of the canonical JSON of `passport`, so it changes whenever any field (including `issued_at`) changes.

## How the signature works

1. **Canonical JSON**: the passport is written with sorted keys and no spaces, so the same content always gives the same bytes (`lineage/schemas/passport.py::canonical_json`).
2. **Sign**: Ed25519 over those bytes with the private key (`lineage/signing/ed25519.py::sign_passport`).
3. **Verify**: anyone with the matching public key recomputes the canonical bytes and checks the signature (`verify_signed`). Any change to any field, including a single hash, makes it fail.
4. **Trust is separate from validity.** A signature can be perfectly valid and still not trusted: Lineage trusts a key only if (a) the organisation's policy lists it, (b) the source being admitted is inside that key's `scope`, and (c) it is not in `revoked_keys`. That is why a valid signature by an unknown key yields `UNTRUSTED_KEY` (medium), and a trusted key signing for a source outside its scope yields `SCOPE_MISMATCH`.
5. **Bytes are tied in by hashes.** The passport lists the SHA-256 of every file; intake recomputes them and any difference is `INTEGRITY.HASH_MISMATCH` (hard block).

The attestation (what `pull` and `load` trust) has the same structure: `{artifact_id, digest, files, outcome, environment, trust, policy_version, issued_at, expires_at, revoked}` plus a signature by the **registry** key, valid for 7 days (shorter if an approval expires sooner).

## What is `lineage.db`?

A single SQLite file that is the registry's memory. It is created by `lineage_server` on first start (`LINEAGE_DB`, default `lineage.db` in the folder you run from).

| Table | Holds |
|---|---|
| `artifacts`, `passports`, `findings`, `decisions` | every artifact processed, its registry passport, every finding, every decision (outcome, reasons, score) |
| `approvals`, `rejections`, `revocations` | who approved (with reason and expiry), rejected or revoked what |
| `edges`, `ghosts` | the lineage graph; `ghosts` are things referenced but never admitted |
| `artifact_meta`, `artifact_identity` | who requested it, the claimed origin and claims, the file table and facts shown on the identity panel |
| `policy_state`, `role_keys`, `trusted_keys` | the active policy (versioned, with signatures), the three role keys that may change it, trusted keys |
| `users` | API tokens (hashed) and roles |
| `log` | an append-only Merkle log of events (update and delete are blocked by triggers) |
| `jobs`, `job_events` | intake runs and their stage events, so a reload rebuilds the page |
| `monitor_ticks`, `fl_*`, `tool_pins` | monitor results, federated-learning rounds, MCP tool pins |

Next to it: **`lineage.db.key` is the registry's private signing key. Never commit or share it** (`*.db` and `*.db.key` are git-ignored). Anyone with it can issue attestations your clients will trust. The demo moves both aside and creates new ones on every run, which is why tokens and the pinned registry key change after each restart of `run_dashboard_demo.sh`. The bytes themselves are in `lineage-store/` (a folder, not the database).
