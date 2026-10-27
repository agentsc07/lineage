"""Use-time enforcement (REFACTOR_SPEC section 5, P4, P5). What an artifact may be used for is decided by a registry-signed
attestation for this environment, re-checked at the moment of use; nothing the artifact ships with is believed.

Configuration, in order: function arguments, environment (`LINEAGE_SERVER`, `LINEAGE_TOKEN`, `LINEAGE_REGISTRY_PUBKEY`,
`LINEAGE_ENV`), then `~/.lineage/config.toml`:

    server = "http://localhost:8000"
    token = "lg_..."
    registry_pubkey = "<ed25519 public key hex>"      # pinned; never read from an artifact
"""
from __future__ import annotations

import hashlib
import os
import tomllib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lineage.schemas.attestation import SignedAttestation
from lineage.schemas.passport import canonical_json
from cryptography.exceptions import InvalidSignature
import base64

DEFAULT_GRACE_HOURS = {"dev": 24, "staging": 6, "prod": 0}  # prod fails closed


class LoadRefused(Exception):
    """The artifact may not be used here: no valid attestation, wrong environment, expired, revoked, or the bytes changed."""


def config_file() -> Path:
    return Path(os.environ.get("LINEAGE_CONFIG", Path.home() / ".lineage" / "config.toml"))


def settings() -> dict:
    cfg: dict = {}
    f = config_file()
    if f.is_file():
        try:
            cfg = tomllib.loads(f.read_text())
        except (OSError, tomllib.TOMLDecodeError):
            cfg = {}
    return {
        "server": (os.environ.get("LINEAGE_SERVER") or cfg.get("server") or "").rstrip("/"),
        "token": os.environ.get("LINEAGE_TOKEN") or cfg.get("token"),
        "registry_pubkey": os.environ.get("LINEAGE_REGISTRY_PUBKEY") or cfg.get("registry_pubkey"),
        "env": os.environ.get("LINEAGE_ENV") or cfg.get("env") or "prod",
    }


def pin_registry_key(public_key_hex: str) -> Path:
    """Write the registry key into the config file (first use). Existing settings are kept."""
    f = config_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    lines = [l for l in (f.read_text().splitlines() if f.is_file() else []) if not l.startswith("registry_pubkey")]
    f.write_text("\n".join([*lines, f'registry_pubkey = "{public_key_hex}"']) + "\n")
    return f


def cache_path(path: Path) -> Path:
    return path.with_name(path.name + ".lineage-attestation.json")


def _headers(token: str | None) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"} if token else {}


def verify_attestation(signed: SignedAttestation, registry_pubkey: str | Ed25519PublicKey | None) -> bool:
    if registry_pubkey is None:
        return False
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(registry_pubkey)) if isinstance(registry_pubkey, str) else registry_pubkey
    try:
        key.verify(base64.b64decode(signed.signature, validate=True), canonical_json(signed.attestation))
    except (InvalidSignature, ValueError):
        return False
    return True


def hash_tree(path: Path) -> dict[str, str]:
    path = Path(path)
    if path.is_file():
        return {path.name: hashlib.sha256(path.read_bytes()).hexdigest()}
    return {p.relative_to(path).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(path.rglob("*")) if p.is_file() and ".git" not in p.parts}


def fetch_attestation(server: str, token: str | None, *, artifact_id: str | None = None, digest: str | None = None, env: str = "prod",
                      client: httpx.Client | None = None) -> SignedAttestation:
    url = f"{server}/attestations/{artifact_id}" if artifact_id else f"{server}/attestations"
    r = (client or httpx).get(url, params={"env": env, **({"digest": digest} if digest else {})}, headers=_headers(token), timeout=15.0)
    if r.status_code != 200:
        raise LoadRefused(f"the registry refused to attest ({r.status_code}): {r.text[:120]}")
    return SignedAttestation.model_validate(r.json())


def check_for_use(path: Path, *, env: str | None = None, attestation: SignedAttestation | None = None,
                  registry_pubkey: str | Ed25519PublicKey | None = None, server: str | None = None, token: str | None = None,
                  offline_grace_hours: int | None = None, allow_pickle: bool = False, now: datetime | None = None,
                  client: httpx.Client | None = None) -> list[str]:
    """Every reason `path` may not be used in `env` (empty = fine). This is `lineage.load()` without loading."""
    cfg = settings()
    path, env = Path(path), env or cfg["env"]
    server = cfg["server"] if server is None else server.rstrip("/")
    token = token or cfg["token"]
    pubkey = registry_pubkey or cfg["registry_pubkey"]
    now = now or datetime.now(timezone.utc)
    cached = cache_path(path)
    if attestation is None and cached.is_file():
        try:
            attestation = SignedAttestation.model_validate_json(cached.read_text())
        except ValueError:
            return [f"{cached.name} is not a valid attestation"]
    actual = hash_tree(path) if path.exists() else {}
    if attestation is None and server and actual:
        from lineage.intake.pipeline import _merkle_root

        try:
            attestation = fetch_attestation(server, token, digest=_merkle_root(actual), env=env, client=client)
        except (LoadRefused, httpx.HTTPError):
            attestation = None
    if attestation is None:
        return [f"no attestation for {path}: run `lineage pull` or pass one; refusing to use unattested bytes"]
    problems: list[str] = []
    att = attestation.attestation
    if pubkey is None:
        return ["no registry public key is pinned (LINEAGE_REGISTRY_PUBKEY or ~/.lineage/config.toml); cannot verify the attestation"]
    if not verify_attestation(attestation, pubkey):
        return ["attestation signature does not verify against the pinned registry key"]
    if att.environment != env:
        problems.append(f"attestation is for {att.environment}, not {env}")
    if att.revoked:
        problems.append("artifact is revoked")
    elif att.outcome not in ("allow", "allow_with_conditions"):
        problems.append(f"decision for {att.environment} is {att.outcome}")
    if att.expires_at <= now:
        problems.append(f"attestation expired {att.expires_at:%Y-%m-%d %H:%M} UTC")
    # (c) online revocation check; unreachable falls back to a cached attestation inside the grace period
    reachable = False
    if server:
        try:
            r = (client or httpx).get(f"{server}/passports/{att.artifact_id}/verify", headers=_headers(token), timeout=10.0)
            if r.status_code == 200:
                reachable = True
                if r.json().get("revoked"):
                    problems.append("registry reports the artifact revoked")
            elif r.status_code in (401, 403):
                problems.append(f"registry rejected our token ({r.status_code})")
                reachable = True
        except httpx.HTTPError:
            reachable = False
    if not reachable:
        grace = offline_grace_hours if offline_grace_hours is not None else DEFAULT_GRACE_HOURS.get(env, 0)
        if grace <= 0:
            problems.append(f"registry unreachable and no offline grace is allowed in {env} (fail closed)")
        elif now - att.issued_at > timedelta(hours=grace):
            problems.append(f"registry unreachable and the cached attestation is older than {grace} h")
    # (d) re-hash every file
    for rel, want in sorted(att.files.items()):
        if rel not in actual:
            problems.append(f"missing file: {rel}")
        elif actual[rel] != want:
            problems.append(f"hash mismatch: {rel}")
    for rel in sorted(set(actual) - set(att.files)):
        problems.append(f"unattested file: {rel}")
    # (e) pickle rules, as before
    if not allow_pickle:
        from lineage.bind import find_pickle_files

        root = path if path.is_dir() else path.parent
        for p in find_pickle_files(path):
            problems.append(f"pickle file refused by policy: {p.relative_to(root).as_posix()}")
    return problems


def resolve_artifact(server: str, token: str | None, ref: str, env: str, client: httpx.Client | None = None) -> str:
    """`lp:...` as is; anything else (`hf:org/name`, `pypi:name==1`, a name) is looked up among admitted artifacts."""
    if ref.startswith("lp:"):
        return ref
    r = (client or httpx).get(f"{server}/lookup", params={"source": ref, "env": env}, headers=_headers(token), timeout=15.0)
    if r.status_code != 200:
        raise LoadRefused(f"{ref}: not admitted for {env} ({r.status_code}: {r.text[:100]})")
    return r.json()["artifact_id"]


def pull(ref: str, dest: Path, *, env: str = "prod", server: str | None = None, token: str | None = None,
         registry_pubkey: str | None = None, client: httpx.Client | None = None) -> SignedAttestation:
    """Download an admitted artifact from the store, verify the attestation and every hash, write the attestation beside it."""
    cfg = settings()
    server = (server or cfg["server"]).rstrip("/")
    token, pubkey = token or cfg["token"], registry_pubkey or cfg["registry_pubkey"]
    if not server:
        raise LoadRefused("no server configured (LINEAGE_SERVER or ~/.lineage/config.toml)")
    aid = resolve_artifact(server, token, ref, env, client)
    signed = fetch_attestation(server, token, artifact_id=aid, env=env, client=client)
    if not verify_attestation(signed, pubkey):
        raise LoadRefused("attestation signature does not verify against the pinned registry key" if pubkey else "no registry public key is pinned")
    att = signed.attestation
    if not att.usable:
        raise LoadRefused(f"{aid[:19]} is not usable in {env}: {'revoked' if att.revoked else att.outcome}")
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    for rel, want in att.files.items():
        r = (client or httpx).get(f"{server}/store/{aid}/files/{rel}", params={"env": env}, headers=_headers(token), timeout=600.0)
        if r.status_code != 200:
            raise LoadRefused(f"{rel}: store answered {r.status_code}")
        if hashlib.sha256(r.content).hexdigest() != want:
            raise LoadRefused(f"{rel}: downloaded bytes do not match the attested hash")
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(r.content)
    cache_path(dest).write_text(signed.model_dump_json(indent=2))
    return signed
