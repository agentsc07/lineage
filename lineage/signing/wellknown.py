"""Outbound key distribution (REFACTOR_SPEC 7.3). A company publishes `/.well-known/lineage-keys.json` ([{name, key, scope}]); a customer
fetches it with `lineage verify --from https://example.com`, pins it on first use, and is warned when it later changes."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization

WELL_KNOWN = ".well-known/lineage-keys.json"


def key_id_of(public_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[:16]


def public_hex_of(pub_file: Path) -> str:
    key = serialization.load_pem_public_key(Path(pub_file).read_bytes())
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def publish(directory: Path, name: str, public_hex: str, scope: list[str]) -> Path:
    """Write (or update) `<directory>/.well-known/lineage-keys.json`, one entry per key."""
    f = Path(directory) / WELL_KNOWN
    f.parent.mkdir(parents=True, exist_ok=True)
    entries = [e for e in (json.loads(f.read_text()) if f.is_file() else []) if e["key"] != public_hex]
    entries.append({"name": name, "key": public_hex, "scope": scope or ["*"]})
    f.write_text(json.dumps(entries, indent=2))
    return f


def pin_file() -> Path:
    return Path(os.environ.get("LINEAGE_PINNED_KEYS", Path.home() / ".lineage" / "pinned-keys.json"))


def fetch(base_url: str, client: httpx.Client | None = None) -> list[dict]:
    r = (client or httpx).get(f"{base_url.rstrip('/')}/{WELL_KNOWN}", timeout=15.0)
    r.raise_for_status()
    data = r.json()
    if not isinstance(data, list) or not all({"name", "key"} <= set(e) for e in data):
        raise ValueError("not a lineage-keys.json document")
    return data


def pin(base_url: str, entries: list[dict], accept_change: bool = False) -> tuple[list[dict], str]:
    """Pin on first use. Returns (the keys to trust, "new" | "same" | "changed"). On a change the OLD pinned keys are returned (and kept)
    unless `accept_change`, so a swapped well-known file cannot silently replace a key you already trusted."""
    f = pin_file()
    pins = json.loads(f.read_text()) if f.is_file() else {}
    old = pins.get(base_url.rstrip("/"))
    canon = sorted(entries, key=lambda e: e["key"])
    if old is None or accept_change:
        status = "new" if old is None else "changed"
        pins[base_url.rstrip("/")] = canon
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(json.dumps(pins, indent=2))
        return canon, status
    if sorted(old, key=lambda e: e["key"]) == canon:
        return old, "same"
    return old, "changed"
