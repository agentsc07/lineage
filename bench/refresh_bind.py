"""Re-issue the signed passports of the `bind` benchmark items in the current passport format (the committed ones predate the trust ladder and
passport v2, so they no longer parse). Each passport is of the *untampered* model (seeded, so it is regenerated exactly); the tampered copy on
disk is not touched. Keeps the item bytes and the manifest; replaces `passport.signed.json` and, if no private key exists, the bench key pair.

    uv run python -m bench.refresh_bind bench/corpus
"""
from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

from lineage.passport.build import build_passport
from lineage.schemas.passport import SourceRef
from lineage.signing.ed25519 import sign_passport
from lineage.signing.keys import generate_keypair, load_private_key
from tests.fixtures.builders import make_tiny_model


def main(root: Path) -> None:
    keys = root / "_keys" / "bench"
    if not (keys / "default.key").exists():
        (keys / "default.pub").unlink(missing_ok=True)  # the old public key has no private half on this machine
        generate_keypair(keys)
    priv = load_private_key(keys / "default.key")
    manifest = json.loads((root / "manifest.json").read_text())
    items = manifest["items"] if isinstance(manifest, dict) else manifest
    n = 0
    for it in items:
        if it["check"] != "bind":
            continue
        i = int(re.search(r"(\d+)$", it["id"]).group(1))
        with tempfile.TemporaryDirectory() as t:
            m = make_tiny_model(Path(t) / "model", seed=100 + i)
            signed = sign_passport(build_passport(m, "model", f"bench-model-{i}", "1", SourceRef(), trust_level="origin_verified"), priv, "bench")
        (root / it["path"] / "passport.signed.json").write_text(signed.model_dump_json(by_alias=True))
        n += 1
    print(f"re-issued {n} bind passports under {root}")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
