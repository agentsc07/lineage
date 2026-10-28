"""`lineage.load()`: re-check an artifact against the registry's decision attestation at the moment of use (REFACTOR_SPEC section 5).

The creator passport is evidence inside the intake record; it is no longer used at load time. `check()` below (passport hashes) is kept
for the benchmark's tamper items."""
from __future__ import annotations

import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lineage.passport.verify import check_contents
from lineage.schemas.passport import SignedPassport
from lineage.schemas.policy import PolicyPack
from lineage.signing.ed25519 import verify_signed

_PICKLE_EXT = {".pkl", ".pickle", ".ckpt", ".joblib", ".dill"}
_MAYBE_PICKLE_EXT = {".pt", ".pth", ".bin"}
_REMOTE_CODE_TRUST = {"origin_verified", "signed", "recorded"}  # attestation trust needed for trust_remote_code


from lineage.client import LoadRefused  # noqa: E402  (re-exported: `from lineage.bind import LoadRefused`)


def _is_pickle(path: Path) -> bool:
    ext = path.suffix.lower()
    if ext in _PICKLE_EXT:
        return True
    if ext not in _MAYBE_PICKLE_EXT:
        return False
    try:
        if zipfile.is_zipfile(path):  # torch.save zip format keeps its pickle in <archive>/data.pkl
            with zipfile.ZipFile(path) as z:
                return any(n.endswith("data.pkl") for n in z.namelist())
        with open(path, "rb") as f:
            return f.read(1) == b"\x80"  # pickle protocol 2+ opcode
    except (OSError, zipfile.BadZipFile):
        return False


def find_pickle_files(path: Path) -> list[Path]:
    """Files under `path` that would be unpickled by a torch/joblib-style loader."""
    path = Path(path)
    files = [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.is_file())
    return [p for p in files if _is_pickle(p)]


def _discover_passport(path: Path) -> SignedPassport | None:
    for cand in (path.with_name(path.name + ".passport.json"), path / "passport.json"):
        if cand.is_file():
            return SignedPassport.model_validate_json(cand.read_text())
    return None


def check(
    path: Path,
    passport: SignedPassport,
    policy: PolicyPack | None = None,
    *,
    public_key: Ed25519PublicKey | None = None,
) -> list[str]:
    """Same checks as `load` without loading; returns a list of problems (empty = OK).

    Pickle is refused unless `policy.model_files.allow_pickle` is true (no policy means refuse).
    """
    path = Path(path)
    problems: list[str] = []
    if public_key is not None and not verify_signed(passport, public_key):
        problems.append("signature invalid")
    expires = passport.passport.predicate.expires_at
    if expires is not None and expires <= datetime.now(timezone.utc):
        problems.append(f"passport expired at {expires.isoformat()}")
    problems += check_contents(passport, path)
    allow_pickle = policy.model_files.allow_pickle if policy else False
    if not allow_pickle:
        root = path if path.is_dir() else path.parent
        for p in find_pickle_files(path):
            problems.append(f"pickle file refused by policy: {p.relative_to(root).as_posix()}")
    return problems


def _transformers_class():
    import transformers

    return transformers.AutoModelForCausalLM


def _verified(path, env, loader_kwargs, check_kwargs):
    from lineage import client

    path = Path(path)
    problems = client.check_for_use(path, env=env, **check_kwargs)
    if loader_kwargs.get("trust_remote_code"):
        att = check_kwargs.get("attestation")
        cached = client.cache_path(path)
        if att is None and cached.is_file():
            from lineage.schemas.attestation import SignedAttestation

            att = SignedAttestation.model_validate_json(cached.read_text())
        if att is None or att.attestation.trust not in _REMOTE_CODE_TRUST:
            problems.append(f"trust_remote_code requires attested trust origin_verified or higher (attestation says {att.attestation.trust if att else 'none'})")
    if problems:
        raise LoadRefused(f"refusing to load {path}:\n  - " + "\n  - ".join(problems))


def _split(kwargs: dict) -> tuple[dict, dict]:
    keys = ("attestation", "registry_pubkey", "server", "token", "offline_grace_hours", "allow_pickle", "now", "client")
    return {k: kwargs.pop(k) for k in keys if k in kwargs}, kwargs


def load(path: Path, *, env: str | None = None, **kwargs: Any) -> Any:
    """Refuse unless the registry attests this exact content for `env`; then load it.

    Needs a registry-signed attestation (`<path>.lineage-attestation.json` from `lineage pull`, else asked of the server), verified
    with the pinned registry key; outcome allow/allow_with_conditions for `env`; not expired; not revoked (online check, fail closed
    in prod if the registry is unreachable); every file re-hashed; pickle refused unless `allow_pickle=True`.
    Returns a transformers model if installed and the directory has a config.json, a dict of numpy arrays for .safetensors,
    else the verified Path. Extra keyword arguments go to the model loader.

    The check and the load are separate reads; for hostile filesystems, load from a read-only mount.
    """
    path = Path(path)
    check_kwargs, loader_kwargs = _split(dict(kwargs))
    _verified(path, env, loader_kwargs, check_kwargs)
    if path.is_dir() and (path / "config.json").is_file():
        try:
            cls = _transformers_class()
        except ImportError:
            cls = None
        if cls is not None:
            try:
                return cls.from_pretrained(path, use_safetensors=True, **loader_kwargs)
            except (ValueError, OSError):
                pass  # an architecture transformers does not know (for example a test model): the verified tensors below are still returned
    st = [path] if path.suffix == ".safetensors" else sorted(path.glob("*.safetensors")) if path.is_dir() else []
    if st:
        from safetensors.numpy import load_file

        out: dict[str, Any] = {}
        for f in st:
            out.update(load_file(str(f)))
        return out
    return path


class LineageAutoModel:
    """Drop-in for `transformers.AutoModelForCausalLM`: `from_pretrained` pulls (for `hf:org/repo` or an artifact id) or checks a
    local directory, verifies the attestation, then delegates. Always passes `use_safetensors=True`."""

    @classmethod
    def from_pretrained(cls, path: str | Path, *model_args: Any, env: str | None = None, auto_class: Any = None,
                        cache_dir: str | Path | None = None, **kwargs: Any) -> Any:
        from lineage import client

        check_kwargs, kwargs = _split(dict(kwargs))
        target = str(path)
        if target.startswith(("hf:", "lp:")):
            dest = Path(cache_dir or Path.home() / ".cache" / "lineage") / target.replace(":", "_").replace("/", "__")
            client.pull(target, dest, env=env or client.settings()["env"], server=check_kwargs.get("server"),
                        token=check_kwargs.get("token"), registry_pubkey=check_kwargs.get("registry_pubkey"), client=check_kwargs.get("client"))
            path = dest
        _verified(path, env, kwargs, check_kwargs)
        auto_class = auto_class or _transformers_class()
        kwargs["use_safetensors"] = True
        return auto_class.from_pretrained(path, *model_args, **kwargs)
