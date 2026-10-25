"""`lineage.load()`: re-check an artifact against its passport at the moment of use (Track A)."""
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
_REMOTE_CODE_TRUST = {"inspected", "recorded", "attested"}


class LoadRefused(Exception):
    """Raised when hashes mismatch, a file is unpinned, or policy forbids the format."""


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


def _verified(path, passport, policy, public_key, loader_kwargs) -> SignedPassport:
    path = Path(path)
    passport = passport or _discover_passport(path)
    if passport is None:
        raise LoadRefused(f"no passport for {path}: refusing to load an unpinned artifact")
    problems = check(path, passport, policy, public_key=public_key)
    if loader_kwargs.get("trust_remote_code") and passport.passport.predicate.trust_level not in _REMOTE_CODE_TRUST:
        problems.append(
            f"trust_remote_code requires trust level inspected or higher (passport is {passport.passport.predicate.trust_level})"
        )
    if problems:
        raise LoadRefused(f"refusing to load {path}:\n  - " + "\n  - ".join(problems))
    return passport


def load(
    path: Path,
    passport: SignedPassport | None = None,
    policy: PolicyPack | None = None,
    *,
    public_key: Ed25519PublicKey | None = None,
    **loader_kwargs: Any,
) -> Any:
    """Re-hash `path` against the passport; refuse on mismatch, on pickle (per policy) and on unpinned files.

    The passport defaults to `<path>.passport.json` or `<path>/passport.json`. Returns, in order of preference:
    a transformers model (if `transformers` is installed and the directory has a config.json), a dict of numpy
    arrays (a single .safetensors), or the verified Path (datasets, packages, tools).

    The check and the load are separate reads; for hostile filesystems, load from a read-only mount.
    """
    path = Path(path)
    _verified(path, passport, policy, public_key, loader_kwargs)
    if path.is_dir() and (path / "config.json").is_file():
        try:
            cls = _transformers_class()
        except ImportError:
            cls = None
        if cls is not None:
            return cls.from_pretrained(path, use_safetensors=True, **loader_kwargs)
    st = [path] if path.suffix == ".safetensors" else sorted(path.glob("*.safetensors")) if path.is_dir() else []
    if st:
        from safetensors.numpy import load_file

        out: dict[str, Any] = {}
        for f in st:
            out.update(load_file(str(f)))
        return out
    return path


class LineageAutoModel:
    """Drop-in for `transformers.AutoModelForCausalLM`: `from_pretrained` verifies, then delegates.

    Always passes `use_safetensors=True`, so transformers will not fall back to a pickle checkpoint.
    """

    @classmethod
    def from_pretrained(
        cls,
        path: str | Path,
        *model_args: Any,
        passport: SignedPassport | None = None,
        policy: PolicyPack | None = None,
        public_key: Ed25519PublicKey | None = None,
        auto_class: Any = None,
        **kwargs: Any,
    ) -> Any:
        _verified(path, passport, policy, public_key, kwargs)
        auto_class = auto_class or _transformers_class()
        kwargs["use_safetensors"] = True
        return auto_class.from_pretrained(path, *model_args, **kwargs)
