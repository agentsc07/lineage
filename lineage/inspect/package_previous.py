"""Find and unpack the release that came before the one being reviewed (wheel only, `pip download --no-deps`).

Diff-aware review needs a baseline. A baseline can be given as a local folder (`previous_path` in the sidecar
metadata, used by tests and the bench) or fetched from PyPI. A wheel is unpacked, never built: building an sdist
would run the very setup code the review is about.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

PYPI_JSON = "https://pypi.org/pypi/{name}/json"
CACHE = Path.home() / ".cache" / "lineage" / "previous"
MAX_TRIES = 3


def _version_key(v: str):
    try:
        from packaging.version import InvalidVersion, Version

        try:
            return Version(v)
        except InvalidVersion:
            return None
    except ImportError:  # pragma: no cover - packaging ships with pip/setuptools
        return tuple(int(x) for x in re.findall(r"\d+", v)) or None


def candidate_versions(releases: dict[str, list[dict]], current: str, limit: int = MAX_TRIES) -> list[str]:
    """Versions older than `current`, newest first, that have an installable wheel and were not yanked.
    Pre-releases are skipped unless `current` is one."""
    cur = _version_key(current)
    if cur is None:
        return []
    cur_pre = bool(getattr(cur, "is_prerelease", False))
    out = []
    for v, files in releases.items():
        k = _version_key(v)
        if k is None or k >= cur or (getattr(k, "is_prerelease", False) and not cur_pre):
            continue
        if any(f.get("packagetype") == "bdist_wheel" and not f.get("yanked") for f in files):
            out.append((k, v))
    return [v for _, v in sorted(out, reverse=True)[:limit]]


def _pip_cmd() -> list[str] | None:
    """A way to run pip: this interpreter's, else a pip on PATH."""
    if subprocess.run([sys.executable, "-m", "pip", "--version"], capture_output=True).returncode == 0:
        return [sys.executable, "-m", "pip"]
    exe = shutil.which("pip3") or shutil.which("pip")
    return [exe] if exe else None


def download_wheel(name: str, version: str, dest: Path, pip_args: list[str] | None = None, timeout: int = 300) -> Path | None:
    """`pip download --no-deps --only-binary=:all: name==version`, unzipped into `dest`. None if there is no wheel."""
    pip = _pip_cmd()
    if pip is None:
        return None
    with tempfile.TemporaryDirectory() as td:
        r = subprocess.run([*pip, "download", "--no-deps", "--only-binary=:all:", "-d", td, "-q", *(pip_args or []), f"{name}=={version}"],
                           capture_output=True, text=True, timeout=timeout)
        wheels = list(Path(td).glob("*.whl"))
        if r.returncode or not wheels:
            return None
        dest.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(wheels[0]) as z:
            z.extractall(dest)  # zipfile drops absolute paths and ".." components
    return dest


def previous_release(name: str, version: str, *, pip_args: list[str] | None = None, cache: Path | None = None) -> tuple[Path, str] | None:
    """(unpacked folder, version) of the newest earlier release that has a wheel, or None (offline, unknown, no wheel).
    Never raises: a missing baseline degrades the review to single-release mode."""
    if os.environ.get("LINEAGE_OFFLINE"):
        return None
    cache = cache or CACHE
    try:
        req = urllib.request.Request(PYPI_JSON.format(name=name), headers={"User-Agent": "lineage/0.1"})
        with urllib.request.urlopen(req, timeout=20) as r:
            releases = json.loads(r.read()).get("releases", {})
    except Exception:  # noqa: BLE001 - network, DNS, JSON: all mean "no baseline"
        return None
    for v in candidate_versions(releases, version):
        dest = cache / f"{name.lower()}-{v}"
        if dest.is_dir() and any(dest.iterdir()):
            return dest, v
        try:
            if download_wheel(name, v, dest, pip_args):
                return dest, v
        except Exception:  # noqa: BLE001
            continue
        shutil.rmtree(dest, ignore_errors=True)
    return None
