"""S0 Acquire: get an artifact's bytes (REFACTOR_SPEC 4.2). Sources: `upload:<id>`, `hf:<repo>[@rev]`, `hf-dataset:<repo>[@rev]`,
`pypi:<name>==<ver>`, `mcp:upload:<id>`. Everything Lineage reads from a hub itself is `fetched`.

The hub endpoints are the Hugging Face / PyPI REST ones (`/api/models/<repo>/revision/<rev>`, `/<repo>/resolve/<rev>/<file>`,
`/pypi/<name>/<ver>/json`); `base_url` is configurable so tests and the bench use `tests/fakehub.py`. Plain httpx, not
`huggingface_hub`, so one code path serves the real hubs and the fake one.
"""
from __future__ import annotations

import hashlib
import os
import re
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

import httpx

HF_ALLOW = (".safetensors", ".json", ".txt", ".md", ".model", ".jinja", ".py", ".gguf")
HF_ALLOW_PREFIX = ("tokenizer",)
PICKLE_SUFFIXES = (".bin", ".pt", ".pkl", ".pickle", ".pth", ".ckpt")
PICKLE_LIMIT = 50 * 1024 * 1024


def hf_url(base: str | None = None) -> str:
    return (base or os.environ.get("LINEAGE_HF_URL") or os.environ.get("LINEAGE_HUB_URL") or "https://huggingface.co").rstrip("/")


def pypi_url(base: str | None = None) -> str:
    base = base or os.environ.get("LINEAGE_PYPI_URL") or os.environ.get("LINEAGE_HUB_URL")
    return (base.rstrip("/") + "/pypi") if base else "https://pypi.org/pypi"


class AcquireError(Exception):
    """The bytes could not be obtained (network down, unknown repo, size cap). Becomes CHECK.NOT_RUN.ACQUIRE."""


class NotFound(AcquireError):
    """The hub answered 404: the repo or file is gone (as opposed to the hub being unreachable)."""


@dataclass
class Acquired:
    path: Path  # what intake inspects (a directory, or a single file)
    record: dict = field(default_factory=dict)  # hub metadata, in the shape the inspectors read
    fetched: bool = False  # Lineage fetched it from the hub itself
    distribution: dict[str, str] | None = None  # {filename, sha256}: the wheel to serve from /simple
    dist_path: Path | None = None
    notes: list[tuple[str, str, str]] = field(default_factory=list)  # (finding id, title, severity): problems found while fetching
    skipped_files: list[str] = field(default_factory=list)


def max_fetch_bytes() -> int:
    return int(os.environ.get("LINEAGE_MAX_FETCH_MB", "4096")) * 1024 * 1024


def max_upload_bytes() -> int:
    return int(os.environ.get("LINEAGE_MAX_UPLOAD_MB", "2048")) * 1024 * 1024


def safe_extract(archive: Path, dest: Path, limit: int | None = None) -> None:
    """Extract a .zip / .tar.gz refusing absolute paths, `..`, links and anything over `limit` bytes in total."""
    limit = limit if limit is not None else max_upload_bytes()
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    total = 0

    def check(name: str) -> Path:
        target = (dest / name).resolve()
        if name.startswith(("/", "\\")) or ".." in Path(name).parts or not str(target).startswith(str(root)):
            raise AcquireError(f"unsafe path in archive: {name}")
        return target

    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as z:
            for info in z.infolist():
                total += info.file_size
                if total > limit:
                    raise AcquireError("archive exceeds the size cap")
                target = check(info.filename)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with z.open(info) as src, target.open("wb") as out:
                    out.write(src.read())
    elif tarfile.is_tarfile(archive):
        with tarfile.open(archive) as t:
            for m in t.getmembers():
                if m.issym() or m.islnk() or m.isdev():
                    raise AcquireError(f"link or device in archive: {m.name}")
                total += m.size
                if total > limit:
                    raise AcquireError("archive exceeds the size cap")
                target = check(m.name)
                if m.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif m.isfile():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    f = t.extractfile(m)
                    target.write_bytes(f.read() if f else b"")
    else:
        raise AcquireError(f"{archive.name} is not a zip or tar archive")


def _git_oid(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()  # noqa: S324 - git's object id, not a security hash


def parse_origin(origin: str) -> tuple[str, str, str | None]:
    """`hf:org/name@rev` -> ("model", "org/name", "rev"); `hf-dataset:` -> "dataset"; `pypi:name==1.0` -> ("pypi", "name", "1.0")."""
    kind, _, rest = origin.partition(":")
    if kind == "hf":
        repo, _, rev = rest.partition("@")
        return "model", repo, rev or None
    if kind == "hf-dataset":
        repo, _, rev = rest.partition("@")
        return "dataset", repo, rev or None
    if kind == "pypi":
        name, _, ver = rest.partition("==")
        return "pypi", name, ver or None
    raise AcquireError(f"unsupported source {origin!r}")


def hf_info(repo: str, rev: str | None, kind: str = "model", base_url: str | None = None, client: httpx.Client | None = None) -> dict:
    prefix = "datasets" if kind == "dataset" else "models"
    url = f"{hf_url(base_url)}/api/{prefix}/{quote(repo, safe='/')}" + (f"/revision/{quote(rev, safe='')}" if rev else "")
    try:
        r = (client or httpx).get(url, params={"blobs": "true"}, timeout=30.0)
    except httpx.HTTPError as e:
        raise AcquireError(f"hub unreachable: {e}") from e
    if r.status_code == 404:
        raise NotFound(f"{repo}{'@' + rev if rev else ''}: hub answered HTTP 404")
    if r.status_code != 200:
        raise AcquireError(f"{repo}{'@' + rev if rev else ''}: hub answered HTTP {r.status_code}")
    return r.json()


def published_files(origin: str, base_url: str | None = None, client: httpx.Client | None = None) -> dict[str, dict] | None:
    """path -> {sha256?, git_oid?, size} as the hub published them at a pinned revision, or None if it cannot be checked."""
    kind, repo, rev = parse_origin(origin)
    try:
        if kind == "pypi":
            r = (client or httpx).get(f"{pypi_url(base_url)}/{repo}/{rev}/json", timeout=30.0)
            if r.status_code != 200:
                return None
            return {u["filename"]: {"sha256": u["digests"]["sha256"]} for u in r.json().get("urls", [])}
        info = hf_info(repo, rev, kind, base_url, client)
    except (AcquireError, httpx.HTTPError, ValueError, KeyError):
        return None
    out = {}
    for s in info.get("siblings", []):
        e = {"size": s.get("size")}
        if s.get("lfs", {}).get("sha256"):
            e["sha256"] = s["lfs"]["sha256"]
        if s.get("blobId"):
            e["git_oid"] = s["blobId"]
        out[s["rfilename"]] = e
    return out


def _wanted(name: str) -> bool:
    base = name.rsplit("/", 1)[-1]
    return name.endswith(HF_ALLOW) or base.startswith(HF_ALLOW_PREFIX) or name.endswith(PICKLE_SUFFIXES)


def fetch_hf(origin: str, dest: Path, *, allow_pickle: bool = False, base_url: str | None = None, client: httpx.Client | None = None) -> Acquired:
    kind, repo, rev = parse_origin(origin)
    info = hf_info(repo, rev, kind, base_url, client)
    sha = info.get("sha") or rev or "main"
    cap = max_fetch_bytes()
    total = 0
    acq = Acquired(path=dest, fetched=True)
    dest.mkdir(parents=True, exist_ok=True)
    resolve = f"{hf_url(base_url)}/{'datasets/' if kind == 'dataset' else ''}{quote(repo, safe='/')}/resolve/{quote(sha, safe='')}"
    for s in info.get("siblings", []):
        name = s["rfilename"]
        size = int(s.get("size") or 0)
        if not _wanted(name):
            continue
        if name.endswith(PICKLE_SUFFIXES) and size > PICKLE_LIMIT and not allow_pickle:
            acq.skipped_files.append(name)  # recorded, not downloaded
            continue
        total += size
        if total > cap:
            raise AcquireError(f"{repo} exceeds LINEAGE_MAX_FETCH_MB")
        target = dest / name
        if ".." in Path(name).parts or name.startswith("/"):
            raise AcquireError(f"unsafe file name from hub: {name}")
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            r = (client or httpx).get(f"{resolve}/{quote(name)}", timeout=300.0)
        except httpx.HTTPError as e:
            raise AcquireError(f"hub unreachable: {e}") from e
        if r.status_code != 200:
            raise AcquireError(f"{name}: hub answered HTTP {r.status_code}")
        target.write_bytes(r.content)
        want = s.get("lfs", {}).get("sha256")
        if want and hashlib.sha256(r.content).hexdigest() != want:
            acq.notes.append(("INTEGRITY.FETCH_MISMATCH", f"{name} downloaded from the hub does not match the hash the hub published", "critical"))
        elif s.get("blobId") and not want and _git_oid(r.content) != s["blobId"]:
            acq.notes.append(("INTEGRITY.FETCH_MISMATCH", f"{name} downloaded from the hub does not match its git object id", "critical"))
    card = info.get("cardData") or {}
    acq.record = {k: v for k, v in {
        "repo": repo, "publisher": repo.split("/")[0], "source_revision": sha, "released_at": info.get("lastModified"),
        "licence": card.get("license"), "claimed_base": card.get("base_model") if isinstance(card.get("base_model"), str) else None,
        "description": card.get("description"),
    }.items() if v}
    return acq


def fetch_pypi(origin: str, dest: Path, *, base_url: str | None = None, client: httpx.Client | None = None) -> Acquired:
    _, name, ver = parse_origin(origin)
    root = pypi_url(base_url)
    try:
        r = (client or httpx).get(f"{root}/{name}/{ver}/json" if ver else f"{root}/{name}/json", timeout=30.0)
    except httpx.HTTPError as e:
        raise AcquireError(f"hub unreachable: {e}") from e
    if r.status_code != 200:
        raise AcquireError(f"pypi {name}{'==' + ver if ver else ''}: HTTP {r.status_code}")
    meta = r.json()
    info = meta.get("info", {})
    ver = info.get("version") or ver
    urls = meta.get("urls", [])
    pick = next((u for u in urls if u.get("packagetype") == "bdist_wheel"), None) or next((u for u in urls if u.get("packagetype") == "sdist"), None)
    if pick is None:
        raise AcquireError(f"pypi {name}=={ver}: no wheel or sdist")
    url = pick["url"] if pick["url"].startswith("http") else (base_url or os.environ.get("LINEAGE_PYPI_URL") or os.environ.get("LINEAGE_HUB_URL") or "").rstrip("/") + pick["url"]
    try:
        blob = (client or httpx).get(url, timeout=300.0).content
    except httpx.HTTPError as e:
        raise AcquireError(f"hub unreachable: {e}") from e
    dest.mkdir(parents=True, exist_ok=True)
    got = hashlib.sha256(blob).hexdigest()
    acq = Acquired(path=dest, fetched=True, distribution={"filename": pick["filename"], "sha256": got})
    if got != pick["digests"]["sha256"]:
        acq.notes.append(("INTEGRITY.FETCH_MISMATCH", f"{pick['filename']} downloaded from the index does not match the sha256 the index published", "critical"))
    archive = dest.parent / pick["filename"]
    archive.write_bytes(blob)
    try:
        safe_extract(archive, dest)
    except AcquireError:
        archive.unlink(missing_ok=True)
        raise
    acq.dist_path = archive  # kept: the wheel itself goes into the store and is what the package index serves
    stamp = pick.get("upload_time_iso_8601")
    acq.record = {**meta, "name": name, "version": ver, "released_at": stamp, "repo": (info.get("project_urls") or {}).get("Source") and
                  re.sub(r"^https?://(www\.)?github\.com/", "", (info.get("project_urls") or {}).get("Source", "")).strip("/") or None,
                  "description": info.get("summary"), "publisher": (info.get("author") or None)}
    acq.record = {k: v for k, v in acq.record.items() if v not in (None, "")}
    return acq
