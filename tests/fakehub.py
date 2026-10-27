"""A test-only stand-in for Hugging Face and PyPI (REFACTOR_SPEC 11.2). Tests, the benchmark and the demo fetch from it, so
none needs the internet and `fetched` facts stay `fetched` (Lineage reads them from the hub, never from the upload).

Two faces:
- `StaticHub`: in-process `lineage.intake.hub.Hub` returning fixed records (what `lineage.meta.json` used to carry).
- `create_app(root, records)`: a FastAPI app serving
    GET /lineage-meta/{type}/{key}                  the record for `key` (what `HttpHub` reads)
    GET /api/models/{repo}[/revision/{rev}]         HF model info with `siblings` (rfilename, size, lfs.sha256) and `sha`
    GET /api/datasets/{repo}[/revision/{rev}]       same for datasets
    GET /{repo}/resolve/{rev}/{file}                the file bytes, with X-Repo-Commit / ETag / X-Linked-Size headers
    GET /pypi/{name}/{version}/json                 PyPI JSON (info, urls with digests)
    GET /files/{name}/{file}                        wheel / sdist bytes
  Fixture layout under `root`:  models/<org>/<name>/..., datasets/<org>/<name>/..., pypi/<name>/<version>/<files>
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import FileResponse, JSONResponse

OLD = "2025-01-01T00:00:00Z"


class StaticHub:
    """Returns `record` for every key (or the entry of `records` for that key / `default`)."""

    def __init__(self, record: dict | None = None, records: dict[str, dict] | None = None, default: dict | None = None):
        self.records, self.default = records or {}, default if default is not None else record
        self.calls: list[tuple[str, str]] = []

    def fetch(self, artifact_type: str, key: str) -> dict | None:
        self.calls.append((artifact_type, key))
        rec = self.records.get(key, self.default)
        return dict(rec) if rec is not None else None


def old_release_hub(**extra) -> StaticHub:
    """A hub that vouches for an old release date and an allowed licence: cooldown cleared, nothing else asserted."""
    return StaticHub({"released_at": OLD, "licence": "mit", **extra})


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _git_blob_id(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()  # noqa: S324 - git's own object id, not a security hash


def _tree_sha(files: list[Path], root: Path) -> str:
    h = hashlib.sha1()  # noqa: S324
    for f in sorted(files):
        h.update(f.relative_to(root).as_posix().encode() + _sha256(f).encode())
    return h.hexdigest()


class _Records(dict):
    """`records`, or a JSON file re-read on every access (the demo edits release dates while the hub is running)."""

    def __init__(self, data: dict | None, path: Path | None):
        super().__init__(data or {})
        self.path = path

    def _fresh(self) -> dict:
        if self.path and self.path.is_file():
            return json.loads(self.path.read_text() or "{}")
        return dict(self)

    def __contains__(self, k):  # type: ignore[override]
        return k in self._fresh()

    def __getitem__(self, k):
        return self._fresh()[k]

    def get(self, k, default=None):  # type: ignore[override]
        return self._fresh().get(k, default)


def create_app(root: Path | str, records: dict[str, dict] | None = None, *, records_file: Path | str | None = None,
               big: int = 10 * 1024 * 1024) -> FastAPI:
    root = Path(root)
    records = _Records(records, Path(records_file) if records_file else None)
    app = FastAPI(title="fake hub")

    @app.get("/lineage-meta/{artifact_type}/{key:path}")
    def meta(artifact_type: str, key: str):
        if key not in records:
            raise HTTPException(404, key)
        return records[key]

    def info(kind: str, repo: str, rev: str | None):
        base = root / kind / repo
        if not base.is_dir():
            raise HTTPException(404, repo)
        files = sorted(p for p in base.rglob("*") if p.is_file() and p.name != "hub.json")
        sha = _tree_sha(files, base)
        siblings = []
        for f in files:
            e = {"rfilename": f.relative_to(base).as_posix(), "size": f.stat().st_size, "blobId": _git_blob_id(f)}
            if f.stat().st_size >= big or f.suffix in (".safetensors", ".bin", ".gguf"):
                e["lfs"] = {"sha256": _sha256(f), "size": f.stat().st_size}
            siblings.append(e)
        extra = records.get(f"{'hf' if kind == 'models' else 'hf-dataset'}:{repo}", {})
        return {"id": repo, "sha": sha, "lastModified": extra.get("released_at", OLD), "siblings": siblings,
                "cardData": {"license": extra.get("licence"), "base_model": extra.get("claimed_base")}, "author": repo.split("/")[0]}

    @app.get("/api/models/{repo:path}/revision/{rev}")
    def model_rev(repo: str, rev: str):
        return info("models", repo, rev)

    @app.get("/api/models/{repo:path}")
    def model(repo: str):
        return info("models", repo, None)

    @app.get("/api/datasets/{repo:path}/revision/{rev}")
    def dataset_rev(repo: str, rev: str):
        return info("datasets", repo, rev)

    @app.get("/api/datasets/{repo:path}")
    def dataset(repo: str):
        return info("datasets", repo, None)

    @app.get("/{repo:path}/resolve/{rev}/{file:path}")
    def resolve(repo: str, rev: str, file: str):
        for kind in ("models", "datasets"):
            p = root / kind / repo / file
            if p.is_file():
                return FileResponse(p, headers={"X-Repo-Commit": rev, "ETag": f'"{_git_blob_id(p)}"', "X-Linked-Size": str(p.stat().st_size)})
        raise HTTPException(404, file)

    @app.get("/pypi/{name}/{version}/json")
    def pypi(name: str, version: str):
        d = root / "pypi" / name / version
        if not d.is_dir():
            raise HTTPException(404, name)
        urls = [{"filename": f.name, "url": f"/files/{name}/{f.name}", "digests": {"sha256": _sha256(f)},
                 "packagetype": "bdist_wheel" if f.suffix == ".whl" else "sdist", "upload_time_iso_8601": records.get(f"pypi:{name}=={version}", {}).get("released_at", OLD)}
                for f in sorted(d.iterdir()) if f.is_file()]
        meta = records.get(f"pypi:{name}=={version}", {})
        return JSONResponse({"info": {"name": name, "version": version, "summary": meta.get("description", ""), "author": meta.get("author", ""),
                                      "project_urls": meta.get("project_urls", {}), "requires_dist": meta.get("requires_dist", [])}, "urls": urls})

    @app.get("/files/{name}/{file}")
    def pypi_file(name: str, file: str):
        for v in (root / "pypi" / name).glob("*"):
            if (v / file).is_file():
                return FileResponse(v / file)
        return Response(status_code=404)

    return app


if __name__ == "__main__":  # python -m tests.fakehub --root DIR --records FILE --port 8766
    import argparse

    import uvicorn

    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--records", default=None)
    ap.add_argument("--port", type=int, default=8766)
    a = ap.parse_args()
    uvicorn.run(create_app(a.root, records_file=a.records), host="127.0.0.1", port=a.port, log_level="warning")
