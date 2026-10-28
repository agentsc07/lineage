"""A Hugging Face compatible endpoint over the admitted store (REFACTOR_SPEC 5, optional): set `HF_ENDPOINT=http://<host>` and
`HF_TOKEN=<lineage token>` and `huggingface_hub` / `transformers` download admitted models from Lineage instead of the internet.

    GET /api/models/{repo}[/revision/{rev}]     model info: sha, siblings with size and lfs.sha256
    GET|HEAD /{repo}/resolve/{rev}/{file}       the bytes, with X-Repo-Commit, ETag and X-Linked-Size

Only artifacts whose attestation for the token's environment allows use are visible; everything else is a 404, as if the repo did not exist."""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse

from lineage.schemas.policy import PolicyPack
from lineage_server import attest, models, service
from lineage_server.auth import User, current_user
from lineage_server.deps import get_conn, get_policy

router = APIRouter()


def _find(request: Request, conn: sqlite3.Connection, policy: tuple[PolicyPack, bool], user: User, repo: str, rev: str | None, env: str | None):
    """(artifact id, commit sha, files) for the newest admitted model called `repo` that the token's environment may use."""
    e = env if (env and not getattr(request.app.state, "require_auth", True)) else user.env
    for r in conn.execute("SELECT id FROM artifacts WHERE artifact_type IN ('model', 'dataset') ORDER BY created_at DESC, rowid DESC").fetchall():
        signed = models.get_signed_passport(conn, r["id"])
        if signed is None:
            continue
        b = signed.passport.predicate
        if repo not in (b.source.repo, b.name):
            continue
        commit = b.source.commit or b.contents.merkle_root[:40]
        if rev not in (None, "main", "master", commit, commit[:7], b.contents.merkle_root):
            continue
        try:
            att = attest.issue(conn, request.app.state.signing_key, r["id"], policy[0], e, policy_expired=policy[1]).attestation
        except service.NotFound:
            continue
        if att.usable:
            return r["id"], commit, att.files
    raise HTTPException(404, f"Repository not found: {repo}")


@router.get("/api/models/{repo:path}/revision/{rev}")
def model_at(repo: str, rev: str, request: Request, env: str | None = None, conn: sqlite3.Connection = Depends(get_conn),
             policy=Depends(get_policy), user: User = Depends(current_user)) -> dict:
    return _info(request, conn, policy, user, repo, rev, env)


@router.get("/api/models/{repo:path}")
def model(repo: str, request: Request, env: str | None = None, conn: sqlite3.Connection = Depends(get_conn), policy=Depends(get_policy),
          user: User = Depends(current_user)) -> dict:
    return _info(request, conn, policy, user, repo, None, env)


def _info(request, conn, policy, user, repo, rev, env) -> dict:
    aid, commit, files = _find(request, conn, policy, user, repo, rev, env)
    store = request.app.state.store
    return {"id": repo, "modelId": repo, "sha": commit, "private": True, "tags": [], "disabled": False, "gated": False,
            "siblings": [{"rfilename": p, "size": store.blob_path(h).stat().st_size if store.has(h) else 0, "blobId": h[:40],
                          "lfs": {"sha256": h, "size": store.blob_path(h).stat().st_size if store.has(h) else 0, "pointerSize": 134}} for p, h in sorted(files.items())]}


@router.api_route("/{repo:path}/resolve/{rev}/{file:path}", methods=["GET", "HEAD"])
def resolve(repo: str, rev: str, file: str, request: Request, env: str | None = None, conn: sqlite3.Connection = Depends(get_conn),
            policy=Depends(get_policy), user: User = Depends(current_user)):
    aid, commit, files = _find(request, conn, policy, user, repo, rev, env)
    sha = files.get(file)
    store = request.app.state.store
    if sha is None or not store.has(sha):
        raise HTTPException(404, f"Entry not found: {file}")
    size = store.blob_path(sha).stat().st_size
    return FileResponse(store.blob_path(sha), headers={"X-Repo-Commit": commit, "ETag": f'"{sha}"', "X-Linked-Size": str(size), "X-Linked-ETag": f'"{sha}"',
                                                       "Accept-Ranges": "bytes"}, media_type="application/octet-stream")
