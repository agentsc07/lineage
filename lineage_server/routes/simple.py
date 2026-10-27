"""A PEP 503 package index that serves only admitted wheels (REFACTOR_SPEC section 5, P4/P5).

    pip install --index-url http://<user>:<token>@<host>/simple/ <package>

`/simple/` and `/simple/<name>/` list the versions whose attestation for the token's environment is allow or allow-with-conditions,
as links to `/files/<sha256>/<filename>#sha256=<hash>`, so pip pins every download by hash. A blocked version is simply absent:
the newest admitted version is what resolves (compliant version selection). Asking for a project with nothing admitted starts an
intake of the latest release and answers 404 with the job in `X-Lineage-Intake-Job`."""
from __future__ import annotations

import html
import json
import re
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, Response

from lineage.schemas.artifact import IntakeRequest
from lineage.schemas.policy import PolicyPack
from lineage_server import attest, models, service
from lineage_server.auth import User, current_user
from lineage_server.deps import get_conn, get_policy

router = APIRouter()


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _env(user: User, env: str | None, request: Request) -> str:
    return env if (env and not getattr(request.app.state, "require_auth", True)) else user.env


def admitted_wheels(request: Request, conn: sqlite3.Connection, policy: tuple[PolicyPack, bool], env: str) -> list[dict]:
    """[{name, version, filename, sha256, artifact_id}] for every package whose attestation for `env` allows use."""
    out = []
    rows = conn.execute("SELECT a.id FROM artifacts a JOIN artifact_meta m ON m.artifact_id = a.id WHERE a.artifact_type = 'package'"
                        " AND m.distribution IS NOT NULL AND m.distribution != 'null' ORDER BY a.created_at, a.rowid").fetchall()
    for r in rows:
        dist = json.loads(conn.execute("SELECT distribution FROM artifact_meta WHERE artifact_id = ?", (r["id"],)).fetchone()["distribution"])
        signed = models.get_signed_passport(conn, r["id"])
        if not dist or signed is None:
            continue
        try:
            if not attest.issue(conn, request.app.state.signing_key, r["id"], policy[0], env, policy_expired=policy[1]).attestation.usable:
                continue
        except service.NotFound:
            continue
        b = signed.passport.predicate
        out.append({"name": b.name, "version": b.version, "filename": dist["filename"], "sha256": dist["sha256"], "artifact_id": r["id"]})
    return out


@router.get("/simple/", response_class=HTMLResponse)
def index(request: Request, env: str | None = None, conn: sqlite3.Connection = Depends(get_conn), policy=Depends(get_policy),
          user: User = Depends(current_user)) -> str:
    names = sorted({normalize(w["name"]) for w in admitted_wheels(request, conn, policy, _env(user, env, request))})
    links = "\n".join(f'<a href="/simple/{n}/">{n}</a><br/>' for n in names)
    return f"<!DOCTYPE html><html><head><meta name=\"pypi:repository-version\" content=\"1.0\"><title>Lineage index</title></head><body>\n{links}\n</body></html>"


@router.get("/simple/{name}/")
def project(name: str, request: Request, env: str | None = None, conn: sqlite3.Connection = Depends(get_conn), policy=Depends(get_policy),
            user: User = Depends(current_user)):
    e = _env(user, env, request)
    wheels = [w for w in admitted_wheels(request, conn, policy, e) if normalize(w["name"]) == normalize(name)]
    if not wheels:
        headers = {}
        hub = request.app.state.hub
        if hub is not None and user.has("requester"):
            pending = request.app.state.__dict__.setdefault("pypi_jobs", {})
            job = pending.get(normalize(name))
            if job is None or request.app.state.jobs.get(job) is None or request.app.state.jobs.get(job).done:
                from lineage_server.routes.intake import launch

                job = launch(IntakeRequest(artifact_type="package", source=f"pypi:{name}", environment=e), request, policy, user).job_id
                pending[normalize(name)] = job
            headers["X-Lineage-Intake-Job"] = f"/events/{job}"
        return Response(f"{name}: no admitted version for {e}", status_code=404, headers=headers)
    base = str(request.base_url).rstrip("/")
    links = "\n".join(f'<a href="{base}/files/{w["sha256"]}/{html.escape(w["filename"])}#sha256={w["sha256"]}">{html.escape(w["filename"])}</a><br/>' for w in wheels)
    return HTMLResponse(f"<!DOCTYPE html><html><head><meta name=\"pypi:repository-version\" content=\"1.0\"><title>Links for {html.escape(name)}</title></head><body>\n{links}\n</body></html>")


@router.get("/files/{sha256}/{filename}")
def file(sha256: str, filename: str, request: Request, env: str | None = None, conn: sqlite3.Connection = Depends(get_conn),
         policy=Depends(get_policy), user: User = Depends(current_user)):
    """The wheel, only while its attestation for this token's environment still allows it (checked on every request)."""
    for w in admitted_wheels(request, conn, policy, _env(user, env, request)):
        if w["sha256"] == sha256 and w["filename"] == filename and request.app.state.store.has(sha256):
            return FileResponse(request.app.state.store.blob_path(sha256), filename=filename, media_type="application/octet-stream")
    raise HTTPException(404, f"{filename} is not admitted for this environment")
