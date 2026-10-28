"""API tokens with roles (REFACTOR_SPEC 7.1, P7). Only a sha256 of each token is stored.

Roles: `requester` starts intakes and uploads, `approver` approves and revokes, `admin` does everything (incl. policy changes),
`auditor` reads. Every request needs `Authorization: Bearer <token>` (or HTTP basic auth for
pip, where the token is the password). `LINEAGE_REQUIRE_AUTH=0` switches authentication off for local development and the
test-suite; the server then treats everyone as an anonymous admin and the separation-of-duties check cannot apply.

    uv run python -m lineage_server.auth add --db lineage.db --name alice --roles requester
    uv run python -m lineage_server.auth demo --db lineage.db --out examples/demo_tokens.json
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from fastapi import Depends, HTTPException, Request

from lineage_server import db
from lineage_server.deps import get_conn

ROLES = ("requester", "approver", "admin", "auditor")
DEMO_USERS = [("alice", "alice@apollo.health", "requester", "dev"), ("bob", "bob@apollo.health", "approver", "prod"),
              ("carol", "carol@apollo.health", "admin", "prod"), ("auditor", "auditor@apollo.health", "auditor", "prod")]  # alice's package index serves dev


@dataclass
class User:
    name: str
    email: str
    roles: set[str]
    env: str = "prod"

    def has(self, *roles: str) -> bool:
        return "admin" in self.roles or bool(self.roles & set(roles))


ANONYMOUS = User("anonymous", "", {"admin"})


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_user(conn: sqlite3.Connection, name: str, roles: str, email: str = "", env: str = "prod") -> str:
    """Create (or replace) a user and return a new token, shown once."""
    bad = set(roles.split(",")) - set(ROLES)
    if bad:
        raise ValueError(f"unknown role(s) {sorted(bad)}; roles are {ROLES}")
    token = "lg_" + secrets.token_urlsafe(24)
    with db.tx(conn):
        conn.execute("DELETE FROM users WHERE name = ?", (name,))
        conn.execute("INSERT INTO users (token_hash, name, email, roles, env) VALUES (?, ?, ?, ?, ?)", (hash_token(token), name, email, roles, env))
    return token


def user_for_token(conn: sqlite3.Connection, token: str) -> User | None:
    row = conn.execute("SELECT name, email, roles, env FROM users WHERE token_hash = ?", (hash_token(token),)).fetchone()
    return User(row["name"], row["email"], set(row["roles"].split(",")), row["env"]) if row else None


TICKET_SECONDS = 60


class TicketStore:
    """Short-lived, job-scoped stream tickets, so the browser's EventSource (which cannot send a header) never puts the API token in a URL where
    logs would keep it. A ticket is random, lives 60 seconds, names one job, and is honoured only for `GET /events/<that job>`: it opens no other route.
    It can be used more than once inside its lifetime so the stream can reconnect. Tickets are in memory; a restart invalidates them."""

    def __init__(self, seconds: int = TICKET_SECONDS, clock=None):
        import time

        self._t: dict[str, tuple[str, User, float]] = {}
        self.seconds, self._clock = seconds, clock or time.monotonic

    def issue(self, user: User, job_id: str) -> str:
        now = self._clock()
        self._t = {k: v for k, v in self._t.items() if v[2] > now}  # forget expired tickets
        ticket = "st_" + secrets.token_urlsafe(24)
        self._t[ticket] = (job_id, user, now + self.seconds)
        return ticket

    def redeem(self, ticket: str, job_id: str) -> User | None:
        hit = self._t.get(ticket)
        if hit is None or hit[2] <= self._clock() or hit[0] != job_id:
            return None
        return hit[1]


def _token_of(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    if auth.lower().startswith("basic "):
        try:
            user, _, pw = base64.b64decode(auth[6:]).decode().partition(":")
        except ValueError:
            return None
        return pw or user
    return None  # never from the query string: URLs end up in logs


def current_user(request: Request, conn: sqlite3.Connection = Depends(get_conn)) -> User:
    if not getattr(request.app.state, "require_auth", True):
        return ANONYMOUS
    ticket = request.query_params.get("ticket")
    job = request.path_params.get("job_id")
    if ticket and job and request.url.path == f"/events/{job}":  # the SSE stream: a ticket for this job, nothing else
        t_user = request.app.state.tickets.redeem(ticket, job)
        if t_user is not None:
            return t_user
    token = _token_of(request)
    user = user_for_token(conn, token) if token else None
    if user is None:
        raise HTTPException(401, "a valid API token is required (Authorization: Bearer <token>)", headers={"WWW-Authenticate": 'Basic realm="lineage"' if request.url.path.startswith("/simple") else 'Bearer realm="lineage"'})  # Basic only for pip: on any other path a browser would pop up its own login dialog
    return user


def require(*roles: str):
    def dep(user: User = Depends(current_user)) -> User:
        if not user.has(*roles):
            raise HTTPException(403, f"requires role {' or '.join(roles)}; {user.name} has {', '.join(sorted(user.roles))}")
        return user

    return dep


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add")
    a.add_argument("--db", default="lineage.db")
    a.add_argument("--name", required=True)
    a.add_argument("--roles", required=True)
    a.add_argument("--email", default="")
    a.add_argument("--env", default="prod")
    d = sub.add_parser("demo")
    d.add_argument("--db", default="lineage.db")
    d.add_argument("--out", default="examples/demo_tokens.json")
    args = ap.parse_args()
    conn = db.connect(Path(args.db))
    db.init_schema(conn)
    if args.cmd == "add":
        print(create_user(conn, args.name, args.roles, args.email, args.env))
    else:
        tokens = {name: create_user(conn, name, roles, email, env) for name, email, roles, env in DEMO_USERS}
        Path(args.out).write_text(json.dumps(tokens, indent=2))
        print(f"wrote {len(tokens)} demo tokens to {args.out} (shown once)")
    conn.commit()


if __name__ == "__main__":
    main()
