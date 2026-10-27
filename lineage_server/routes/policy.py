"""GET/PUT /policy. PUT requires 2-of-3 role signatures, unexpired metadata and no rollback (TUF-style)."""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException
from pydantic import ValidationError

from lineage.schemas.artifact import PolicyState, PolicyUpdate
from lineage_server import log, policy_store, tuf
from lineage_server.auth import require
from lineage_server.deps import get_conn

router = APIRouter()


@router.get("/policy", response_model=PolicyState)
def get_policy(conn: sqlite3.Connection = Depends(get_conn)) -> PolicyState:
    state = policy_store.get_state(conn)
    if state is None:
        raise HTTPException(503, "no policy installed")
    return state


@router.put("/policy", response_model=PolicyState, dependencies=[Depends(require("admin"))])
def put_policy(update: PolicyUpdate, conn: sqlite3.Connection = Depends(get_conn)) -> PolicyState:
    try:
        before = policy_store.get_state(conn)
        state = policy_store.apply_update(conn, update)
        # P8: everything that changes a decision is in the Merkle log; trusted-publisher changes get their own entry
        log.append(conn, "policy", state.version)
        old = (before.policy.get("trusted_publishers"), before.policy.get("revoked_keys")) if before else None
        if old != (state.policy.get("trusted_publishers"), state.policy.get("revoked_keys")):
            log.append(conn, "trusted_publishers", state.version)
        conn.commit()
        return state
    except policy_store.RoleKeysMissing as e:
        raise HTTPException(409, str(e))
    except ValidationError as e:
        raise HTTPException(422, f"invalid policy document: {e.error_count()} error(s): {e.errors()[0]['loc']}")
    except tuf.ThresholdNotMet as e:
        raise HTTPException(403, str(e))
    except tuf.Rollback as e:
        raise HTTPException(409, str(e))
    except tuf.UpdateRejected as e:
        raise HTTPException(400, str(e))
