"""GET /whoami: who the presented token belongs to (the dashboard shows it and enables or disables actions by role)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from lineage_server.auth import User, current_user

router = APIRouter()


class WhoAmI(BaseModel):
    name: str
    email: str
    roles: list[str]
    env: str
    auth_required: bool


@router.get("/whoami", response_model=WhoAmI)
def whoami(request_user: User = Depends(current_user)) -> WhoAmI:
    return WhoAmI(name=request_user.name, email=request_user.email, roles=sorted(request_user.roles), env=request_user.env, auth_required=request_user.name != "anonymous")
