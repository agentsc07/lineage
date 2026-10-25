"""FastAPI app. Skeleton: all routes return mock data that matches the schemas (Track B replaces the bodies)."""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from lineage_server.routes import artifacts, decisions, events, graph, intake, passports, policy

app = FastAPI(title="Lineage", version="0.1.0", description="Admission control for AI artifacts")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_methods=["*"], allow_headers=["*"])

for module in (intake, events, artifacts, passports, graph, decisions, policy):
    app.include_router(module.router)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}
