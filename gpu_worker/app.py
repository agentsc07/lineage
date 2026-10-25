"""GPU worker: one FastAPI app on :8800 implementing BUILD_PLAN §2.6 (Track D).

    uv run uvicorn gpu_worker.app:app --host 0.0.0.0 --port 8800

Endpoints that cannot run here answer 503 so `lineage.intake.gpu` callers fall back to an `info` finding.
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from gpu_worker import behaviour_api, modelio, notary_api, reviewer_api, weights_api
from gpu_worker.weights_api import CALIBRATION, bank

app = FastAPI(title="Lineage GPU worker", version="0.1.0")
for module in (weights_api, behaviour_api, notary_api, reviewer_api):
    app.include_router(module.router)


@app.exception_handler(FileNotFoundError)
async def _not_found(_: Request, exc: FileNotFoundError) -> JSONResponse:
    return JSONResponse({"detail": str(exc)}, status_code=404)


@app.exception_handler(RuntimeError)
async def _runtime(_: Request, exc: RuntimeError) -> JSONResponse:
    # e.g. CUDA out of memory or a missing calibration: the caller should fall back, not crash
    return JSONResponse({"detail": f"{type(exc).__name__}: {exc}"[:300]}, status_code=503)


@app.get("/health")
def health() -> dict:
    gpu = None
    if modelio.have_gpu():
        import torch
        gpu = torch.cuda.get_device_name(0)
    return {
        "status": "ok",
        "gpu": gpu,
        "endpoints": {
            "/weights/parent": True,
            "/weights/spectral": CALIBRATION.exists(),
            "/behaviour/diff": gpu is not None,
            "/behaviour/claims": gpu is not None,
            "/behaviour/triggers": gpu is not None,
            "/notary/certify": gpu is not None,
            "/notary/check": gpu is not None,
            "/review/code": False,  # reviewer not implemented yet (503)
            "/review/card": False,
        },
        "parent_bank": sorted(bank()),
        "reviewer_llm": reviewer_api.reviewer_model(),
    }
