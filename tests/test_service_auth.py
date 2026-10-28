"""P1.5: the GPU worker and the MCP gateway can require a shared bearer secret; the callers send it. (Worker routes are exercised on a stand-in app
because the real worker imports torch; the middleware and the client header are the same code.)"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from lineage import serviceauth


def stand_in():
    app = FastAPI()
    serviceauth.add_token_auth(app, "LINEAGE_GPU_TOKEN", frozenset({"/health"}))

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.post("/review/code")
    def review():
        return {"claims": []}

    return TestClient(app)


def test_with_a_secret_set_the_service_refuses_callers_without_it(monkeypatch):
    monkeypatch.setenv("LINEAGE_GPU_TOKEN", "s3cret-value")
    c = stand_in()
    assert c.post("/review/code").status_code == 401
    assert c.post("/review/code", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.post("/review/code", headers={"Authorization": "Basic czNjcmV0LXZhbHVl"}).status_code == 401
    assert c.post("/review/code", headers={"Authorization": "Bearer s3cret-value"}).status_code == 200
    assert c.get("/health").status_code == 200  # liveness stays open


def test_with_no_secret_set_the_service_is_open_for_local_development(monkeypatch):
    monkeypatch.delenv("LINEAGE_GPU_TOKEN", raising=False)
    assert stand_in().post("/review/code").status_code == 200


def test_the_client_helper_sends_the_secret_only_when_one_is_configured(monkeypatch):
    monkeypatch.delenv("LINEAGE_GPU_TOKEN", raising=False)
    assert serviceauth.bearer("LINEAGE_GPU_TOKEN") == {}
    monkeypatch.setenv("LINEAGE_GPU_TOKEN", "abc")
    assert serviceauth.bearer("LINEAGE_GPU_TOKEN") == {"Authorization": "Bearer abc"}


def test_the_intake_gpu_client_sends_the_secret(monkeypatch):
    import httpx

    from lineage.intake import gpu
    from lineage.schemas.gpu import SpectralRequest, SpectralResponse

    seen = {}

    def fake_post(url, json, timeout, headers):
        seen["headers"] = headers
        return httpx.Response(200, json={"score": 0.1, "per_layer": {}}, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.setenv("LINEAGE_GPU_TOKEN", "abc")
    gpu.post("/weights/spectral", SpectralRequest(model_path="m", parent="p"), SpectralResponse, "http://worker")
    assert seen["headers"] == {"Authorization": "Bearer abc"}


def test_the_mcp_gateway_requires_its_secret_when_configured(monkeypatch):
    from mcp_gateway.gateway import Gateway, create_app

    class Up:
        def request(self, *_a, **_k):
            return {"result": {"tools": []}}

    monkeypatch.setenv("LINEAGE_GATEWAY_TOKEN", "gw-secret")
    gw = Gateway(Up(), pins={}) if "pins" in Gateway.__init__.__code__.co_varnames else Gateway(Up())
    c = TestClient(create_app(gw))
    assert c.get("/gateway/status").status_code == 401
    assert c.post("/", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).status_code == 401
    assert c.get("/gateway/status", headers={"Authorization": "Bearer gw-secret"}).status_code == 200
    monkeypatch.delenv("LINEAGE_GATEWAY_TOKEN")
    assert TestClient(create_app(gw)).get("/gateway/status").status_code == 200
