"""R3.1: the reviewer runs against a hosted OpenAI-compatible API, no GPU worker (REFACTOR_SPEC 8.1). The hosted endpoint is a local
stub here (no key, no network); `response_format` support and the JSON-in-the-prompt fallback are both exercised."""
import json

import httpx
import pytest

from gpu_worker import reviewer_llm as llm
from lineage.inspect.llm_review import client as lc
from lineage.schemas.gpu import CodeSlice, ReviewCardRequest, ReviewCodeRequest


@pytest.fixture
def hosted(monkeypatch):
    for k in ("LINEAGE_VLLM_URL", "LINEAGE_GPU_URL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")
    monkeypatch.setenv("LINEAGE_LLM_BASE_URL", "http://hosted.test/v1")
    monkeypatch.setenv("LINEAGE_LLM_MODEL", "nvidia/test-model")


class Stub:
    """Plays the hosted endpoint: records requests, answers with the given content, optionally rejecting response_format."""

    def __init__(self, monkeypatch, replies, reject_schema=False):
        self.requests, self.replies, self.reject = [], list(replies), reject_schema
        monkeypatch.setattr(httpx, "post", self.post)

    def post(self, url, json=None, headers=None, timeout=None, **kw):
        self.requests.append((url, json, headers))
        if self.reject and "response_format" in json:
            return httpx.Response(400, json={"error": "response_format unsupported"}, request=httpx.Request("POST", url))
        content = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        return httpx.Response(200, request=httpx.Request("POST", url),
                              json={"choices": [{"message": {"content": content}}], "usage": {"prompt_tokens": 10, "completion_tokens": 5}})


REPLY = json.dumps({"analysis": "x", "claims": [{"text": "opens a socket to send data", "file": "a.py", "line": 2, "api": "socket.create_connection",
                                                 "severity": "high", "purpose_mismatch": True}], "verdict": "suspicious"})
REQ = ReviewCodeRequest(purpose="ROLE: PROSECUTOR\nStated purpose: resize images", capabilities=["network"],
                        slices=[CodeSlice(file="a.py", start=1, end=3, code="import socket\nsocket.create_connection(('127.0.0.1', 9))\n")])


def test_hosted_backend_uses_the_key_the_model_and_a_json_schema(hosted, monkeypatch):
    stub = Stub(monkeypatch, [REPLY])
    c = lc.GpuClient()
    assert c.hosted
    resp = c.review_code(REQ)
    url, body, headers = stub.requests[0]
    assert url == "http://hosted.test/v1/chat/completions" and headers["Authorization"] == "Bearer test-key"
    assert body["model"] == "nvidia/test-model" and body["response_format"]["type"] == "json_schema"
    assert [x.api for x in resp.claims] == ["socket.create_connection"] and resp.claims[0].purpose_mismatch


def test_falls_back_to_json_in_the_prompt_when_response_format_is_rejected(hosted, monkeypatch):
    stub = Stub(monkeypatch, ["Sure! Here is the JSON: " + REPLY], reject_schema=True)
    resp = lc.GpuClient().review_code(REQ)
    assert "response_format" not in stub.requests[-1][1] and "ONE JSON object" in stub.requests[-1][1]["messages"][0]["content"]
    assert resp.claims and resp.verdict == "suspicious"


def test_invalid_json_is_retried_once_then_unavailable(hosted, monkeypatch):
    Stub(monkeypatch, ["not json at all", "still not json", "nope", "nope"])
    with pytest.raises(lc.GpuUnavailable):
        lc.GpuClient().review_code(REQ)


def test_ungrounded_claims_are_still_dropped(hosted, monkeypatch):
    bad = json.dumps({"analysis": "x", "claims": [{"text": "x", "file": "a.py", "line": 1, "api": "subprocess.Popen", "severity": "critical"}], "verdict": "malicious"})
    Stub(monkeypatch, [bad])
    assert lc.GpuClient().review_code(REQ).claims == []  # line 1 has no subprocess.Popen: dropped before anything sees it


def test_a_named_gpu_worker_wins_over_the_hosted_api(hosted, monkeypatch):
    monkeypatch.setenv("LINEAGE_GPU_URL", "http://worker.test")
    assert not lc.GpuClient().hosted
    monkeypatch.delenv("LINEAGE_GPU_URL")
    monkeypatch.setenv("LINEAGE_VLLM_URL", "http://127.0.0.1:8001/v1")
    assert not llm.hosted()  # the Brev vLLM path keeps working when its URL is set


def test_no_key_means_not_hosted(monkeypatch):
    for k in ("LINEAGE_VLLM_URL", "LINEAGE_GPU_URL", "NVIDIA_API_KEY", "LINEAGE_LLM_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    assert not lc.GpuClient().hosted


def test_card_review_goes_through_the_hosted_api_too(hosted, monkeypatch):
    reply = json.dumps({"analysis": "x", "claims": [{"text": "card says MIT", "file": "card.md", "line": 1, "api": "license: mit", "severity": "medium"}], "verdict": "suspicious"})
    Stub(monkeypatch, [reply, json.dumps({"rebuttals": []}), json.dumps({"ratings": [], "extra_claims": [], "verdict": "suspicious"})])
    resp = lc.review_card_hosted(ReviewCardRequest(card_text="license: mit\n", measured={"files": 3}))
    assert resp.verdict in ("suspicious", "benign")


def test_pipeline_emits_not_run_when_the_hosted_api_is_unreachable(hosted, monkeypatch, tmp_path):
    import shutil
    from lineage.intake.pipeline import run_to_decision
    from lineage.schemas.policy import PolicyPack
    from tests.fakehub import old_release_hub
    from tests.server_helpers import NOW

    def boom(*a, **k):
        raise httpx.ConnectError("no route")

    monkeypatch.setattr(httpx, "post", boom)
    pkg = tmp_path / "p"
    shutil.copytree("tests/fixtures/toy_package", pkg)
    (pkg / "net.py").write_text("import urllib.request\n\ndef get(u):\n    return urllib.request.urlopen(u).read()\n")
    d, _ = run_to_decision("package", str(pkg), "prod", PolicyPack.from_yaml("examples/policy.org.yaml"), "j", now=NOW, hub=old_release_hub())
    assert "CHECK.NOT_RUN.LLM_REVIEW" in {f.id for f in d.findings}


def test_policy_check_uses_the_general_nemotron_model_and_drops_uncited_lines(hosted, monkeypatch):
    from lineage.inspect.llm_review import policy_hosted
    from lineage.schemas.policy import PolicyPack

    reply = json.dumps({"violations": [{"line": 2, "reason": "licence is not on the allow list"}, {"line": 99, "reason": "invented"}]})
    stub = Stub(monkeypatch, [reply])
    claims = policy_hosted.check("# card\nlicense: gpl-3.0\n", PolicyPack.from_yaml("examples/policy.org.yaml"))
    assert stub.requests[0][1]["model"] == "nvidia/nemotron-3.5-lightning-30b-a3b" and stub.requests[0][1]["chat_template_kwargs"] == {"enable_thinking": False} and "Allowed licences" in stub.requests[0][1]["messages"][0]["content"]
    assert [(c.line, c.api) for c in claims] == [(2, "license: gpl-3.0")]


def test_policy_check_without_a_key_is_not_run(monkeypatch, tmp_path, policy_path):
    for k in ("LINEAGE_VLLM_URL", "LINEAGE_GPU_URL", "NVIDIA_API_KEY", "LINEAGE_LLM_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    from lineage.intake.pipeline import run_to_decision
    from lineage.schemas.policy import PolicyPack
    from tests.fakehub import old_release_hub
    from tests.fixtures.builders import make_tiny_model
    from tests.server_helpers import NOW

    m = make_tiny_model(tmp_path / "m")
    (m / "README.md").write_text("# card\nlicense: mit\n")
    d, _ = run_to_decision("model", str(m), "prod", PolicyPack.from_yaml(policy_path), "j", now=NOW, hub=old_release_hub(), gpu_url="http://127.0.0.1:9")
    assert {"CHECK.NOT_RUN.LLM_REVIEW"} <= {f.id for f in d.findings}
