"""Client for the reviewer LLM served by vLLM (OpenAI-compatible, scripts/serve_reviewer.sh), with JSON-schema constrained output.

Every call is timed and its token usage recorded so latency and tokens/sec can be reported (bench/reviewer.json).
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field

import httpx

VLLM_URL = os.environ.get("LINEAGE_VLLM_URL", "http://127.0.0.1:8001/v1")
SERVED_NAME = "reviewer"
# Hosted backend (no Brev): any OpenAI-compatible endpoint, by default NVIDIA's. Used when LINEAGE_VLLM_URL is not set and a key is.
DEFAULT_HOSTED_URL = "https://integrate.api.nvidia.com/v1"
DEFAULT_HOSTED_MODEL = "nvidia/nemotron-3.5-lightning-30b-a3b"  # nvidia-nemotron-nano-9b-v2 is not listed by the hosted API; override with LINEAGE_LLM_MODEL


def hosted_key() -> str | None:
    return os.environ.get("LINEAGE_LLM_API_KEY") or os.environ.get("NVIDIA_API_KEY") or None


def hosted() -> bool:
    """The Brev vLLM path wins whenever LINEAGE_VLLM_URL is set; otherwise a key selects the hosted API."""
    return "LINEAGE_VLLM_URL" not in os.environ and hosted_key() is not None


def hosted_url() -> str:
    return os.environ.get("LINEAGE_LLM_BASE_URL", DEFAULT_HOSTED_URL).rstrip("/")


def hosted_model() -> str:
    return os.environ.get("LINEAGE_LLM_MODEL", DEFAULT_HOSTED_MODEL)
TIMEOUT = 180.0


class ReviewerUnavailable(RuntimeError):
    """vLLM is not reachable or returned something unusable: the endpoint answers 503 and callers fall back."""


@dataclass
class CallStat:
    stage: str
    latency_s: float
    prompt_tokens: int
    completion_tokens: int

    @property
    def tok_s(self) -> float:
        return self.completion_tokens / self.latency_s if self.latency_s > 0 else 0.0


@dataclass
class Trace:
    """Calls made while serving one request."""
    calls: list[CallStat] = field(default_factory=list)

    @property
    def latency_s(self) -> float:
        return sum(c.latency_s for c in self.calls)

    @property
    def completion_tokens(self) -> int:
        return sum(c.completion_tokens for c in self.calls)

    @property
    def prompt_tokens(self) -> int:
        return sum(c.prompt_tokens for c in self.calls)


_lock = threading.Lock()
_totals = {"calls": 0, "latency_s": 0.0, "prompt_tokens": 0, "completion_tokens": 0}


def totals() -> dict:
    with _lock:
        return dict(_totals)


def is_up() -> bool:
    if hosted():
        return True
    try:
        return httpx.get(f"{VLLM_URL}/models", timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


def _hosted_json(system: str, user: str, schema: dict, max_tokens: int) -> tuple[dict, dict]:
    """JSON from a hosted OpenAI-compatible endpoint. Tries `response_format` with the JSON schema; if the endpoint rejects it, asks for
    JSON in the prompt instead. The reply is parsed and the caller validates its shape; invalid JSON is retried once."""
    headers = {"Authorization": f"Bearer {hosted_key()}"}
    # nemotron-3.5 ignores `/no_think`; without enable_thinking=false it spends max_tokens on reasoning and returns content=None
    base = {"model": hosted_model(), "temperature": 0, "max_tokens": max_tokens, "chat_template_kwargs": {"enable_thinking": False},
            "messages": [{"role": "system", "content": "/no_think\n" + system}, {"role": "user", "content": user}]}
    modes = [{"response_format": {"type": "json_schema", "json_schema": {"name": "review", "schema": schema, "strict": True}}}, {}]
    last: Exception | None = None
    for mode in modes:
        body = dict(base, **mode)
        if not mode:  # plain JSON-in-the-prompt fallback
            body["messages"] = [{"role": "system", "content": base["messages"][0]["content"] + "\nReply with ONE JSON object only, no prose, matching this JSON schema: " + json.dumps(schema)},
                                base["messages"][1]]
        for attempt in range(2):
            try:
                r = httpx.post(f"{hosted_url()}/chat/completions", json=body, headers=headers, timeout=TIMEOUT)
                if r.status_code in (400, 404, 422) and mode:  # response_format not supported here: fall back
                    last = ReviewerUnavailable(f"HTTP {r.status_code}: {r.text[:120]}")
                    break
                r.raise_for_status()
                data = r.json()
                text = data["choices"][0]["message"]["content"] or ""
                text = text[text.find("{"): text.rfind("}") + 1] if "{" in text else text
                return json.loads(text), data
            except ValueError as e:
                last = e  # invalid JSON: retry once
            except (httpx.HTTPError, KeyError) as e:
                raise ReviewerUnavailable(f"hosted reviewer call failed: {type(e).__name__}: {e}"[:300]) from e
    raise ReviewerUnavailable(f"hosted reviewer returned no valid JSON: {last}"[:300])


def chat_json(system: str, user: str, schema: dict, *, stage: str, trace: Trace, max_tokens: int = 1200) -> dict:
    """One constrained generation. `/no_think` switches Nemotron's reasoning off so the output is the JSON object only."""
    body = {
        "model": SERVED_NAME, "temperature": 0, "max_tokens": max_tokens,
        "messages": [{"role": "system", "content": "/no_think\n" + system}, {"role": "user", "content": user}],
        # disable_any_whitespace: otherwise the constrained decoder can emit runs of blanks until max_tokens and truncate the JSON
        "structured_outputs": {"json": schema, "disable_any_whitespace": True},
    }
    t0 = time.perf_counter()
    data = out = None
    if hosted():
        out, data = _hosted_json(system, user, schema, max_tokens)
        for key in ("claims", "ratings", "rebuttals", "extra_claims"):
            if key in schema.get("properties", {}):
                out.setdefault(key, [])  # a hosted model may omit an empty list
        out.setdefault("verdict", "benign") if "verdict" in schema.get("properties", {}) else None
        dt = time.perf_counter() - t0
        u = data.get("usage") or {}
        stat = CallStat(stage, dt, int(u.get("prompt_tokens", 0)), int(u.get("completion_tokens", 0)))
        trace.calls.append(stat)
        with _lock:
            _totals["calls"] += 1
            _totals["latency_s"] += dt
            _totals["prompt_tokens"] += stat.prompt_tokens
            _totals["completion_tokens"] += stat.completion_tokens
        return out
    for attempt in range(3):  # a constrained decoder can stall on whitespace; the retry samples slightly differently
        if attempt:
            body["temperature"], body["seed"] = 0.3, attempt
        try:
            r = httpx.post(f"{VLLM_URL}/chat/completions", json=body, timeout=TIMEOUT)
            r.raise_for_status()
            data = r.json()
            out = json.loads(data["choices"][0]["message"]["content"])
            break
        except ValueError as e:
            err = e  # truncated / invalid JSON: retry
        except (httpx.HTTPError, KeyError) as e:
            raise ReviewerUnavailable(f"reviewer LLM call failed ({stage}): {type(e).__name__}: {e}"[:300]) from e
    else:
        raise ReviewerUnavailable(f"reviewer LLM returned invalid JSON 3 times ({stage}): {err}"[:300])
    dt = time.perf_counter() - t0
    u = data.get("usage") or {}
    stat = CallStat(stage, dt, int(u.get("prompt_tokens", 0)), int(u.get("completion_tokens", 0)))
    trace.calls.append(stat)
    with _lock:
        _totals["calls"] += 1
        _totals["latency_s"] += dt
        _totals["prompt_tokens"] += stat.prompt_tokens
        _totals["completion_tokens"] += stat.completion_tokens
    return out
