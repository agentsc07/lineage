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
    try:
        return httpx.get(f"{VLLM_URL}/models", timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


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
