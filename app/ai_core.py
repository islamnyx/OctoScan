"""Hardened model calls for every AI feature (AGENTS.md "Coding rules").

call_json(): one JSON answer validated by a pydantic schema. Strips
<think> blocks and ``` fences, retries once with the validation error,
then falls back to the next provider in the chain.
call_text(): same transport, redaction, fallback and logging for
free-text callers (app.ai.chat_complete delegates here).

Every call is recorded (purpose, provider, model, latency, tokens,
fallback) in memory and in data/ai_calls.jsonl so we can report real
numbers. Keys are never logged. Secrets are redacted from every message
before it leaves the machine, whatever the provider.
"""
from __future__ import annotations

import json
import logging
import re
import statistics
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from app.config import settings

log = logging.getLogger("octoscan.ai")

CALL_LOG_PATH = settings.data_dir / "ai_calls.jsonl"
# Providers that serve vLLM-style structured output (response_format
# json_schema). Others get the schema in the prompt only.
STRUCTURED_OUTPUT_PROVIDERS = {"brev", "vllm"}
MAX_TIMEOUT_S = 60

T = TypeVar("T", bound=BaseModel)


class AIError(RuntimeError):
    """Every configured provider failed (or none is configured)."""


# ---------------------------------------------------------------- redaction
# Single choke point lives in app/redact.py; these aliases keep existing
# importers (ai_fix, ai_review, tests) working unchanged.
from app.redact import redact, redact_messages as _redact_messages  # noqa: E402


# ------------------------------------------------------------------ parsing

_THINK_RE = re.compile(r"<think>[\s\S]*?</think>", re.I)
_FENCE_RE = re.compile(r"```[a-zA-Z]*\s*([\s\S]*?)```")


def strip_reasoning(text: str) -> str:
    """Drop <think>…</think> blocks and ``` fences around the answer."""
    t = _THINK_RE.sub("", text or "")
    # Templates that omit the opening tag leave a bare "</think>".
    if "</think>" in t.lower():
        t = t[t.lower().rindex("</think>") + len("</think>"):]
    # Truncated reasoning: "<think>" never closed -> no answer after it.
    if "<think>" in t.lower():
        t = t[: t.lower().index("<think>")]
    fence = _FENCE_RE.search(t)
    if fence:
        t = fence.group(1)
    return t.strip()


def parse_json_loose(text: str, want: type | None = None) -> Any:
    """First JSON value in a model reply (optionally only dict or list).

    Raises ValueError when nothing parses.
    """
    t = strip_reasoning(text)
    try:
        value = json.loads(t)
        if want is None or isinstance(value, want):
            return value
    except ValueError:
        pass
    decoder = json.JSONDecoder()
    openers = "{[" if want is None else ("{" if want is dict else "[")
    tried = 0
    for i, ch in enumerate(t):
        if ch not in openers:
            continue
        tried += 1
        if tried > 200:
            break
        try:
            value, _end = decoder.raw_decode(t, i)
        except ValueError:
            continue
        if want is None or isinstance(value, want):
            return value
    raise ValueError("no JSON value found in model reply")


# ---------------------------------------------------------------- providers

def _complete(p: dict[str, str] | None) -> bool:
    return bool(p and (p.get("base_url") or "").strip() and (p.get("model") or "").strip())


def provider_chain(cfg: dict[str, str] | None = None, fallback: bool = True) -> list[dict[str, str]]:
    """Primary provider first, then (if fallback) every other saved profile,
    then the .env AI_* defaults. Incomplete and duplicate entries skipped."""
    from app import ai as ai_layer

    chain: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(p: dict[str, str] | None) -> None:
        if not _complete(p):
            return
        key = ((p.get("base_url") or "").strip().rstrip("/"), (p.get("model") or "").strip())
        if key in seen:
            return
        seen.add(key)
        chain.append(dict(p))

    add(cfg if cfg is not None else ai_layer.load_config())
    if fallback:
        for p in ai_layer._load_store().get("providers", {}).values():
            add(p)
        add({
            "name": "env",
            "provider": settings.ai_provider or "env",
            "base_url": settings.ai_base_url,
            "api_key": settings.ai_api_key,
            "model": settings.ai_model,
        })
    return chain


# Cooldown: a provider that is down (unreachable / 5xx / 429) is tried LAST
# for 60 s instead of first on every call. Without it a hung Brev instance
# costs a full timeout on each of the ~40 calls of an agent run.
COOLDOWN_S = 60
_DOWN_UNTIL: dict[tuple[str, str], float] = {}
_OUTAGE_RE = re.compile(r"unreachable|error (5\d\d|429)")


def _pkey(p: dict[str, str]) -> tuple[str, str]:
    return ((p.get("base_url") or "").strip().rstrip("/"), (p.get("model") or "").strip())


def _note_result(p: dict[str, str], exc: Exception | None) -> None:
    if exc is None:
        _DOWN_UNTIL.pop(_pkey(p), None)
    elif _OUTAGE_RE.search(str(exc)):
        _DOWN_UNTIL[_pkey(p)] = time.monotonic() + COOLDOWN_S


def _healthy_first(chain: list[dict[str, str]]) -> list[dict[str, str]]:
    now = time.monotonic()
    cooling = [p for p in chain if _DOWN_UNTIL.get(_pkey(p), 0) > now]
    return [p for p in chain if p not in cooling] + cooling


def _endpoint(base_url: str) -> str:
    base = (base_url or "").strip().rstrip("/")
    return base if base.endswith("/chat/completions") else base + "/chat/completions"


def _http_post(url: str, payload: dict, headers: dict, timeout: float) -> httpx.Response:
    # Separate function so tests can swap the transport.
    return httpx.post(url, json=payload, headers=headers, timeout=timeout)


def _post_once(
    p: dict[str, str],
    messages: list[dict[str, str]],
    max_tokens: int,
    temperature: float,
    response_format: dict | None,
) -> tuple[str, dict, int]:
    """One HTTP call. Returns (content, usage, latency_ms); raises AIError."""
    headers = {"Content-Type": "application/json"}
    if p.get("api_key"):
        headers["Authorization"] = f"Bearer {p['api_key']}"
    payload: dict[str, Any] = {
        "model": p["model"].strip(),
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if response_format:
        payload["response_format"] = response_format
    timeout = max(5, min(settings.ai_timeout_s, MAX_TIMEOUT_S))
    t0 = time.perf_counter()
    try:
        r = _http_post(_endpoint(p["base_url"]), payload, headers, timeout)
    except Exception as exc:
        raise AIError(f"AI provider unreachable: {type(exc).__name__}: {str(exc)[:200]}")
    latency_ms = int((time.perf_counter() - t0) * 1000)
    if r.status_code >= 400:
        raise AIError(f"AI provider error {r.status_code}: {r.text[:300]}")
    try:
        data = r.json()
        content = data["choices"][0]["message"].get("content") or ""
    except Exception as exc:
        raise AIError(f"AI provider bad response: {exc}")
    return content, (data.get("usage") or {}), latency_ms


def _post_with_429_retry(p, messages, max_tokens, temperature, response_format, can_wait: bool):
    """429 on the last provider in the chain: wait once (<= 20 s) and retry.
    Earlier providers just fall through to the next one."""
    try:
        return _post_once(p, messages, max_tokens, temperature, response_format)
    except AIError as exc:
        if not can_wait or " 429" not in str(exc):
            raise
        m = re.search(r"try again in ([\d.]+)s", str(exc))
        time.sleep(min(float(m.group(1)) + 1.0 if m else 10.0, 20.0))
        return _post_once(p, messages, max_tokens, temperature, response_format)


# ------------------------------------------------------------ call records

_CALLS: deque[dict] = deque(maxlen=2000)
_LOCK = threading.Lock()


def _record(purpose: str, p: dict[str, str], ok: bool, latency_ms: int = 0,
            usage: dict | None = None, fallback_used: bool = False,
            error: str = "", redactions: int = 0) -> dict:
    usage = usage or {}
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "purpose": purpose,
        "provider": p.get("name") or p.get("provider") or "",
        "model": p.get("model", ""),
        "ok": ok,
        "latency_ms": latency_ms,
        "tokens_in": int(usage.get("prompt_tokens") or 0),
        "tokens_out": int(usage.get("completion_tokens") or 0),
        "fallback_used": fallback_used,
        "redactions": redactions,
    }
    if error:
        entry["error"] = error[:200]
    with _LOCK:
        _CALLS.append(entry)
        try:
            CALL_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with CALL_LOG_PATH.open("a") as fh:
                fh.write(json.dumps(entry) + "\n")
        except Exception:
            pass
    log.info("ai call %s", json.dumps(entry))
    return entry


def stats(since_ts: str = "") -> dict[str, Any]:
    """Aggregate recorded calls (optionally only those at/after an ISO ts)."""
    with _LOCK:
        calls = [c for c in _CALLS if not since_ts or c["ts"] >= since_ts]
    ok = [c for c in calls if c["ok"]]
    return {
        "calls": len(calls),
        "ok": len(ok),
        "failed": len(calls) - len(ok),
        "median_latency_ms": int(statistics.median([c["latency_ms"] for c in ok])) if ok else 0,
        "tokens_in": sum(c["tokens_in"] for c in calls),
        "tokens_out": sum(c["tokens_out"] for c in calls),
        "fallback_used": any(c["fallback_used"] for c in ok),
        "models": sorted({c["model"] for c in ok}),
    }


def _meta(p: dict[str, str], latency_ms: int, usage: dict, fallback_used: bool, redactions: int, attempts: int) -> dict:
    return {
        "provider": p.get("name") or p.get("provider") or "",
        "model": p.get("model", ""),
        "latency_ms": latency_ms,
        "tokens_in": int(usage.get("prompt_tokens") or 0),
        "tokens_out": int(usage.get("completion_tokens") or 0),
        "fallback_used": fallback_used,
        "attempts": attempts,
        "redactions": redactions,
    }


# ------------------------------------------------------------------- calls

def call_text(
    messages: list[dict[str, str]],
    *,
    cfg: dict[str, str] | None = None,
    fallback: bool = True,
    max_tokens: int | None = None,
    temperature: float = 0.2,
    purpose: str = "text",
) -> tuple[str, dict]:
    """Free-text completion with redaction, fallback chain and logging.

    Returns (text with <think> blocks removed, meta). Raises AIError with the
    FIRST provider's error when all fail (callers match on "429"/"413").
    """
    chain = provider_chain(cfg, fallback)
    if not chain:
        raise AIError("AI base_url/model not configured")
    msgs, n_red = _redact_messages(messages)
    primary = chain[0]
    ordered = _healthy_first(chain)
    first_err: AIError | None = None
    for idx, p in enumerate(ordered):
        fb = p is not primary
        try:
            text, usage, ms = _post_with_429_retry(
                p, msgs, max_tokens or settings.ai_max_tokens, temperature, None,
                can_wait=idx == len(ordered) - 1,
            )
        except AIError as exc:
            _note_result(p, exc)
            _record(purpose, p, False, fallback_used=fb, error=str(exc), redactions=n_red)
            first_err = first_err or exc
            continue
        _note_result(p, None)
        _record(purpose, p, True, ms, usage, fb, redactions=n_red)
        return _THINK_RE.sub("", text).strip(), _meta(p, ms, usage, fb, n_red, 1)
    raise first_err or AIError("all AI providers failed")


def _wants_list(schema: type[BaseModel]) -> bool:
    return schema.model_json_schema().get("type") == "array"


def _structured_format(p: dict[str, str], schema: type[BaseModel]) -> dict | None:
    if (p.get("provider") or "").lower() not in STRUCTURED_OUTPUT_PROVIDERS:
        return None
    return {
        "type": "json_schema",
        "json_schema": {"name": schema.__name__, "schema": schema.model_json_schema()},
    }


def call_json(
    messages: list[dict[str, str]],
    schema: type[T],
    *,
    max_tokens: int = 800,
    purpose: str = "json",
    cfg: dict[str, str] | None = None,
    fallback: bool = True,
    temperature: float = 0.1,
) -> tuple[T, dict]:
    """One JSON answer validated by `schema`. Returns (instance, meta).

    Per provider: call -> parse -> validate; on bad JSON retry once with the
    error; then the next provider. Raises AIError when every provider failed
    so the caller can return its non-AI result.
    """
    chain = provider_chain(cfg, fallback)
    if not chain:
        raise AIError("AI base_url/model not configured")
    schema_txt = json.dumps(schema.model_json_schema(), separators=(",", ":"))[:4000]
    instr = (
        "Answer with ONE JSON value only: no prose, no markdown fences. "
        f"It must validate against this JSON schema: {schema_txt}"
    )
    base = [dict(m) for m in messages]
    if base and base[0].get("role") == "system":
        base[0]["content"] = f"{base[0]['content']}\n\n{instr}"
    else:
        base.insert(0, {"role": "system", "content": instr})
    base, n_red = _redact_messages(base)
    want = list if _wants_list(schema) else dict

    primary = chain[0]
    ordered = _healthy_first(chain)
    first_err: AIError | None = None
    for idx, p in enumerate(ordered):
        fb = p is not primary
        rf = _structured_format(p, schema)
        msgs = base
        for attempt in (1, 2):
            try:
                text, usage, ms = _post_with_429_retry(
                    p, msgs, max_tokens, temperature, rf, can_wait=idx == len(ordered) - 1,
                )
            except AIError as exc:
                if rf and " 400" in str(exc) and attempt == 1:
                    rf = None  # server refused structured output: retry plain
                    continue
                _note_result(p, exc)
                _record(purpose, p, False, fallback_used=fb, error=str(exc), redactions=n_red)
                first_err = first_err or exc
                break
            try:
                obj = schema.model_validate(parse_json_loose(text, want=want))
            except (ValueError, ValidationError) as exc:
                err = AIError(f"invalid JSON from {p.get('model')}: {str(exc)[:300]}")
                _record(purpose, p, False, ms, usage, fb, error=str(err), redactions=n_red)
                first_err = first_err or err
                msgs = base + [
                    {"role": "assistant", "content": (text or "")[:2000]},
                    {"role": "user", "content": (
                        f"That reply was not valid for the schema ({str(exc)[:300]}). "
                        "Reply again with the corrected JSON only."
                    )},
                ]
                continue
            _note_result(p, None)
            _record(purpose, p, True, ms, usage, fb, redactions=n_red)
            return obj, _meta(p, ms, usage, fb, n_red, attempt)
    raise first_err or AIError("all AI providers failed")
