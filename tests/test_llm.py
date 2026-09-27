"""Tests for the LLM client — provider selection and the OpenAI-compatible
backend (Muse Spark via OpenCode Zen). All HTTP is mocked; no network.
"""

from __future__ import annotations

import json

import httpx
import pytest

from scan_toolkit.agents.llm_client import (
    LLMClient,
    LLMError,
    OpenAICompatibleBackend,
)


def _chat_response(content: str) -> dict:
    return {"choices": [{"message": {"role": "assistant", "content": content}}]}


def _transport(responses: list, record: dict | None = None):
    """MockTransport serving queued responses; optionally records requests."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if record is not None:
            record["url"] = str(request.url)
            record["auth"] = request.headers.get("authorization")
            record["body"] = json.loads(request.content.decode())
        resp = responses[min(calls["n"] - 1, len(responses) - 1)]
        if isinstance(resp, httpx.Response):
            return resp
        return httpx.Response(200, json=resp)

    return httpx.MockTransport(handler)


# ---------------------------------------------------------------------------
# OpenAI-compatible backend
# ---------------------------------------------------------------------------

class TestOpenAIBackend:
    def test_request_shape(self):
        record: dict = {}
        backend = OpenAICompatibleBackend(
            api_key="zen-key", model="muse-spark-1.3-contributor-free",
            max_tokens=100, base_url="https://opencode.ai/zen/v1",
            transport=_transport([_chat_response("hi")], record),
        )
        assert backend.complete(system="sys", messages=[{"role": "user",
                                                         "content": "yo"}]) == "hi"
        assert record["url"] == "https://opencode.ai/zen/v1/chat/completions"
        assert record["auth"] == "Bearer zen-key"
        body = record["body"]
        assert body["model"] == "muse-spark-1.3-contributor-free"
        assert body["temperature"] == 0
        assert body["messages"][0] == {"role": "system", "content": "sys"}
        assert body["messages"][1]["role"] == "user"

    def test_http_error(self):
        backend = OpenAICompatibleBackend(
            api_key="k", model="m", max_tokens=10, base_url="https://x/v1",
            transport=_transport([httpx.Response(401, json={"error": "no"})]),
        )
        with pytest.raises(LLMError, match="request failed"):
            backend.complete(system="s", messages=[])

    def test_missing_choices(self):
        backend = OpenAICompatibleBackend(
            api_key="k", model="m", max_tokens=10, base_url="https://x/v1",
            transport=_transport([{"oops": True}]),
        )
        with pytest.raises(LLMError, match="no choices"):
            backend.complete(system="s", messages=[])

    def test_empty_content(self):
        backend = OpenAICompatibleBackend(
            api_key="k", model="m", max_tokens=10, base_url="https://x/v1",
            transport=_transport([_chat_response("   ")]),
        )
        with pytest.raises(LLMError, match="empty response"):
            backend.complete(system="s", messages=[])


# ---------------------------------------------------------------------------
# Provider selection
# ---------------------------------------------------------------------------

class TestProviderSelection:
    def test_default_is_anthropic(self, monkeypatch):
        monkeypatch.delenv("OPENCODE_API_KEY", raising=False)
        client = LLMClient(api_key="sk-ant-test")
        assert client.provider == "anthropic"

    def test_anthropic_missing_key(self, monkeypatch):
        from scan_toolkit.config import get_settings
        monkeypatch.setattr(get_settings(), "anthropic_api_key", "")
        with pytest.raises(RuntimeError, match="SCAN_TOOLKIT_ANTHROPIC_API_KEY"):
            LLMClient(api_key="")

    def test_opencode_explicit_key(self):
        client = LLMClient(provider="openai_compatible", api_key="zen-key")
        assert client.provider == "openai_compatible"
        assert isinstance(client._backend, OpenAICompatibleBackend)
        assert client._backend._model == "muse-spark-1.3-contributor-free"
        assert client._backend._base_url == "https://opencode.ai/zen/v1"

    def test_opencode_env_fallback(self, monkeypatch):
        from scan_toolkit.config import get_settings
        monkeypatch.setenv("OPENCODE_API_KEY", "zen-from-env")
        get_settings.cache_clear()
        try:
            client = LLMClient(provider="opencode")
            assert client._backend._api_key == "zen-from-env"
        finally:
            get_settings.cache_clear()

    def test_opencode_missing_key(self, monkeypatch):
        from scan_toolkit.config import get_settings
        monkeypatch.setenv("SCAN_TOOLKIT_LLM_API_KEY", "")
        monkeypatch.setenv("OPENCODE_API_KEY", "")
        monkeypatch.setenv("SCAN_TOOLKIT_ZEN_API_KEY", "")
        get_settings.cache_clear()
        try:
            with pytest.raises(RuntimeError, match="SCAN_TOOLKIT_LLM_API_KEY"):
                LLMClient(provider="openai_compatible", api_key="")
        finally:
            get_settings.cache_clear()

    def test_unknown_provider(self):
        with pytest.raises(ValueError, match="unknown LLM provider"):
            LLMClient(provider="skynet", api_key="x")


# ---------------------------------------------------------------------------
# Retry / validation through the new backend
# ---------------------------------------------------------------------------

class TestCallRetry:
    def _client(self, responses):
        return LLMClient(
            provider="openai_compatible", api_key="zen-key",
            transport=_transport(responses),
        )

    def test_valid_first_try(self):
        client = self._client([_chat_response('{"findings": []}')])
        assert client.call(system="s", user_message="u") == {"findings": []}

    def test_retry_then_valid(self):
        client = self._client([
            _chat_response('{"findings": "oops"}'),
            _chat_response('{"findings": []}'),
        ])

        def validate(data):
            if not isinstance(data.get("findings"), list):
                raise ValueError("findings must be a list")

        assert client.call(system="s", user_message="u",
                           validate_fn=validate) == {"findings": []}

    def test_fail_after_retry(self):
        client = self._client([_chat_response('{"nope": 1}')])

        def validate(data):
            if "findings" not in data:
                raise ValueError("missing findings")

        with pytest.raises(LLMError, match="after retry"):
            client.call(system="s", user_message="u", validate_fn=validate)

    def test_invalid_json(self):
        client = self._client([_chat_response("not json at all")])
        with pytest.raises(LLMError, match="invalid JSON"):
            client.call(system="s", user_message="u")

    def test_fenced_json(self):
        client = self._client(
            [_chat_response('```json\n{"findings": []}\n```')])
        assert client.call(system="s", user_message="u") == {"findings": []}
