"""LLM client — structured JSON output with retry + validation, pluggable provider.

Centralises LLM interaction so every agent gets the same retry logic,
timeout handling, and response validation.  The ``call`` method returns
parsed JSON (a Python dict/list) or raises.

Providers (``SCAN_TOOLKIT_LLM_PROVIDER``):
  * ``anthropic`` (default) — Anthropic Messages API via the ``anthropic``
    SDK.  Key: ``SCAN_TOOLKIT_ANTHROPIC_API_KEY``.
  * ``openai_compatible`` — any OpenAI-style ``/chat/completions`` endpoint
    over httpx (no extra dependency).  Key: ``SCAN_TOOLKIT_LLM_API_KEY``
    (falls back to ``OPENCODE_API_KEY``).  Use this for Muse Spark via
    OpenCode Zen (base ``https://opencode.ai/zen/v1``, model
    ``muse-spark-1.3-contributor-free``) or Meta's own API
    (``https://api.meta.ai/v1``).

Design decisions:
  * One retry on schema-validation failure (append the error to the
    conversation so the model can self-correct).
  * Hard fail after the retry — never store garbage.
  * temperature=0 on both backends — agents need deterministic JSON.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Any

import anthropic
import httpx

from scan_toolkit.config import get_settings

log = logging.getLogger(__name__)

_ANTHROPIC_DEFAULT_MODEL = "claude-sonnet-4-20250514"
# OpenCode Zen default: Muse Spark 1.3 contributor-free tier.
_OPENAI_COMPAT_DEFAULT_BASE_URL = "https://opencode.ai/zen/v1"
_OPENAI_COMPAT_DEFAULT_MODEL = "muse-spark-1.3-contributor-free"
_MAX_TOKENS = 16_384


# ---------------------------------------------------------------------------
# Backends — each turns (system, messages) into raw response text
# ---------------------------------------------------------------------------

class ChatBackend(ABC):
    @abstractmethod
    def complete(self, *, system: str, messages: list[dict]) -> str:
        """Return the model's raw text reply.  Raise LLMError on failure."""


class AnthropicBackend(ChatBackend):
    """Anthropic Messages API via the first-party SDK."""

    def __init__(self, *, api_key: str, model: str, max_tokens: int):
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model
        self._max_tokens = max_tokens

    def complete(self, *, system: str, messages: list[dict]) -> str:
        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                temperature=0,
                system=system,
                messages=messages,
            )
        except anthropic.APIError as exc:
            raise LLMError(f"Anthropic API error: {exc}") from exc
        text = "".join(
            block.text for block in response.content if block.type == "text")
        if not text.strip():
            raise LLMError("LLM returned empty response")
        return text


class OpenAICompatibleBackend(ChatBackend):
    """Any ``POST {base_url}/chat/completions`` endpoint (Zen, Meta, etc.)."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        max_tokens: int,
        base_url: str,
        transport: httpx.BaseTransport | None = None,
    ):
        self._api_key = api_key
        self._model = model
        self._max_tokens = max_tokens
        self._base_url = base_url.rstrip("/")
        self._transport = transport

    def complete(self, *, system: str, messages: list[dict]) -> str:
        payload = {
            "model": self._model,
            "messages": [{"role": "system", "content": system}, *messages],
            "max_tokens": self._max_tokens,
            "temperature": 0,
        }
        kwargs: dict[str, Any] = {
            "timeout": get_settings().tool_timeout_seconds,
            "follow_redirects": True,
        }
        if self._transport is not None:
            kwargs["transport"] = self._transport
        try:
            with httpx.Client(**kwargs) as client:
                resp = client.post(
                    f"{self._base_url}/chat/completions",
                    headers={"Authorization": f"Bearer {self._api_key}"},
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPError as exc:
            raise LLMError(f"LLM API request failed: {exc}") from exc
        except ValueError as exc:
            raise LLMError(f"LLM returned non-JSON response: {exc}") from exc
        try:
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(
                f"LLM response has no choices[0].message.content: {exc}"
            ) from exc
        if not isinstance(text, str) or not text.strip():
            raise LLMError("LLM returned empty response")
        return text


# ---------------------------------------------------------------------------
# Client — provider selection + retry/validation (provider-agnostic)
# ---------------------------------------------------------------------------

class LLMClient:
    """Stateless wrapper over the configured provider backend."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        max_tokens: int = _MAX_TOKENS,
        provider: str | None = None,
        base_url: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ):
        settings = get_settings()
        self._provider = (provider or settings.llm_provider).strip().lower()
        if self._provider == "anthropic":
            key = api_key or settings.anthropic_api_key
            if not key:
                raise RuntimeError(
                    "SCAN_TOOLKIT_ANTHROPIC_API_KEY is not set. "
                    "Configure it in .env before running LLM agents."
                )
            self._backend: ChatBackend = AnthropicBackend(
                api_key=key,
                model=model or settings.llm_model or _ANTHROPIC_DEFAULT_MODEL,
                max_tokens=max_tokens,
            )
        elif self._provider in ("openai_compatible", "openai-compatible",
                                "opencode", "zen"):
            key = api_key or settings.llm_api_key or settings.zen_api_key
            if not key:
                raise RuntimeError(
                    "SCAN_TOOLKIT_LLM_API_KEY is not set (falls back to "
                    "OPENCODE_API_KEY). Configure it in .env before running "
                    "LLM agents."
                )
            self._backend = OpenAICompatibleBackend(
                api_key=key,
                model=model or settings.llm_model or _OPENAI_COMPAT_DEFAULT_MODEL,
                max_tokens=max_tokens,
                base_url=(base_url or settings.llm_base_url
                          or _OPENAI_COMPAT_DEFAULT_BASE_URL),
                transport=transport,
            )
        else:
            raise ValueError(
                f"unknown LLM provider {self._provider!r} "
                "(use 'anthropic' or 'openai_compatible')"
            )

    @property
    def provider(self) -> str:
        return self._provider

    def call(
        self,
        *,
        system: str,
        user_message: str,
        validate_fn: Any | None = None,
    ) -> dict:
        """Send a prompt and return parsed JSON, with one retry on failure.

        Parameters
        ----------
        system : str
            System prompt.
        user_message : str
            User message containing the data for the LLM to process.
        validate_fn : callable, optional
            ``validate_fn(parsed_dict)`` — should raise ``ValueError`` with
            a human-readable message if the output is invalid.  Called after
            JSON parsing succeeds.

        Returns
        -------
        dict
            Parsed and validated JSON response.

        Raises
        ------
        LLMError
            On non-recoverable failures (bad JSON after retry, API errors).
        """
        messages = [{"role": "user", "content": user_message}]
        parsed = self._attempt(system, messages)

        # --- validate ---
        if validate_fn is not None:
            try:
                validate_fn(parsed)
            except (ValueError, KeyError, TypeError) as exc:
                log.warning("LLM output failed validation: %s — retrying", exc)
                # Append the model's bad answer + an error nudge, then retry.
                messages.append({"role": "assistant", "content": json.dumps(parsed)})
                messages.append({
                    "role": "user",
                    "content": (
                        f"Your previous response failed schema validation:\n\n"
                        f"  {exc}\n\n"
                        f"Please fix the JSON and return a corrected version. "
                        f"Output ONLY the corrected JSON object, nothing else."
                    ),
                })
                parsed = self._attempt(system, messages)
                # Validate again — hard fail this time.
                try:
                    validate_fn(parsed)
                except (ValueError, KeyError, TypeError) as exc2:
                    raise LLMError(
                        f"LLM output failed validation after retry: {exc2}"
                    ) from exc2

        return parsed

    # ------------------------------------------------------------------

    def _attempt(self, system: str, messages: list[dict]) -> dict:
        """Single backend call → parsed JSON dict."""
        text = self._backend.complete(system=system, messages=messages)

        # Strip markdown code fences if present.
        text = _strip_code_fences(text.strip())

        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise LLMError(
                f"LLM returned invalid JSON: {exc}\n\nRaw output:\n{text[:2000]}"
            ) from exc


class LLMError(Exception):
    """Non-recoverable LLM interaction failure."""


def _strip_code_fences(text: str) -> str:
    """Remove ```json ... ``` wrappers if present."""
    if text.startswith("```"):
        # Remove opening fence line.
        first_newline = text.index("\n") if "\n" in text else len(text)
        text = text[first_newline + 1:]
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()
