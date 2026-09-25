"""Thin Anthropic API wrapper — structured JSON output with retry + validation.

Centralises LLM interaction so every agent gets the same retry logic,
timeout handling, and response validation.  The ``call`` method returns
parsed JSON (a Python dict/list) or raises.

Design decisions:
  * One retry on schema-validation failure (append the error to the
    conversation so the model can self-correct).
  * Hard fail after the retry — never store garbage.
  * ``anthropic`` SDK is used directly (no langchain/etc.) to keep the
    dependency footprint small and the interface predictable.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import anthropic

from scan_toolkit.config import get_settings

log = logging.getLogger(__name__)

# Default model — Claude Sonnet for cost/speed balance on structured tasks.
_DEFAULT_MODEL = "claude-sonnet-4-20250514"
_MAX_TOKENS = 16_384


class LLMClient:
    """Stateless wrapper around the Anthropic Messages API."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        max_tokens: int = _MAX_TOKENS,
    ):
        key = api_key or get_settings().anthropic_api_key
        if not key:
            raise RuntimeError(
                "SCAN_TOOLKIT_ANTHROPIC_API_KEY is not set. "
                "Configure it in .env before running LLM agents."
            )
        self._client = anthropic.Anthropic(api_key=key)
        self._model = model or _DEFAULT_MODEL
        self._max_tokens = max_tokens

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
        """Single API call → parsed JSON dict."""
        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                system=system,
                messages=messages,
            )
        except anthropic.APIError as exc:
            raise LLMError(f"Anthropic API error: {exc}") from exc

        # Extract text content from the response.
        text = ""
        for block in response.content:
            if block.type == "text":
                text += block.text

        if not text.strip():
            raise LLMError("LLM returned empty response")

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
