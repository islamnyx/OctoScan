"""Deterministic redaction of secrets/PII before LLM and report boundaries.

The API/Backend agent (Phase 7) is the first agent whose input routinely
contains live secrets (Authorization headers, session cookies, passwords
in captured traffic) and PII (emails in test accounts).  Redaction here is
RULE-BASED and runs BEFORE any LLM call — it does not depend on the model
behaving well, and the system prompt's redaction instruction is only a
second layer.

What is redacted (-> ``[REDACTED]``):
  * Authorization headers (Bearer/Basic/Token) and Set-Cookie values
  * labelled secrets: password/passwd/api_key/session/token/secret values
  * JWT-shaped tokens
  * email addresses
  * secret-ish query params (token/session/auth/key/password)

What is NOT covered (documented limits — the human reviewer stays
responsible):
  * real names / phone numbers without labels (no reliable regex exists;
    the agent prompt instructs the model to redact obvious PII too)
  * secrets under exotic field names (e.g. ``x_acme_vault``)
"""

from __future__ import annotations

import copy
import re

REDACTED = "[REDACTED]"

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Authorization: Bearer <token>  (keep the scheme, redact the secret)
    (
        re.compile(
            r"(?im)^(authorization\s*:\s*(?:bearer|basic|token|digest)\s+)\S+",
        ),
        r"\1" + REDACTED,
    ),
    # Set-Cookie: <entire value> — the whole cookie is session state
    (
        re.compile(r"(?im)^(set-cookie\s*:\s*).+$"),
        r"\1" + REDACTED,
    ),
    # Cookie: <entire value>
    (
        re.compile(r"(?im)^(cookie\s*:\s*).+$"),
        r"\1" + REDACTED,
    ),
    # "password": "secret..." / password=secret (JSON, headers, bodies, HAR)
    (
        re.compile(
            r"(?i)(\"(?:password|passwd|pwd|api[_-]?key|session[_-]?id|"
            r"auth[_-]?token|access[_-]?token|refresh[_-]?token|id[_-]?token|"
            r"client[_-]?secret|secret)\"\s*:\s*\")([^\"]*)(\")",
        ),
        r"\1" + REDACTED + r"\3",
    ),
    (
        re.compile(
            r"(?i)\b(password|passwd|pwd|api[_-]?key|session[_-]?id|"
            r"auth[_-]?token|access[_-]?token|secret)\s*=\s*([^&\s\"'};,]+)",
        ),
        r"\1=" + REDACTED,
    ),
    # ?token=...& / ?sessionid=... in URLs
    (
        re.compile(
            r"(?i)([?&](?:token|session|sess|auth|api[_-]?key|password)"
            r"[^=]*=)([^&\s\"'}]+)",
        ),
        r"\1" + REDACTED,
    ),
    # JWT-shaped tokens anywhere
    (
        re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        REDACTED,
    ),
    # Bare "Bearer <token>" outside an Authorization header line
    # (token-like: 8+ chars, no spaces — avoids mangling prose).
    (
        re.compile(r"\b(Bearer\s+)([A-Za-z0-9\-._~+/=]{8,})"),
        r"\1" + REDACTED,
    ),
    # Email addresses (PII)
    (
        re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
        REDACTED,
    ),
]


def redact_text(text: str | None) -> str | None:
    """Apply all redaction patterns to a string (None-safe)."""
    if not text:
        return text
    redacted = text
    for pattern, replacement in _PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def redact_dict(obj: dict) -> dict:
    """Deep-copy a dict with redaction applied to every string value."""
    scrubbed = copy.deepcopy(obj)

    def _walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, str):
                    node[key] = redact_text(value)
                else:
                    _walk(value)
        elif isinstance(node, list):
            for i, value in enumerate(node):
                if isinstance(value, str):
                    node[i] = redact_text(value)
                else:
                    _walk(value)

    _walk(scrubbed)
    return scrubbed
