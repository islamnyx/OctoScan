"""Secret redaction for everything sent to a cloud model.

Single choke point: app.ai_core.call_text/call_json redact every message
through here (and log only counts, never keys). ai_fix/ai_review also use
`redact` for diffs pasted into prompts or stored in API output.
"""

from __future__ import annotations

import re

_KEYWORDS = r"(?:password|passwd|pwd|secret|token|key|salt|credential|auth)"
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
     "[REDACTED PRIVATE KEY]"),
    (re.compile(r"\bnvapi-[A-Za-z0-9_-]{16,}"), "[REDACTED]"),
    (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}"), "[REDACTED]"),
    (re.compile(r"\bgsk_[A-Za-z0-9]{20,}"), "[REDACTED]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), "[REDACTED]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "[REDACTED]"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"), "[REDACTED JWT]"),
    (re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/-]{16,}=*"), r"\1[REDACTED]"),
    # user:password@ in connection strings (mongodb://, postgres://, https://)
    (re.compile(r"(\b[a-z][a-z0-9+.-]*://[^:/\s@]+:)[^@\s/]{3,}@", re.I), r"\1[REDACTED]@"),
    # name = "literal" where name looks secret-ish (password, apiKey, cryptoKey…)
    (re.compile(
        r"(?i)(\b[\w.-]*" + _KEYWORDS + r"[\w.-]*[\"']?\s*(?:[:=]|=>)\s*)([\"'`])([^\"'`\n]{4,})\2"),
     r"\1\2[REDACTED]\2"),
    # comparisons against a literal: password === 'hunter2' (Juice Shop login.ts)
    (re.compile(
        r"(?i)(\b[\w.]*" + _KEYWORDS + r"[\w.]*\s*(?:===|!==|==|!=)\s*)([\"'`])([^\"'`\n]{4,})\2"),
     r"\1\2[REDACTED]\2"),
]


def redact(text: str) -> tuple[str, int]:
    """Return (text with secrets masked, number of replacements)."""
    if not text:
        return text or "", 0
    total = 0
    for pattern, repl in _SECRET_PATTERNS:
        text, n = pattern.subn(repl, text)
        total += n
    return text, total


def redact_messages(messages: list[dict[str, str]]) -> tuple[list[dict[str, str]], int]:
    """Redact every message's content. Returns (messages, total)."""
    out, total = [], 0
    for m in messages:
        content, n = redact(str(m.get("content") or ""))
        total += n
        out.append({**m, "content": content})
    return out, total
