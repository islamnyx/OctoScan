"""Test-fixture context for secret findings (Task 1).

WebGoat-style lesson repos ship ~dozens of intentional hardcoded
secrets (JWT/crypto teaching fixtures, e.g. secretKey=test). Reporting
them as production leaks destroys client-report credibility.

Rule (from Notion NEXT page): keep the finding (auditors like full
lists) but mark likely_test_fixture=true + lower severity, and exclude
from headline secret counts / client PDFs by default.
"""
from __future__ import annotations

import re
from pathlib import Path

from app.models import Severity

# Directory parts that signal test / teaching / sample code.
TEST_DIR_PARTS = frozenset({
    "test", "tests", "__tests__", "testing", "testdata",
    "spec", "specs", "src/test", "src/it", "it",
    "fixtures", "fixture", "mocks", "mock",
    "examples", "example", "samples", "sample",
    "docs", "doc", "tutorial", "tutorials", "lessons", "lesson",
    "training", "workshop", "demo", "demos",
})

# Filename signals (WebGoat: *Test.java, lesson files, etc.)
TEST_FILE_RE = re.compile(
    r"(?i)(test|spec|fixture|mock|example|sample|dummy|fake|lesson|tutorial|docs?)"
)

# Placeholder secret values — the secret itself is literally one of these.
PLACEHOLDER_VALUES = frozenset({
    "test", "testing", "admin", "password", "passwd", "secret",
    "changeme", "change-me", "example", "placeholder", "dummy", "fake",
    "123456", "12345678", "qwerty", "letmein",
    "john", "doe", "john doe",
})

# Substrings inside a secret value that mark it as a placeholder/demo.
PLACEHOLDER_SUBSTR_RE = re.compile(
    r"(?i)(test|example|placeholder|changeme|change-me|dummy|fake|sample|tutorial|john.?doe)"
)


def _norm_secret(secret: str) -> str:
    s = (secret or "").strip().strip("\"'").strip()
    # Strip common prefixes like "secretKey = test" -> "test".
    if "=" in s or ":" in s:
        s = re.split(r"[:=]", s)[-1].strip().strip("\"'").strip()
    return s.lower()


def is_likely_test_fixture(file_path: str, secret: str = "", context: str = "") -> bool:
    """True when a secret finding is probably a teaching/test fixture."""
    path_lower = (file_path or "").replace("\\", "/").lower()
    parts = set(path_lower.split("/"))
    # 1. Test / teaching directories (covers src/test, src/it, fixtures…).
    if parts & TEST_DIR_PARTS:
        return True
    if "/src/test/" in path_lower or "/src/it/" in path_lower:
        return True
    # 2. Test-ish filenames.
    try:
        name = Path(file_path or "").name
    except Exception:
        name = file_path or ""
    if name and TEST_FILE_RE.search(name):
        return True
    # 3. Placeholder secret value.
    norm = _norm_secret(secret)
    if norm in PLACEHOLDER_VALUES:
        return True
    if norm and PLACEHOLDER_SUBSTR_RE.search(norm):
        return True
    # 4. Placeholder context (e.g. JWT decoding to a John Doe example).
    if context and PLACEHOLDER_SUBSTR_RE.search(context):
        # Only when the secret itself looks weak/short or the context is
        # explicitly a lesson — avoid flagging real leaks that merely
        # mention "test" nearby. Require short secret or lesson keywords.
        if len(norm) <= 24 or re.search(r"(?i)(lesson|tutorial|example|fixture)", context):
            return True
    return False


def downgrade_for_fixture(sev: Severity) -> Severity:
    """Lower severity one rank for fixtures (min low, info stays info)."""
    order = [Severity.info, Severity.low, Severity.medium, Severity.high, Severity.critical]
    try:
        idx = order.index(sev)
    except ValueError:
        return Severity.low
    if sev == Severity.info:
        return Severity.info
    return order[max(0, idx - 1)]


FIXTURE_NOTE = (
    "Likely test fixture — found in test/teaching code or uses a "
    "placeholder value. Verify before treating as a leaked production secret."
)
