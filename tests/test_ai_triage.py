"""Friend A: prefilter + triage tests (no network).

Run: .venv/bin/python -m pytest tests -q
The model is stubbed by monkeypatching app.ai_core.call_json.
"""
import math
from pathlib import Path

import pytest
from pydantic import BaseModel

from app import ai_core, ai_triage
from app.ai_triage import TriageBatch, code_window, locate, prefilter, triage
from app.models import Finding, Severity


def _f(fid="f1", scanner="semgrep", sev=Severity.high, title="SQLi",
       location="repo#app/a.js:10", **raw):
    # unique default location per id so dedupe() does not merge test rows
    if location == "repo#app/a.js:10":
        location = f"repo#app/{fid}.js:10"
    return Finding(id=fid, scanner=scanner, title=title, severity=sev,
                   description=title, location=location, raw=dict(raw))


# --------------------------------------------------------------- locate


def test_locate_from_raw_file_and_line():
    f = _f(location="https://x#other/b.js:99", file="app/a.js", line=12)
    assert locate(f) == ("app/a.js", 12)


def test_locate_from_location_suffix():
    f = _f(location="https://github.com/OWASP/NodeGoat#app/routes/index.js:42")
    assert locate(f) == ("app/routes/index.js", 42)


def test_locate_location_without_line():
    f = _f(location="https://x#package-lock.json")
    assert locate(f) == ("package-lock.json", None)


def test_locate_no_file_anywhere():
    f = _f(location="https://x")
    assert locate(f) == (None, None)


# ------------------------------------------------------------- prefilter


def test_prefilter_drops_dev_fixtures_info_and_review():
    findings = [
        _f("dev1", scanner="osv", sev=Severity.critical, scope="dev"),
        _f("fx1", scanner="gitleaks", sev=Severity.high, likely_test_fixture=True),
        _f("info1", scanner="semgrep", sev=Severity.info),
        _f("rev1", scanner="ai-code-review", sev=Severity.high),
        _f("keep1", scanner="semgrep", sev=Severity.high),
        _f("keep2", scanner="osv", sev=Severity.medium, scope="runtime"),
    ]
    out = prefilter(findings)
    # Stable finding IDs (normalize.stable_id) replace caller-set ids;
    # assert survival by location (unique per row in this fixture).
    assert [f.location for f in out] == ["repo#app/keep1.js:10", "repo#app/keep2.js:10"]


def test_prefilter_keeps_priority_order_and_limit():
    findings = [_f(f"m{i}", sev=Severity.medium) for i in range(5)]
    findings += [_f(f"c{i}", sev=Severity.critical) for i in range(5)]
    out = prefilter(findings, limit=3)
    assert len(out) == 3
    assert all(f.severity == Severity.critical for f in out)


def test_prefilter_no_ai_import():
    import ast
    src = Path("app/ai_triage.py").read_text()
    tree = ast.parse(src)
    # prefilter() body must not reference the model client
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "prefilter":
            body = ast.dump(node)
            assert "call_json" not in body and "chat_complete" not in body


# ---------------------------------------------------------- code window


def test_code_window_numbered_and_missing(tmp_path):
    p = tmp_path / "a.js"
    p.write_text("\n".join(f"line{i}" for i in range(1, 101)))
    out = code_window(tmp_path, "a.js", 50, radius=20)
    rows = out.splitlines()
    assert len(rows) == 41
    assert rows[0].startswith("30: ") and rows[-1].startswith("70: ")
    assert "50: line50" in rows
    assert code_window(tmp_path, "nope.js", 1) == ""
    # traversal outside workdir -> ""
    assert code_window(tmp_path, "../evil.js", 1) == ""


# ---------------------------------------------------------------- triage


class _Item(BaseModel):
    finding_id: str
    verdict: str = "real"
    confidence: float = 0.9
    reason: str = "r"


def _batch_reply(items):
    return TriageBatch(items=[
        ai_triage.TriageItem(finding_id=i[0], verdict=i[1],
                             confidence=i[2], reason=i[3]) for i in items
    ])


def test_triage_batches_five_per_call(monkeypatch, tmp_path):
    findings = [_f(f"id{i}", location=f"r#a{i}.js:{i + 1}") for i in range(12)]
    calls = []

    def fake_call(messages, schema, **kw):
        calls.append(messages)
        # return "real" for every finding in this batch by parsing IDs
        n = messages[1]["content"].count("ID: id")
        start = (len(calls) - 1) * 5
        items = [(f"id{start + k}", "real", 0.8, "uses sink") for k in range(n)]
        return _batch_reply(items), {"model": "m", "latency_ms": 1}

    monkeypatch.setattr(ai_core, "call_json", fake_call)
    out = triage(findings, tmp_path)
    assert len(out) == 12
    assert len(calls) == math.ceil(12 / 5) == 3
    assert all(o["verdict"] == "real" for o in out)
    # only the core JSON helper may talk to the model
    src = Path("app/ai_triage.py").read_text()
    assert "ai_core.call_json" in src or "call_json(" in src
    assert "httpx" not in src and "OpenAI" not in src


def test_triage_aierror_maps_to_review(monkeypatch, tmp_path):
    findings = [_f("a"), _f("b")]

    def boom(messages, schema, **kw):
        raise ai_core.AIError("all providers down")

    monkeypatch.setattr(ai_core, "call_json", boom)
    out = triage(findings, tmp_path)
    assert [o["finding_id"] for o in out] == ["a", "b"]
    assert all(o["verdict"] == "review" and o["confidence"] == 0.0 for o in out)
    assert all(o["reason"].startswith("AI unavailable:") for o in out)


def test_triage_empty_never_calls(monkeypatch, tmp_path):
    def boom(*a, **k):
        raise AssertionError("must not call the model")
    monkeypatch.setattr(ai_core, "call_json", boom)
    assert triage([], tmp_path) == []
