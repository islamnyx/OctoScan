"""ai_story: one call_json -> attack story + verdict; rule-based on AIError.

Run: .venv/bin/python -m pytest tests -q   (call_json monkeypatched, no network)
"""
import pytest

from app import ai_core, ai_story

REAL = [
    {"id": "a", "title": "eval() on request body", "severity": "high", "file": "app/routes/contributions.js",
     "line": 32, "reason": "req.body reaches eval", "fixed_and_verified": True},
    {"id": "b", "title": "Open redirect", "severity": "medium", "file": "app/routes/index.js", "line": 72,
     "reason": "url param reaches redirect"},
]


@pytest.fixture
def model(monkeypatch):
    state = {"reply": None, "calls": []}

    def fake(messages, schema, **kw):
        state["calls"].append({"messages": messages, **kw})
        if isinstance(state["reply"], Exception):
            raise state["reply"]
        return schema.model_validate(state["reply"]), {"model": "brev"}

    monkeypatch.setattr(ai_core, "call_json", fake)
    return state


def test_valid_story(model):
    model["reply"] = {"verdict": "not_ready", "blockers": ["RCE via eval in contributions.js"],
                      "attack_story": "An attacker sends JavaScript instead of a number..."}
    out = ai_story.attack_story(REAL, "https://github.com/OWASP/NodeGoat")
    assert out == {"verdict": "not_ready", "blockers": ["RCE via eval in contributions.js"],
                   "attack_story": "An attacker sends JavaScript instead of a number..."}
    assert len(model["calls"]) == 1 and model["calls"][0]["purpose"] == "story"
    sent = model["calls"][0]["messages"][-1]["content"]
    assert "eval() on request body" in sent and '"fixed_and_verified": true' in sent


def test_ai_error_rule_based(model):
    model["reply"] = ai_core.AIError("AI provider unreachable")
    out = ai_story.attack_story(REAL, "t")
    assert out["verdict"] == "not_ready"
    assert out["blockers"] == ["eval() on request body (app/routes/contributions.js:32)"]
    assert out["attack_story"].startswith("AI unavailable:")


def test_ai_error_only_medium_is_ready(model):
    model["reply"] = ai_core.AIError("down")
    assert ai_story.attack_story(REAL[1:], "t")["verdict"] == "ready"


def test_model_cannot_call_ready_with_high_finding(model):
    model["reply"] = {"verdict": "ready", "blockers": [], "attack_story": "looks fine"}
    out = ai_story.attack_story(REAL, "t")
    assert out["verdict"] == "not_ready" and out["blockers"][0].startswith("eval() on request body")


def test_no_real_findings_no_call(model):
    out = ai_story.attack_story([], "t")
    assert out["verdict"] == "ready" and out["blockers"] == [] and model["calls"] == []


def test_blockers_capped_and_trimmed(model):
    model["reply"] = {"verdict": "not_ready", "blockers": [" x "] * 10 + [""], "attack_story": " s "}
    out = ai_story.attack_story(REAL, "t")
    assert out["blockers"] == ["x"] * 6 and out["attack_story"] == "s"
