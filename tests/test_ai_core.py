"""AI-layer fixes: ai_core (JSON, fallback, redaction, logging) + ai/ai_review.

Run: .venv/bin/python -m pytest tests -q
No network: the HTTP transport is replaced by a scripted fake.
"""
import json

import httpx
import pytest
from pydantic import BaseModel

from app import ai, ai_core, ai_review
from app.models import Finding, Severity

A = {"name": "brev", "provider": "brev", "base_url": "https://a.example/v1", "model": "m-a", "api_key": "k-a"}
B = {"name": "nvidia", "provider": "nvidia", "base_url": "https://b.example/v1", "model": "m-b", "api_key": "k-b"}


def reply(content: str, status: int = 200) -> httpx.Response:
    if status >= 400:
        return httpx.Response(status, text=content)
    return httpx.Response(200, json={
        "choices": [{"message": {"content": content}}],
        "usage": {"prompt_tokens": 11, "completion_tokens": 7},
    })


@pytest.fixture
def fake(monkeypatch, tmp_path):
    """Script replies per call; capture every outgoing request."""
    state = {"replies": [], "sent": [], "chain": [A, B]}

    def post(url, payload, headers, timeout):
        state["sent"].append({"url": url, "payload": payload, "headers": headers})
        r = state["replies"].pop(0)
        if isinstance(r, Exception):
            raise r
        return r

    monkeypatch.setattr(ai_core, "_http_post", post)
    monkeypatch.setattr(ai_core, "provider_chain", lambda cfg=None, fallback=True: list(state["chain"]))
    monkeypatch.setattr(ai_core, "CALL_LOG_PATH", tmp_path / "ai_calls.jsonl")
    monkeypatch.setattr(ai_core.time, "sleep", lambda s: None)
    monkeypatch.setattr(ai_core, "_DOWN_UNTIL", {})
    return state


class Verdict(BaseModel):
    verdict: str
    confidence: float


# ------------------------------------------------------------- parsing

def test_parse_strips_think_block_with_braces():
    text = '<think>maybe {"verdict": "wrong"} hmm</think>\n{"verdict": "real", "confidence": 0.9}'
    assert ai_core.parse_json_loose(text) == {"verdict": "real", "confidence": 0.9}


def test_parse_fenced_and_prose():
    text = 'Sure! Here it is:\n```json\n[{"a": 1}]\n```\nHope that helps.'
    assert ai_core.parse_json_loose(text, want=list) == [{"a": 1}]


def test_parse_want_list_skips_leading_object():
    assert ai_core.parse_json_loose('{"note": 1} then ["x.py"]', want=list) == ["x.py"]


def test_parse_unclosed_think_is_no_answer():
    with pytest.raises(ValueError):
        ai_core.parse_json_loose('<think>still thinking {"a": 1}')


# ----------------------------------------------------------- redaction

def test_redact_common_secrets():
    src = "\n".join([
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
        'cryptoKey: "a_secret_key_value",',
        "db = 'mongodb://admin:hunter22@db:27017/app'",
        "key = " + "nvapi-" + "AbCdEf0123456789xyzXYZ",  # split: no token literal in git
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
        "const user = req.body.user;",
    ])
    out, n = ai_core.redact(src)
    assert n >= 5
    for leaked in ("MIIEpAIBAAKCAQEA", "a_secret_key_value", "hunter22", "nvapi-AbCdEf", "abcdefghijklmnop"):
        assert leaked not in out
    assert "const user = req.body.user;" in out  # ordinary code untouched


def test_outgoing_messages_are_redacted(fake):
    fake["replies"] = [reply("ok")]
    text, meta = ai_core.call_text([{"role": "user", "content": 'password = "SuperSecret123"'}])
    sent = json.dumps(fake["sent"][0]["payload"])
    assert "SuperSecret123" not in sent and "[REDACTED]" in sent
    assert meta["redactions"] == 1 and text == "ok"


# ------------------------------------------------ call_json / call_text

def test_call_json_repairs_bad_json_once(fake):
    fake["replies"] = [reply("I think it is real."), reply('{"verdict": "real", "confidence": 0.8}')]
    obj, meta = ai_core.call_json([{"role": "user", "content": "x"}], Verdict, purpose="t")
    assert obj.verdict == "real" and meta["attempts"] == 2 and not meta["fallback_used"]
    # the retry tells the model what was wrong
    assert "not valid for the schema" in fake["sent"][1]["payload"]["messages"][-1]["content"]


def test_call_json_falls_back_to_second_provider(fake):
    fake["replies"] = [reply("boom", 500), reply('{"verdict": "review", "confidence": 0.5}')]
    obj, meta = ai_core.call_json([{"role": "user", "content": "x"}], Verdict)
    assert obj.verdict == "review" and meta["fallback_used"] and meta["model"] == "m-b"


def test_down_provider_is_skipped_during_cooldown(fake):
    ok = '{"verdict": "real", "confidence": 1}'
    fake["replies"] = [reply("boom", 502), reply(ok), reply(ok)]
    ai_core.call_json([{"role": "user", "content": "x"}], Verdict)
    _, meta = ai_core.call_json([{"role": "user", "content": "y"}], Verdict)
    assert [r["payload"]["model"] for r in fake["sent"]] == ["m-a", "m-b", "m-b"]
    assert meta["fallback_used"]  # still reported: primary was not used


def test_client_errors_do_not_trigger_cooldown(fake):
    fake["replies"] = [reply("bad request", 400), reply("ok"), reply("ok")]
    ai_core.call_text([{"role": "user", "content": "x"}])
    ai_core.call_text([{"role": "user", "content": "y"}])
    assert [r["payload"]["model"] for r in fake["sent"]] == ["m-a", "m-b", "m-a"]


def test_call_json_all_fail_raises_first_error(fake):
    fake["replies"] = [reply("rate limited", 429), reply("rate limited", 429), httpx.ConnectError("down")]
    with pytest.raises(ai_core.AIError) as err:
        ai_core.call_json([{"role": "user", "content": "x"}], Verdict)
    assert "429" in str(err.value)  # callers still match on status codes


def test_structured_output_used_for_brev_and_dropped_on_400(fake):
    fake["replies"] = [reply("response_format unsupported", 400), reply('{"verdict": "real", "confidence": 1}')]
    obj, _ = ai_core.call_json([{"role": "user", "content": "x"}], Verdict)
    assert fake["sent"][0]["payload"]["response_format"]["type"] == "json_schema"
    assert "response_format" not in fake["sent"][1]["payload"]
    assert obj.verdict == "real"


def test_call_text_strips_think_and_records_stats(fake):
    since = "0000"
    fake["replies"] = [reply("<think>hmm</think>ok")]
    text, meta = ai_core.call_text([{"role": "user", "content": "x"}], purpose="t")
    assert text == "ok" and meta["tokens_in"] == 11 and meta["tokens_out"] == 7
    s = ai_core.stats(since)
    assert s["calls"] >= 1 and "m-a" in s["models"]
    logged = [json.loads(line) for line in ai_core.CALL_LOG_PATH.read_text().splitlines()]
    assert logged[-1]["model"] == "m-a" and "k-a" not in ai_core.CALL_LOG_PATH.read_text()


def test_not_configured_raises(fake):
    fake["chain"] = []
    with pytest.raises(ai_core.AIError, match="not configured"):
        ai_core.call_text([{"role": "user", "content": "x"}])


# --------------------------------------------------------------- ai.py

def _f(scanner, sev, title, **raw):
    return Finding(scanner=scanner, title=title, severity=sev, description=title,
                   location=f"repo#{title}", raw=raw)


def test_digest_mixes_scanners_and_demotes_dev_deps():
    osv = [_f("osv", Severity.critical, f"cve{i}", scope="dev" if i < 30 else "runtime") for i in range(60)]
    code = [_f("semgrep", Severity.high, f"sqli{i}") for i in range(10)]
    picked = ai._digest_pick(osv + code, 20)
    assert sum(f.scanner == "semgrep" for f in picked) == 10
    assert all((f.raw or {}).get("scope") != "dev" for f in picked if f.scanner == "osv")


def test_analyze_findings_non_ai_fallback(fake):
    fake["replies"] = [reply("down", 503), reply("down", 503)]
    findings = [_f("semgrep", Severity.high, "sqli")]
    out = ai.analyze_findings("repo", findings, cfg=A)
    assert out.raw.get("fallback") == "non-ai" and "AI unavailable" in out.summary
    assert out.prioritized_fixes


def test_analyze_findings_ok(fake):
    fake["replies"] = [reply(json.dumps({
        "summary": "Fix the SQLi first.",
        "prioritized_fixes": [{"step": "Parametrize query", "file": "a.js"}],
        "false_positive_notes": "none",
    }))]
    out = ai.analyze_findings("repo", [_f("semgrep", Severity.high, "sqli")], cfg=A)
    assert out.summary == "Fix the SQLi first." and "Parametrize query" in out.prioritized_fixes[0]
    assert out.model == "m-a" and out.raw["tokens_in"] == 11


# ---------------------------------------------------------- ai_review

def test_nomination_keeps_path_strings(monkeypatch, tmp_path):
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "index.js").write_text("app.get('/', h)\n")
    entries = [(tmp_path / "routes" / "index.js", 16, "routes/index.js")]
    monkeypatch.setattr(ai_review, "_chat_with_retry",
                        lambda m, c, max_tokens: ('<think>[x]</think>["NodeGoat/routes/index.js"]', 0.0, 1))
    assert ai_review.nominate_files(tmp_path, entries, A, limit=5) == ["routes/index.js"]


def test_excerpt_sends_numbered_windows_not_whole_file(tmp_path):
    lines = [f"var filler{i} = {i};" for i in range(2000)]
    lines[1200] = "db.query('SELECT * FROM users WHERE id=' + req.query.id)"
    p = tmp_path / "big.js"
    p.write_text("\n".join(lines))
    out = ai_review._excerpt(p)
    assert len(out) <= ai_review.EXCERPT_CAP + 200
    assert "1201: db.query(" in out and "1: var filler0" not in out
