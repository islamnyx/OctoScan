"""ai_fix: patch a ~40-line window, apply to a COPY, re-run only the rule.

Run: .venv/bin/python -m pytest tests -q
call_json is monkeypatched (no network). The two real-binary tests use the
in-repo custom semgrep rules / gitleaks and are skipped when missing.
"""
import hashlib
import shutil

import pytest

from app import ai_core, ai_fix
from app.models import Finding, Severity

SRC = """const express = require('express');

function handler(req, res) {
    const a = 1;
    const preTax = eval(req.body.preTax);
    const b = 2;
    res.send(String(preTax + a + b));
}

module.exports = handler;
"""


def finding(scanner="semgrep", rel="app/routes/x.js", line=5, **raw):
    raw = raw or ({"check": "javascript.browser.security.eval-detected.eval-detected", "file": rel}
                  if scanner == "semgrep" else {"rule": "generic-api-key", "file": rel})
    return Finding(scanner=scanner, title=f"{scanner} in {rel}", severity=Severity.high,
                   description="eval with user input", location=f"https://g/x#{rel}:{line}", raw=raw)


@pytest.fixture
def repo(tmp_path):
    wd = tmp_path / "src"
    (wd / "app/routes").mkdir(parents=True)
    (wd / "app/routes/x.js").write_text(SRC)
    return wd


@pytest.fixture
def model(monkeypatch):
    """Scripted call_json: each call pops the next reply (or raises it)."""
    state = {"replies": [], "calls": []}

    def fake(messages, schema, **kw):
        state["calls"].append({"messages": messages, "schema": schema, **kw})
        r = state["replies"].pop(0)
        if isinstance(r, Exception):
            raise r
        return schema.model_validate(r), {"model": "fake"}

    monkeypatch.setattr(ai_core, "call_json", fake)
    return state


def fake_verify(monkeypatch, before, after, broken=False, error=""):
    monkeypatch.setattr(ai_fix, "run_semgrep_rule",
                        lambda check, d: {"before": before, "after": after, "broken": broken, "error": error})


def digest(path):
    return {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(path.rglob("*")) if p.is_file()}


GOOD = {"start_line": 5, "end_line": 5, "replacement": "    const preTax = parseInt(req.body.preTax, 10);",
        "explanation": "parseInt instead of eval"}


# ------------------------------------------------------------ pure helpers

def test_locate_from_raw_and_location():
    assert ai_fix.locate(finding(line=12)) == ("app/routes/x.js", 12)
    f = Finding(scanner="semgrep", title="t", severity=Severity.low, description="",
                location="https://g/x#lib/a.py:7")
    assert ai_fix.locate(f) == ("lib/a.py", 7)


def test_window_numbers_lines():
    lines = SRC.splitlines(keepends=True)
    lo, hi, text = ai_fix.window(lines, 5, radius=2)
    assert (lo, hi) == (3, 7)
    assert text.splitlines()[2] == "5:     const preTax = eval(req.body.preTax);"


def test_apply_patch_and_diff():
    lines = SRC.splitlines(keepends=True)
    out = ai_fix.apply_patch(lines, ai_fix.PatchReply(**GOOD), 1, 10)
    assert out[4] == "    const preTax = parseInt(req.body.preTax, 10);\n"
    assert len(out) == len(lines)
    diff = ai_fix.unified_diff(lines, out, "app/routes/x.js")
    assert "-    const preTax = eval(req.body.preTax);" in diff and "+++ b/app/routes/x.js" in diff


def test_apply_patch_strips_echoed_numbers():
    lines = SRC.splitlines(keepends=True)
    reply = ai_fix.PatchReply(start_line=5, end_line=5, explanation="x",
                              replacement="5:     const preTax = Number(req.body.preTax);")
    assert ai_fix.apply_patch(lines, reply, 1, 10)[4] == "    const preTax = Number(req.body.preTax);\n"


@pytest.mark.parametrize("s,e", [(0, 2), (4, 12), (6, 4)])
def test_apply_patch_rejects_out_of_window(s, e):
    lines = SRC.splitlines(keepends=True)
    with pytest.raises(ai_fix.PatchError):
        ai_fix.apply_patch(lines, ai_fix.PatchReply(start_line=s, end_line=e, replacement="x", explanation=""), 1, 10)


def test_apply_patch_restores_redacted_echo_and_rejects_placeholder():
    lines = ['const cfg = {\n', '  cookieSecret: "super-secret-value",\n', '  port: 80,\n', '};\n']
    # Model changed port but copied the (redacted) secret line verbatim.
    reply = ai_fix.PatchReply(start_line=2, end_line=3, explanation="",
                              replacement='  cookieSecret: "[REDACTED]",\n  port: Number(process.env.PORT),')
    out = ai_fix.apply_patch(lines, reply, 1, 4)
    assert out[1] == '  cookieSecret: "super-secret-value",\n'
    bad = ai_fix.PatchReply(start_line=3, end_line=3, explanation="", replacement='  port: "[REDACTED]",')
    with pytest.raises(ai_fix.PatchError):
        ai_fix.apply_patch(lines, bad, 1, 4)


def test_apply_patch_rejects_noop():
    lines = SRC.splitlines(keepends=True)
    same = ai_fix.PatchReply(start_line=5, end_line=5, explanation="", replacement=lines[4].rstrip("\n"))
    with pytest.raises(ai_fix.PatchError):
        ai_fix.apply_patch(lines, same, 1, 10)


# ------------------------------------------------------------ fix_finding

def test_fix_verified_true_and_clone_untouched(repo, tmp_path, model, monkeypatch):
    fake_verify(monkeypatch, 3, 2)
    model["replies"] = [GOOD]
    before = digest(repo)
    fix = ai_fix.fix_finding(finding(), repo, tmp_path / "run")
    assert fix.verified is True and "3 -> 2" in fix.note
    assert fix.diff.startswith("--- a/app/routes/x.js") and fix.explanation == GOOD["explanation"]
    assert digest(repo) == before  # kept clone never written
    fix_dir = tmp_path / "run" / f"{fix.finding_id}-1"
    assert "eval(" in (fix_dir / "before/app/routes/x.js").read_text()
    assert "parseInt" in (fix_dir / "after/app/routes/x.js").read_text()
    # ~40-line window with numbered lines went to the model, one call.
    assert len(model["calls"]) == 1 and "5:     const preTax = eval" in model["calls"][0]["messages"][-1]["content"]


@pytest.mark.parametrize("b,a,broken,err,expected", [
    (3, 3, False, "", False),      # rule still fires as often
    (1, 0, True, "", False),       # patch breaks parsing
    (0, 0, False, "", None),       # rule did not fire on the original
    (0, 0, False, "rule unavailable", None),
])
def test_fix_verification_outcomes(repo, tmp_path, model, monkeypatch, b, a, broken, err, expected):
    fake_verify(monkeypatch, b, a, broken, err)
    model["replies"] = [GOOD]
    assert ai_fix.fix_finding(finding(), repo, tmp_path / "run").verified is expected


def test_osv_is_not_verifiable_and_costs_no_call(repo, tmp_path, model):
    f = Finding(scanner="osv", title="lodash CVE", severity=Severity.high, description="",
                recommendation="Upgrade lodash to 4.17.21", location="package.json")
    fix = ai_fix.fix_finding(f, repo, tmp_path / "run")
    assert fix.verified is None and fix.diff == "" and "4.17.21" in fix.explanation
    assert model["calls"] == []


def test_ai_error_gives_null_not_crash(repo, tmp_path, model):
    model["replies"] = [ai_core.AIError("AI provider unreachable")]
    fix = ai_fix.fix_finding(finding(), repo, tmp_path / "run")
    assert fix.verified is None and fix.diff == "" and "AI unavailable" in fix.note


def test_rejected_patch_is_null(repo, tmp_path, model):
    model["replies"] = [{"start_line": 40, "end_line": 41, "replacement": "x", "explanation": "e"}]
    fix = ai_fix.fix_finding(finding(), repo, tmp_path / "run")
    assert fix.verified is None and "patch rejected" in fix.note


def test_path_traversal_and_key_files_not_patchable(repo, tmp_path, model):
    (repo / "server.key").write_text("-----BEGIN RSA PRIVATE KEY-----\nabc\n")
    for rel in ("../../etc/passwd", "server.key", "missing.js"):
        fix = ai_fix.fix_finding(finding(rel=rel, line=1), repo, tmp_path / "run")
        assert fix.verified is None and fix.diff == ""
    assert model["calls"] == []


# ----------------------------------------------------- real binaries (opt.)

@pytest.mark.skipif(not shutil.which("semgrep"), reason="semgrep not installed")
def test_real_semgrep_custom_rule(tmp_path, model):
    wd = tmp_path / "src"
    (wd / "app/data").mkdir(parents=True)
    (wd / "app/data/dao.js").write_text(
        "function q(userId, threshold) {\n"
        "    return {\n"
        "        $where: `this.userId == ${userId} && this.stocks > '${threshold}'`\n"
        "    };\n"
        "}\nmodule.exports = q;\n")
    f = finding(rel="app/data/dao.js", line=3, check="semgrep-rules.nodegoat-nosql-where-interpolation",
                file="app/data/dao.js")
    model["replies"] = [
        {"start_line": 2, "end_line": 4, "explanation": "query operators, no $where",
         "replacement": "    return {\n        userId: userId,\n        stocks: { $gt: parseInt(threshold, 10) }\n    };"},
        {"start_line": 3, "end_line": 3, "explanation": "broken", "replacement": "        $where: `x ${threshold}` ((("},
    ]
    good = ai_fix.fix_finding(f, wd, tmp_path / "run")
    assert good.verified is True, good.note
    bad = ai_fix.fix_finding(f, wd, tmp_path / "run", attempt=2)
    assert bad.verified is False, bad.note


@pytest.mark.skipif(not shutil.which("gitleaks"), reason="gitleaks not installed")
def test_real_gitleaks_rule(tmp_path, model):
    wd = tmp_path / "src"
    (wd / "config").mkdir(parents=True)
    (wd / "config/prod.js").write_text(
        'module.exports = {\n   zapApiKey: "v9dn0balpqas1pcc281tn5ood1",\n   port: 80\n};\n')
    f = finding(scanner="gitleaks", rel="config/prod.js", line=2)
    model["replies"] = [{"start_line": 2, "end_line": 2, "explanation": "read from env",
                         "replacement": "   zapApiKey: process.env.ZAP_API_KEY,"}]
    fix = ai_fix.fix_finding(f, wd, tmp_path / "run")
    assert fix.verified is True, fix.note
    assert "v9dn0balpqas1pcc281tn5ood1" not in fix.diff and "process.env.ZAP_API_KEY" in fix.diff
    # call_json redacts every message before sending: the secret never leaves.
    sent, _ = ai_core.redact(model["calls"][0]["messages"][-1]["content"])
    assert "v9dn0balpqas1pcc281tn5ood1" not in sent


@pytest.mark.skipif(not shutil.which("semgrep"), reason="semgrep not installed")
def test_real_semgrep_with_relative_run_dir(tmp_path, model, monkeypatch):
    # DATA_DIR=data in .env makes run_dir relative; semgrep runs with cwd=fix_dir.
    wd = tmp_path / "src"
    (wd / "app").mkdir(parents=True)
    (wd / "app/dao.js").write_text("function q(t) {\n    return { $where: `this.stocks > '${t}'` };\n}\n")
    f = finding(rel="app/dao.js", line=2, check="semgrep-rules.nodegoat-nosql-where-interpolation", file="app/dao.js")
    model["replies"] = [{"start_line": 2, "end_line": 2, "explanation": "operator query",
                         "replacement": "    return { stocks: { $gt: parseInt(t, 10) } };"}]
    monkeypatch.chdir(tmp_path)
    fix = ai_fix.fix_finding(f, wd, tmp_path.relative_to(tmp_path) / "run")
    assert fix.verified is True, fix.note
