"""Guided agent loop + /api/agent-scan (docs/NEXT.md frozen API).

Run: .venv/bin/python -m pytest tests -q
No network: call_json, the repo scan, triage/story modules and the
semgrep re-run are all replaced by deterministic fakes.
"""
import hashlib
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app import ai_agent, ai_core, ai_fix, main, repo_pipeline, repo_store
from app.config import settings
from app.models import AgentRun, Finding, RepoScanJob, ScanStatus, Severity

REPO = "https://github.com/OWASP/NodeGoat"
SRC = ("function h(req, res) {\n    const a = 1;\n    const preTax = eval(req.body.preTax);\n"
       "    res.send(String(preTax + a));\n}\nmodule.exports = h;\n")
FIXED = "    const preTax = parseInt(req.body.preTax, 10);"


def f(fid, scanner, sev, rel="app/x.js", line=3, **raw):
    return Finding(id=fid, scanner=scanner, title=f"{scanner} {fid} in {rel}", severity=sev,
                   description="d", recommendation="Upgrade lodash to 4.17.21" if scanner == "osv" else "",
                   location=f"{REPO}#{rel}:{line}", raw={"file": rel, **raw})


FINDINGS = [
    f("eval1", "semgrep", Severity.high, check="javascript.browser.security.eval-detected.eval-detected"),
    f("fp1", "semgrep", Severity.medium, check="html.security.plaintext-http-link.plaintext-http-link"),
    f("osv1", "osv", Severity.high, rel="package-lock.json", line=None, scope="runtime"),
    f("osvdev", "osv", Severity.critical, rel="package-lock.json", line=None, scope="dev"),
    f("fixture", "gitleaks", Severity.low, rule="generic-api-key", likely_test_fixture=True),
    f("info1", "semgrep", Severity.info),
]
VERDICTS = {"eval1": "real", "fp1": "false_positive", "osv1": "real"}


def digest(path):
    return {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(path.rglob("*")) if p.is_file()}


@pytest.fixture
def env(tmp_path, monkeypatch):
    wd = tmp_path / "src"
    (wd / "app").mkdir(parents=True)
    (wd / "app/x.js").write_text(SRC)
    jobs: dict[str, RepoScanJob] = {}
    monkeypatch.setattr(ai_agent, "AGENT_DIR", tmp_path / "agent")
    monkeypatch.setattr(ai_agent, "_RUNS", {})
    monkeypatch.setattr(repo_store, "save_repo_job", lambda j: jobs.__setitem__(j.id, j))
    monkeypatch.setattr(repo_store, "load_repo_job", lambda i: jobs.get(i))
    monkeypatch.setattr(repo_store, "list_repo_jobs", lambda: list(jobs.values()))
    monkeypatch.setattr(repo_store, "repo_workdir", lambda i: wd)

    def fake_scan(scan_id, run_ai=False):
        j = jobs[scan_id]
        j.status, j.findings, j.files_scanned = ScanStatus.completed, list(FINDINGS), 2
        j.scanners_run = ["gitleaks", "semgrep", "osv"]

    monkeypatch.setattr(repo_pipeline, "run_repo_scan", fake_scan)

    state = {"decisions": {}, "patches": [], "calls": [], "story_in": None, "verify": [(1, 0)]}

    def fake_triage(batch, workdir):
        return [{"finding_id": x.id, "verdict": VERDICTS.get(x.id, "review"), "confidence": 0.9,
                 "reason": f"reason {x.id}"} for x in batch]

    def fake_story(real, target):
        state["story_in"] = real
        return {"verdict": "not_ready", "blockers": ["eval in app/x.js"], "attack_story": "Attacker posts code."}

    monkeypatch.setattr(ai_agent, "_triage_mod", SimpleNamespace(triage=fake_triage))  # prefilter/locate: stand-in
    monkeypatch.setattr(ai_agent, "_story_mod", SimpleNamespace(attack_story=fake_story))

    def fake_call_json(messages, schema, **kw):
        purpose = kw.get("purpose", "")
        state["calls"].append(purpose)
        if purpose == "fix":
            r = state["patches"].pop(0) if state["patches"] else {
                "start_line": 3, "end_line": 3, "replacement": FIXED, "explanation": "parseInt, not eval"}
        else:
            phase = purpose.split(":", 1)[1]
            r = state["decisions"].get(phase)
            if isinstance(r, list):
                r = r.pop(0) if r else None
            if r is None:
                r = {"thought": f"model thought for {phase}", "tool": phase, "args": {}}
        if isinstance(r, Exception):
            raise r
        try:
            return schema.model_validate(r), {"model": "brev-model"}
        except ValidationError as exc:  # real call_json: retry, then AIError
            raise ai_core.AIError(f"invalid JSON: {exc}")

    monkeypatch.setattr(ai_core, "call_json", fake_call_json)
    monkeypatch.setattr(ai_core, "stats", lambda since_ts="": {
        "calls": len(state["calls"]), "ok": len(state["calls"]), "failed": 0, "median_latency_ms": 42,
        "tokens_in": 10, "tokens_out": 5, "fallback_used": False, "models": ["brev-model"]})

    def fake_verify(check, fix_dir):
        b, a = state["verify"].pop(0) if state["verify"] else (1, 0)
        return {"before": b, "after": a, "broken": False, "error": ""}

    monkeypatch.setattr(ai_fix, "run_semgrep_rule", fake_verify)
    return SimpleNamespace(wd=wd, jobs=jobs, state=state, tmp=tmp_path)


def run_sync():
    run = AgentRun(repo_url=REPO)
    ai_agent._save(run)
    ai_agent.run_agent(run.run_id)
    return ai_agent.get(run.run_id)


def test_full_run_frozen_shape(env):
    before = digest(env.wd)
    env.state["decisions"]["fix"] = [{"thought": "eval is RCE, fix it first", "tool": "fix",
                                      "args": {"finding_id": "eval1"}}]
    d = run_sync()
    assert d["status"] == "done", d["error"]
    assert [s["tool"] for s in d["steps"]] == ["scan", "prefilter", "triage", "fix", "verify", "fix", "story"]
    assert d["steps"][3]["thought"] == "eval is RCE, fix it first"
    assert all(s["status"] == "done" and {"n", "thought", "tool", "result"} <= set(s) for s in d["steps"])
    # prefilter dropped dev-only, fixture, info rows without AI
    assert {x["id"] for x in d["findings"]} == {"eval1", "fp1", "osv1"}
    ev = next(x for x in d["findings"] if x["id"] == "eval1")
    assert ev == {**ev, "file": "app/x.js", "line": 3, "verdict": "real", "confidence": 0.9, "severity": "high"}
    fixes = {x["finding_id"]: x for x in d["fixes"]}
    assert fixes["eval1"]["verified"] is True and "+" + FIXED in fixes["eval1"]["diff"]
    assert fixes["osv1"]["verified"] is None and fixes["osv1"]["diff"] == ""
    assert d["verdict"] == "not_ready" and d["blockers"] and d["attack_story"]
    assert {r["id"]: r["fixed_and_verified"] for r in env.state["story_in"]} == {"eval1": True, "osv1": False}
    assert d["stats"] | {} == {**d["stats"], "model": "brev-model", "median_latency_ms": 42,
                               "fallback_used": False, "calls": d["stats"]["calls"]}
    assert digest(env.wd) == before  # kept clone never written
    # planner: 1 call per backbone step + 1 fix call
    assert env.state["calls"] == ["agent:scan", "agent:prefilter", "agent:triage", "agent:fix", "fix", "agent:story"]


def test_reuse_scan_is_offered_and_honoured(env):
    cached = RepoScanJob(repo_url=REPO + ".git", status=ScanStatus.completed, findings=list(FINDINGS),
                         scanners_run=["gitleaks", "semgrep", "osv"])
    env.jobs[cached.id] = cached
    env.state["decisions"]["scan"] = {"thought": "fresh enough", "tool": "reuse_scan", "args": {"scan_id": cached.id}}
    d = run_sync()
    assert d["steps"][0]["tool"] == "reuse_scan" and d["scan_id"] == cached.id
    assert len(env.jobs) == 1  # no new scan


def test_disallowed_tool_and_unknown_id_fall_back_to_backbone(env):
    env.state["decisions"]["scan"] = {"thought": "x", "tool": "rm_rf", "args": {}}  # not in Literal
    env.state["decisions"]["fix"] = [{"thought": "fix it", "tool": "fix", "args": {"finding_id": "nope"}}]
    d = run_sync()
    assert d["status"] == "done"
    assert d["steps"][0]["tool"] == "scan" and "fixed backbone" in d["steps"][0]["thought"]
    fix_step = d["steps"][3]
    assert fix_step["args"]["finding_id"] == "eval1" and "unknown id" in fix_step["thought"]


def test_failed_verification_retries_with_scanner_feedback(env):
    env.state["verify"] = [(1, 1), (1, 0)]
    d = run_sync()
    tools = [s["tool"] for s in d["steps"]]
    assert tools[:7] == ["scan", "prefilter", "triage", "fix", "verify", "fix", "verify"]
    assert d["steps"][4]["status"] == "error" and "NOT FIXED" in d["steps"][4]["result"]
    assert "Last attempt" in d["steps"][5]["args"]["hint"] and d["steps"][5]["args"]["attempt"] == 2
    assert next(x for x in d["fixes"] if x["finding_id"] == "eval1")["verified"] is True


def test_total_ai_outage_still_finishes(env, monkeypatch):
    monkeypatch.setattr(ai_agent, "_triage_mod", None)
    monkeypatch.setattr(ai_agent, "_story_mod", None)

    def down(messages, schema, **kw):
        raise ai_core.AIError("AI provider unreachable: ConnectError")

    monkeypatch.setattr(ai_core, "call_json", down)
    d = run_sync()
    assert d["status"] == "done"
    assert all("fixed backbone" in s["thought"] for s in d["steps"] if s["tool"] in ("scan", "prefilter", "story"))
    ev = next(x for x in d["fixes"] if x["finding_id"] == "eval1")
    assert ev["verified"] is None and "AI unavailable" in ev["note"]
    assert d["verdict"] == "not_ready"  # rule-based: a real high finding remains


def test_scan_failure_marks_run_failed(env, monkeypatch):
    def broken_scan(scan_id, run_ai=False):
        env.jobs[scan_id].status = ScanStatus.failed
        env.jobs[scan_id].error = "clone failed"

    monkeypatch.setattr(repo_pipeline, "run_repo_scan", broken_scan)
    d = run_sync()
    assert d["status"] == "failed" and "clone failed" in d["error"]
    assert d["finished_at"]


def test_orphaned_run_reported_failed(env):
    run = AgentRun(repo_url=REPO)
    (env.tmp / "agent").mkdir(parents=True, exist_ok=True)
    (env.tmp / "agent" / f"{run.run_id}.json").write_text(run.model_dump_json())
    d = ai_agent.get(run.run_id)
    assert d["status"] == "failed" and "orphaned" in d["error"]


# ------------------------------------------------------------------ API

@pytest.fixture
def client(env, monkeypatch):
    monkeypatch.setattr(main, "API_KEY", "")
    monkeypatch.setattr(settings, "allow_private_targets", True)  # no DNS in tests
    monkeypatch.setattr(main, "_limiter", main.SimpleRateLimiter(max_hits=100, window_s=60))
    started = []

    def fake_start(repo_url, target_url=None):
        run = AgentRun(repo_url=repo_url, target_url=target_url)
        ai_agent._save(run)
        started.append(run)
        return run

    monkeypatch.setattr(ai_agent, "start", fake_start)
    c = TestClient(main.app)
    c.started = started
    return c


def test_api_post_and_get(client):
    r = client.post("/api/agent-scan", json={"repo_url": REPO, "target_url": None})
    assert r.status_code == 200 and set(r.json()) == {"run_id"}
    g = client.get(f"/api/agent-scan/{r.json()['run_id']}")
    assert g.status_code == 200 and g.json()["status"] == "running" and g.json()["repo_url"] == REPO


@pytest.mark.parametrize("url", ["http://github.com/OWASP/NodeGoat", "https://user:pw@github.com/x/y", ""])
def test_api_rejects_bad_repo_urls(client, url):
    assert client.post("/api/agent-scan", json={"repo_url": url}).status_code in (400, 422)
    assert client.started == []


def test_api_target_url_goes_through_ssrf_guard(client, monkeypatch):
    monkeypatch.setattr(settings, "allow_private_targets", False)
    monkeypatch.setattr(main.settings, "allow_private_targets", False)
    r = client.post("/api/agent-scan", json={"repo_url": REPO, "target_url": "http://169.254.169.254/"})
    assert r.status_code == 403 and client.started == []


def test_api_get_unknown_and_invalid_ids(client):
    assert client.get("/api/agent-scan/abcdef0123456789").status_code == 404
    assert client.get("/api/agent-scan/..%2Fetc").status_code in (400, 404)
    assert client.get("/api/agent-scan/not-hex!").status_code == 400


def test_api_caps_concurrent_runs(client, monkeypatch):
    monkeypatch.setattr(ai_agent, "running_count", lambda: ai_agent.MAX_RUNNING)
    assert client.post("/api/agent-scan", json={"repo_url": REPO}).status_code == 429


def test_never_ready_with_unconfirmed_high_findings(env, monkeypatch):
    # AI triage down -> every item "review"; story (wrongly) says ready.
    monkeypatch.setattr(ai_agent, "_triage_mod", SimpleNamespace(triage=lambda b, w: [
        {"finding_id": x.id, "verdict": "review", "confidence": 0.0, "reason": "AI unavailable"} for x in b]))
    monkeypatch.setattr(ai_agent, "_story_mod", SimpleNamespace(
        attack_story=lambda real, target: {"verdict": "ready", "blockers": [], "attack_story": ""}))
    d = run_sync()
    assert d["verdict"] == "not_ready" and "human review" in d["blockers"][-1]


def test_prefilter_keeps_code_findings_when_deps_flood(env):
    many = [f(f"osv{i}", "osv", Severity.critical, rel="package-lock.json", line=None, scope="runtime")
            for i in range(60)]
    env.state["decisions"]["prefilter"] = {"thought": "t", "tool": "prefilter", "args": {"limit": 30}}
    kept = ai_agent._Agent(AgentRun(repo_url=REPO)).do_prefilter(many + FINDINGS)
    assert len(kept) == 30 and {"eval1", "fp1"} <= {x.id for x in kept}
