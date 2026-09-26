"""Tests for run_static orchestration -- injectable stub tool runners.

Nothing external is invoked: tools are stubbed, data dir is tmp, DB in-memory.
"""

from pathlib import Path

import pytest

from scan_toolkit import engagements
from scan_toolkit.db import Base, create_engine, session_factory
from scan_toolkit.intermediate import IRFinding, IRToolOutput
from scan_toolkit.models import Platform
from scan_toolkit.stages import run_static


@pytest.fixture()
def env(tmp_path, monkeypatch):
    from scan_toolkit.config import get_settings
    s = get_settings()
    orig = s.data_dir
    s.data_dir = tmp_path / "data"
    yield tmp_path
    s.data_dir = orig
    get_settings.cache_clear()


class StubRunner:
    def __init__(self, output: IRToolOutput, sources_dir: Path | None = None):
        self.output = output
        self._sources_dir = sources_dir
        self.last_target = None

    def sources_dir(self) -> Path:
        return self._sources_dir or Path("/nonexistent")

    def run(self, **ctx):
        self.last_target = ctx.get("target_dir")
        return self.output


def _stubs(sources_dir, findings=None):
    findings = findings or []
    apktool = StubRunner(IRToolOutput(tool="apktool", version="2.9.0",
                                      raw_path="/tmp/apktool/decoded"))
    jadx = StubRunner(IRToolOutput(tool="jadx", version="1.4.0",
                                   raw_path=str(sources_dir)),
                      sources_dir=sources_dir)
    semgrep = StubRunner(IRToolOutput(tool="semgrep", findings=findings))
    mobsf = StubRunner(IRToolOutput(tool="mobsf", findings=[]))
    return apktool, jadx, semgrep, mobsf


def _complete_engagement(db_session, tmp_path):
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"apk")
    return engagements.create_engagement(
        db_session,
        client_name="Acme",
        app_platform=Platform.android,
        scope_agreement_confirmed=True,
        binary_source=apk,
    )


def test_run_static_aggregates_and_writes_results(db_session, env, tmp_path):
    jadx_root = env / "jadx-out"
    sources = jadx_root / "sources"
    sources.mkdir(parents=True)
    (sources / "Main.java").write_text("class Main {}")

    finding = IRFinding(tool="semgrep", rule_id="android-hardcoded-secret-token",
                        severity="warning", cwe_id="CWE-798", file="Main.java")
    apktool, jadx, semgrep, mobsf = _stubs(jadx_root, findings=[finding])
    eng = _complete_engagement(db_session, tmp_path)

    result = run_static(db_session, eng, apktool=apktool, jadx=jadx,
                        semgrep=semgrep, mobsf=mobsf)

    assert result.status == "completed"
    assert result.errors == []
    assert sum(len(t.findings) for t in result.tools) == 1
    assert semgrep.last_target == sources  # semgrep pointed at jadx sources
    assert (result.ir_path).exists()
    assert (result.artifacts_dir / "stage_result.json").exists()


def test_run_static_skips_semgrep_when_no_jadx_sources(db_session, env, tmp_path):
    apktool, jadx, semgrep, mobsf = _stubs(env / "missing")
    eng = _complete_engagement(db_session, tmp_path)

    result = run_static(db_session, eng, apktool=apktool, jadx=jadx,
                        semgrep=semgrep, mobsf=mobsf)

    assert not result.errors  # jadx successful; no sources, so semgrep noted & skipped
    assert any("jadx produced no sources" in n for n in result.notes)
    assert semgrep.last_target is None


def test_run_static_partial_when_tools_error(db_session, env, tmp_path):
    from scan_toolkit.intermediate import IRToolOutput
    errors = IRToolOutput(tool="mobsf", errors=["mobsf request failed: boom"])
    apktool, jadx, semgrep, mobsf = _stubs(env / "missing")
    mobsf.output = mobsf.output.model_copy(
        update={"errors": ["mobsf request failed: boom"]}
    )
    eng = _complete_engagement(db_session, tmp_path)

    result = run_static(db_session, eng, apktool=apktool, jadx=jadx,
                        semgrep=semgrep, mobsf=mobsf)

    assert result.status == "partial"
    assert any("mobsf" in e for e in result.errors)


def test_run_static_requires_binary(db_session, env, tmp_path):
    eng = engagements.create_engagement(
        db_session, client_name="Acme", app_platform=Platform.android,
    )
    db_session.flush()
    with pytest.raises(ValueError, match="no stored, readable binary"):
        run_static(db_session, eng)


def test_semgrep_runner_degrades_cleanly(tmp_path, monkeypatch):
    """With semgrep absent, the real runner reports an error, never raises."""
    from scan_toolkit.config import get_settings
    from scan_toolkit.tools import SemgrepRunner

    # Hermetic: force-absent binary (the test env may HAVE semgrep installed).
    monkeypatch.setattr(get_settings(), "semgrep_bin", "/nonexistent/semgrep")
    runner = SemgrepRunner(tmp_path)
    out = runner.run(target_dir=tmp_path)
    assert not runner.available()
    assert out.errors and "not available" in out.errors[0]
    assert out.findings == []
