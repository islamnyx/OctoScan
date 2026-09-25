"""Stage orchestration — one entry per scan stage (static/sca/dynamic/api).

Phases add stages here: SCA (Phase 5), API (Phase 7), dynamic (Phase 8). The
static stage runs the deterministic decompilers/scanners even when some tools
are missing — the stage degrades to a clean per-tool error instead of dying,
so partial results are always stored.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy.orm import Session

from scan_toolkit import artifacts
from scan_toolkit.api_traffic import (
    access_matrix,
    compare_roles,
    load_role_captures,
)
from scan_toolkit.engagements import get_engagement, load_test_accounts
from scan_toolkit.intermediate import IRToolOutput, StageIR
from scan_toolkit.tools import (
    ApktoolRunner, GrypeRunner, JadxRunner, MitmRunner, MobsfRunner,
    OsvRunner, SemgrepRunner, ToolRunner, ZAPRunner,
)
from scan_toolkit.tools.deps import Dependency, extract_dependencies


@dataclass
class StageResult:
    status: str  # completed | partial | failed
    engagement_id: str
    stage: str
    artifacts_dir: Path
    ir_path: Path
    tools: list[IRToolOutput] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def summary_line(self) -> str:
        total = sum(len(t.findings) for t in self.tools)
        by_tool = ", ".join(f"{t.tool}={len(t.findings)}" for t in self.tools) or "no findings"
        return (
            f"[{self.stage}] status={self.status} findings={total} ({by_tool})\n"
            + f"  IR: {self.ir_path}"
        )


def _stage_dir(engagement_id: str, stage: str) -> Path:
    return artifacts.engagement_dir(engagement_id) / "stages" / stage


def run_stage(session: Session, engagement_id: str, stage: str) -> StageResult:
    engagement = get_engagement(session, engagement_id)
    if engagement is None:
        raise ValueError(f"engagement {engagement_id!r} not found")
    if stage == "static":
        return run_static(session, engagement)
    if stage == "sca":
        return run_sca(session, engagement)
    if stage == "api":
        return run_api(session, engagement)
    raise ValueError(f"stage {stage!r} not implemented yet (dynamic lands in Phase 8)")


def run_static(
    session: Session,
    engagement,
    *,
    apktool: ToolRunner | None = None,
    jadx: ToolRunner | None = None,
    semgrep: ToolRunner | None = None,
    mobsf: ToolRunner | None = None,
) -> StageResult:
    """Run the static analysis stage for an engagement. Tool params are injectable for tests."""
    checklist = engagement.intake
    if checklist is None or not checklist.binary_path or not Path(checklist.binary_path).exists():
        raise ValueError(f"engagement {engagement.id} has no stored, readable binary (run intake first)")

    stage_dir = _stage_dir(engagement.id, "static")
    stage_dir.mkdir(parents=True, exist_ok=True)
    workdir = stage_dir / "tools"
    apk = Path(checklist.binary_path)

    apktool_runner = apktool or ApktoolRunner(workdir)
    jadx_runner = jadx or JadxRunner(workdir)
    semgrep_runner = semgrep or SemgrepRunner(workdir)
    mobsf_runner = mobsf or MobsfRunner(workdir)

    tool_outputs: list[IRToolOutput] = []
    errors: list[str] = []
    notes: list[str] = []

    def _collect(output: IRToolOutput) -> None:
        tool_outputs.append(output)
        errors.extend(f"{output.tool}: {e}" for e in output.errors)

    # 1. decompile (decode resources/smali) — feeds later pass
    _collect(apktool_runner.run(apk=apk))

    # 2. decompile to Java source
    jadx_out = jadx_runner.run(apk=apk)
    _collect(jadx_out)

    # 3. semgrep over decompiled Java (needs jadx's sources)
    sources = jadx_runner.sources_dir() / "sources"
    if jadx_out.errors or not sources.exists():
        notes.append("jadx produced no sources — semgrep skipped")
    else:
        _collect(semgrep_runner.run(target_dir=sources))

    # 4. mobile secure framework report
    _collect(mobsf_runner.run(apk=apk))

    status = "completed" if not errors else ("partial" if tool_outputs else "failed")
    ir = StageIR(
        engagement_id=engagement.id,
        stage="static",
        input={
            "binary": checklist.binary_filename,
            "binary_path": checklist.binary_path,
            "platform": engagement.app_platform.value if engagement.app_platform else None,
            "app_version": engagement.app_version,
        },
        tools=tool_outputs,
        notes=notes,
    )
    ir_path = stage_dir / "static_ir.json"
    ir_path.write_text(ir.model_dump_json(indent=2))

    # human-readable stage summary for `status`/`report` later
    summary_path = stage_dir / "stage_result.json"
    summary_path.write_text(
        json.dumps(
            {
                "status": status,
                "engagement_id": engagement.id,
                "stage": "static",
                "errors": errors,
                "notes": notes,
                "ran_at": ir.ran_at,
                "tools": [t.model_dump(mode="json") for t in tool_outputs],
            },
            indent=2,
        )
    )
    return StageResult(
        status=status,
        engagement_id=engagement.id,
        stage="static",
        artifacts_dir=stage_dir,
        ir_path=ir_path,
        tools=tool_outputs,
        errors=errors,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# SCA stage
# ---------------------------------------------------------------------------

def run_sca(
    session: Session,
    engagement,
    *,
    osv: OsvRunner | None = None,
    grype: GrypeRunner | None = None,
    deps_override: list[Dependency] | None = None,
) -> StageResult:
    """Run the SCA (software composition analysis) stage.

    1. Extract dependencies from the decompiled APK (or use deps_override for tests).
    2. Query OSV.dev for known vulnerabilities.
    3. Optionally run Grype as a fallback/supplement.
    4. Store combined IR.

    Tool params are injectable for tests.
    """
    checklist = engagement.intake
    if checklist is None or not checklist.binary_path or not Path(checklist.binary_path).exists():
        raise ValueError(f"engagement {engagement.id} has no stored, readable binary (run intake first)")

    stage_dir = _stage_dir(engagement.id, "sca")
    stage_dir.mkdir(parents=True, exist_ok=True)
    workdir = stage_dir / "tools"

    tool_outputs: list[IRToolOutput] = []
    errors: list[str] = []
    notes: list[str] = []

    def _collect(output: IRToolOutput) -> None:
        tool_outputs.append(output)
        errors.extend(f"{output.tool}: {e}" for e in output.errors)

    # 1. Extract dependencies from decompiled sources.
    # Look for apktool/jadx output from static stage.
    static_stage_dir = _stage_dir(engagement.id, "static")
    deps = deps_override
    if deps is None:
        deps = _extract_deps_from_static(static_stage_dir)
    if not deps:
        notes.append("no dependencies extracted — SCA tools will have limited input")

    # Write extracted deps for traceability.
    deps_path = stage_dir / "extracted_deps.json"
    deps_path.write_text(json.dumps([d.to_dict() for d in deps], indent=2))

    # 2. OSV.dev query.
    osv_runner = osv or OsvRunner(workdir)
    if deps:
        _collect(osv_runner.run(dependencies=deps))
    else:
        notes.append("OSV skipped — no dependencies to query")

    # 3. Grype (optional — runs if available).
    grype_runner = grype or GrypeRunner(workdir)
    if grype_runner.available():
        # Point Grype at the decompiled APK directory from static stage.
        apktool_decoded = static_stage_dir / "tools" / "apktool" / "decoded"
        if apktool_decoded.exists():
            _collect(grype_runner.run(target_dir=apktool_decoded))
        else:
            notes.append("Grype available but no apktool decoded dir found — skipped")
    else:
        notes.append("Grype not available — OSV.dev results only")

    status = "completed" if not errors else ("partial" if tool_outputs else "failed")
    ir = StageIR(
        engagement_id=engagement.id,
        stage="sca",
        input={
            "binary": checklist.binary_filename,
            "platform": engagement.app_platform.value if engagement.app_platform else None,
            "dependency_count": len(deps),
        },
        tools=tool_outputs,
        notes=notes,
    )
    ir_path = stage_dir / "sca_ir.json"
    ir_path.write_text(ir.model_dump_json(indent=2))

    summary_path = stage_dir / "stage_result.json"
    summary_path.write_text(
        json.dumps(
            {
                "status": status,
                "engagement_id": engagement.id,
                "stage": "sca",
                "errors": errors,
                "notes": notes,
                "ran_at": ir.ran_at,
                "dependency_count": len(deps),
                "tools": [t.model_dump(mode="json") for t in tool_outputs],
            },
            indent=2,
        )
    )
    return StageResult(
        status=status,
        engagement_id=engagement.id,
        stage="sca",
        artifacts_dir=stage_dir,
        ir_path=ir_path,
        tools=tool_outputs,
        errors=errors,
        notes=notes,
    )


def _extract_deps_from_static(static_stage_dir: Path) -> list[Dependency]:
    """Try to extract dependencies from previous static stage output."""
    deps: list[Dependency] = []

    # jadx decompiled sources (most likely to have build.gradle / pom.xml)
    jadx_sources = static_stage_dir / "tools" / "jadx" / "sources"
    if jadx_sources.exists():
        deps.extend(extract_dependencies(jadx_sources))

    # apktool decoded (has META-INF, AndroidManifest, etc.)
    apktool_decoded = static_stage_dir / "tools" / "apktool" / "decoded"
    if apktool_decoded.exists():
        for d in extract_dependencies(apktool_decoded):
            key = f"{d.name}:{d.version}"
            if not any(f"{e.name}:{e.version}" == key for e in deps):
                deps.append(d)

    return deps


# ---------------------------------------------------------------------------
# API/backend stage (Phase 7)
# ---------------------------------------------------------------------------

_API_TARGET_FILE = "api_target.txt"


def _resolve_api_target(engagement, explicit: str | None) -> str:
    """Target base URL: explicit arg wins, else api_target.txt in the folder.

    Raises ValueError with instructions when neither exists — a backend scan
    without a confirmed target could hit the wrong system, so this is
    fail-closed, never a silent default.
    """
    if explicit and explicit.strip():
        return explicit.strip()
    candidate = artifacts.engagement_dir(engagement.id) / _API_TARGET_FILE
    if candidate.exists():
        target = candidate.read_text().strip().splitlines()[0].strip()
        if target:
            return target
    raise ValueError(
        f"engagement {engagement.id} has no API target: pass target_url or "
        f"write the base URL (e.g. https://api.client.internal) to "
        f"{candidate} (first line is used)"
    )


def run_api(
    session: Session,
    engagement,
    *,
    mitm: MitmRunner | None = None,
    zap: ZAPRunner | None = None,
    target_url: str | None = None,
    flows_dir: Path | None = None,
) -> StageResult:
    """Run the API/backend stage for an engagement.

    1. Resolve the backend target (explicit URL or api_target.txt).
    2. Load test accounts from intake credentials (roles only are logged).
    3. Parse per-role HAR captures from the flows dir + passive checks.
    4. Multi-role access diff -> candidate auth findings.
    5. ZAP spider + active scan against the target (if ZAP is up).

    Tool params are injectable for tests.  Missing captures or a missing
    ZAP daemon degrade to notes/errors — the stage always stores IR.
    """
    checklist = engagement.intake
    if checklist is None or not checklist.binary_path or not Path(checklist.binary_path).exists():
        raise ValueError(f"engagement {engagement.id} has no stored, readable binary (run intake first)")

    target = _resolve_api_target(engagement, target_url)

    stage_dir = _stage_dir(engagement.id, "api")
    stage_dir.mkdir(parents=True, exist_ok=True)
    workdir = stage_dir / "tools"

    tool_outputs: list[IRToolOutput] = []
    errors: list[str] = []
    notes: list[str] = []

    def _collect(output: IRToolOutput) -> None:
        tool_outputs.append(output)
        errors.extend(f"{output.tool}: {e}" for e in output.errors)

    # 1. Test accounts (roles only — secrets never logged).
    try:
        accounts = load_test_accounts(engagement)
    except ValueError as exc:
        raise ValueError(f"cannot run API stage: {exc}") from exc
    roles = [a.role for a in accounts]
    if roles:
        notes.append(f"test accounts loaded for roles: {', '.join(roles)}")
    else:
        notes.append("no test credentials stored — role comparison limited to provided captures")

    # 2. Per-role HAR captures.
    flows = flows_dir or (artifacts.engagement_dir(engagement.id) / "flows")
    mitm_runner = mitm or MitmRunner(workdir)
    try:
        captures = load_role_captures(flows)
    except ValueError as exc:
        captures = {}
        errors.append(f"mitmproxy: {exc}")
    if not captures:
        notes.append(
            f"no .har captures in {flows} — capture per-role traffic with "
            "mitmdump --savehar (one file per role, e.g. user.har, admin.har, "
            "anonymous.har) and re-run"
        )
        # Still record an (empty) mitmproxy output so the IR shows the step ran.
        _collect(IRToolOutput(tool="mitmproxy", errors=[f"no .har captures in {flows}"]))
    else:
        _collect(mitm_runner.run_all(flows))
        notes.append(f"captured roles: {', '.join(sorted(captures))} "
                     f"({sum(len(c) for c in captures.values())} calls)")

    # 3. Multi-role diff (deterministic triage candidates).
    if captures:
        diff_findings = compare_roles(captures)
        matrix = access_matrix(captures)
        matrix_path = stage_dir / "access_matrix.json"
        matrix_path.write_text(json.dumps(matrix, indent=2))
        notes.append(f"access matrix written to {matrix_path.name} "
                     f"({len(matrix)} endpoints)")
    else:
        diff_findings = []
        matrix = {}
        notes.append("role comparison skipped — no captures")
    tool_outputs.append(IRToolOutput(tool="role_diff", findings=diff_findings))

    # 4. Passive checks already ran inside MitmRunner; surface a summary.
    # (Findings live in the mitmproxy IRToolOutput above.)

    # 5. ZAP baseline scan (unauthenticated — see tools/zap.py scope note).
    zap_runner = zap or ZAPRunner(workdir)
    if zap_runner.available():
        notes.append(f"ZAP active scan against {target} (unauthenticated baseline)")
        _collect(zap_runner.run(target))
    else:
        notes.append(
            "ZAP daemon not reachable at "
            f"{zap_runner._settings.zap_base_url} — start it with "
            "`zap.sh -daemon -port 8090` to include active-scan coverage"
        )

    # mitmdump presence hint for the analyst.
    from scan_toolkit.config import get_settings as _get_settings
    import shutil as _shutil
    if _shutil.which(_get_settings().mitmdump_bin) is None:
        notes.append("mitmdump not on PATH — HAR files must be captured elsewhere and copied in")

    status = "completed" if not errors else ("partial" if tool_outputs else "failed")
    ir = StageIR(
        engagement_id=engagement.id,
        stage="api",
        input={
            "binary": checklist.binary_filename,
            "platform": engagement.app_platform.value if engagement.app_platform else None,
            "target": target,
            "roles": roles,
            "call_counts": {r: len(c) for r, c in captures.items()},
            "access_matrix": matrix,
        },
        tools=tool_outputs,
        notes=notes,
    )
    ir_path = stage_dir / "api_ir.json"
    ir_path.write_text(ir.model_dump_json(indent=2))

    summary_path = stage_dir / "stage_result.json"
    summary_path.write_text(
        json.dumps(
            {
                "status": status,
                "engagement_id": engagement.id,
                "stage": "api",
                "target": target,
                "errors": errors,
                "notes": notes,
                "ran_at": ir.ran_at,
                "tools": [t.model_dump(mode="json") for t in tool_outputs],
            },
            indent=2,
        )
    )
    return StageResult(
        status=status,
        engagement_id=engagement.id,
        stage="api",
        artifacts_dir=stage_dir,
        ir_path=ir_path,
        tools=tool_outputs,
        errors=errors,
        notes=notes,
    )