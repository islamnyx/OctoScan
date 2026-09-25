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
from scan_toolkit.engagements import get_engagement
from scan_toolkit.intermediate import IRToolOutput, StageIR
from scan_toolkit.tools import ApktoolRunner, JadxRunner, MobsfRunner, SemgrepRunner, ToolRunner


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
    raise ValueError(f"stage {stage!r} not implemented yet (sca dynamic api land in Phases 5/7/8)")


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