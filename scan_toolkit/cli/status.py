"""Status command — engagement overview or per-engagement detail (Phase 11)."""

import json
from collections import Counter

import typer

from scan_toolkit import artifacts
from scan_toolkit.audit import recent as recent_audit
from scan_toolkit.db import init_db, session_scope
from scan_toolkit.engagements import get_engagement, intake_missing_items
from scan_toolkit.models import AttackChain, Finding
from scan_toolkit.queue import JobQueue, JobStatus, ScanJob


def show_status(
    engagement: str | None = typer.Option(
        None, "--engagement", help="Engagement ID (omit for all-engagements overview)"),
    audit_limit: int = typer.Option(
        10, "--audit-limit", help="Audit events shown in detail view"),
):
    """Display engagement state, stage results, findings, and queue."""
    engine = init_db()
    with session_scope(engine) as session:
        if engagement:
            _detail(session, engagement, audit_limit)
        else:
            _overview(session)


def _overview(session) -> None:
    from scan_toolkit.models import Engagement

    engagements = session.query(Engagement).order_by(
        Engagement.created_at).all()
    if not engagements:
        typer.echo("No engagements yet.")
    for eng in engagements:
        n_findings = session.query(Finding).filter(
            Finding.engagement_id == eng.id).count()
        n_chains = session.query(AttackChain).filter(
            AttackChain.engagement_id == eng.id).count()
        typer.echo(
            f"  {eng.id}  {eng.status.value:<10}  "
            f"{(eng.client_name or '?')[:20]:<20}  "
            f"{eng.app_platform.value if eng.app_platform else '?':<8}  "
            f"findings={n_findings} chains={n_chains}"
        )

    counts = Counter(
        status for (status,) in session.query(ScanJob.status).all())
    typer.echo("")
    typer.echo("Queue: " + ", ".join(
        f"{s.value}={counts.get(s, 0)}" for s in JobStatus))


def _detail(session, engagement_id: str, audit_limit: int) -> None:
    try:
        eng = get_engagement(session, engagement_id)
    except ValueError:
        eng = None
    if eng is None:
        typer.echo(f"[status] engagement {engagement_id!r} not found", err=True)
        raise typer.Exit(1)

    typer.echo(f"Engagement {eng.id} — {eng.client_name} "
               f"({eng.app_platform.value if eng.app_platform else '?'}, "
               f"{eng.app_version or '?'})")
    typer.echo(f"Status: {eng.status.value}")
    missing = intake_missing_items(eng)
    if missing:
        typer.echo("Intake incomplete:")
        for item in missing:
            typer.echo(f"  - {item}")
    else:
        typer.echo("Intake: complete")

    findings = session.query(Finding).filter(
        Finding.engagement_id == eng.id).all()
    if findings:
        typer.echo(f"Findings: {len(findings)}  "
                   f"by status: {_counts(f.status.value for f in findings)}  "
                   f"by severity: {_counts(f.severity.value for f in findings)}  "
                   f"by agent: {_counts(f.source_agent.value for f in findings)}")
    else:
        typer.echo("Findings: none")

    chains = session.query(AttackChain).filter(
        AttackChain.engagement_id == eng.id).all()
    typer.echo(f"Attack chains: {len(chains)}")
    for chain in chains:
        typer.echo(f"  [{chain.combined_severity.value.upper()}] "
                   f"{', '.join(chain.finding_ids)}")

    typer.echo("Stages:")
    for stage, summary in _stage_results(eng.id):
        typer.echo(f"  {stage:<8} {summary}")

    jobs = JobQueue.list_jobs(session, engagement_id=eng.id)
    typer.echo(f"Jobs: {len(jobs)}")
    for job in jobs[:10]:
        d = job.to_dict()
        typer.echo(f"  {d['id']}  {d['status']:<10}  stage={d['stage']}")

    events = recent_audit(session, engagement_id=eng.id, limit=audit_limit)
    typer.echo(f"Recent activity ({len(events)}):")
    for event in events:
        d = event.to_dict()
        typer.echo(f"  {d['created_at'][:19]}  {d['actor']:<12}  "
                   f"{d['action']:<16}  {d['details'] or ''}")


def _counts(values) -> str:
    return ", ".join(f"{k}={v}"
                     for k, v in sorted(Counter(values).items()))


def _stage_results(engagement_id: str) -> list[tuple[str, str]]:
    """Read stored stage_result.json files (defensive — never crashes)."""
    results = []
    try:
        stages_dir = artifacts.engagement_dir(engagement_id) / "stages"
    except ValueError:
        return [("(none)", "no stages run yet")]
    if not stages_dir.exists():
        return [("(none)", "no stages run yet")]
    for result_file in sorted(stages_dir.glob("*/stage_result.json")):
        stage = result_file.parent.name
        try:
            data = json.loads(result_file.read_text())
        except (json.JSONDecodeError, OSError):
            results.append((stage, "unreadable result file"))
            continue
        n_findings = sum(len(t.get("findings", []))
                         for t in data.get("tools", []))
        n_errors = len(data.get("errors", []))
        results.append(
            (stage, f"{data.get('status', '?')}  "
                    f"findings={n_findings} errors={n_errors}"))
    if not results:
        results.append(("(none)", "no stages run yet"))
    return results
