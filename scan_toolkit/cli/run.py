import typer

from scan_toolkit.audit import audit
from scan_toolkit.db import init_db, session_scope
from scan_toolkit.queue import requires_queue
from scan_toolkit.stages import run_stage


def run_scan(
    engagement: str = typer.Option(..., "--engagement", help="Engagement ID"),
    stage_name: str = typer.Option("static", "--stage", help="static | sca | dynamic | api"),
    analyze: bool = typer.Option(
        False, "--analyze", help="Run LLM agent after tools to produce Finding rows"
    ),
):
    """Run a scan stage and store raw results.

    Static/SCA stages run inline. Dynamic/API stages are enqueued and
    processed through the concurrency-limited job queue.
    """
    engine = init_db()

    if requires_queue(stage_name):
        _enqueue_job(engine, engagement, stage_name, analyze)
        return

    # Inline execution (static / sca).
    with session_scope(engine) as session:
        try:
            result = run_stage(session, engagement, stage_name)
        except ValueError as exc:
            typer.echo(f"[run] {exc}", err=True)
            raise typer.Exit(1)
        audit(
            session, "run.stage", engagement_id=engagement,
            details=f"stage={stage_name} status={result.status} "
                    f"findings={sum(len(t.findings) for t in result.tools)}",
        )

    typer.echo(result.summary_line())
    if result.errors:
        typer.echo("Errors (per-tool, stage continued):")
        for err in result.errors:
            typer.echo(f"  - {err}")
    if result.notes:
        typer.echo("Notes:")
        for note in result.notes:
            typer.echo(f"  - {note}")
    typer.echo(f"Raw results stored under: {result.artifacts_dir}")

    # --- LLM agent (Phase 4+) ---
    if analyze and stage_name == "static":
        _run_static_agent(engine, engagement, result.ir_path)
    elif analyze and stage_name == "sca":
        _run_sca_agent(engine, engagement, result.ir_path)
    elif analyze:
        typer.echo(f"[analyze] LLM agent for stage '{stage_name}' not implemented yet.")


def _enqueue_job(engine, engagement_id: str, stage_name: str, analyze: bool):
    """Enqueue a resource-heavy stage into the job queue."""
    from scan_toolkit.queue import JobQueue

    queue = JobQueue(engine)
    with session_scope(engine) as session:
        try:
            job = queue.submit(
                session, engagement_id=engagement_id, stage=stage_name, analyze=analyze,
            )
        except ValueError as exc:
            typer.echo(f"[run] {exc}", err=True)
            raise typer.Exit(1)
        audit(
            session, "run.enqueue", engagement_id=engagement_id,
            details=f"stage={stage_name} job={job.id} analyze={analyze}",
        )

    typer.echo(
        f"Enqueued job {job.id} for engagement {engagement_id} stage '{stage_name}'.\n"
        f"Run 'scan-toolkit worker' to process the queue, or 'scan-toolkit status' to check."
    )


def _run_static_agent(engine, engagement_id: str, ir_path):
    """Run the Static Analysis Agent on the IR output."""
    from scan_toolkit.agents.llm_client import LLMError

    typer.echo("\nRunning Static Analysis Agent...")
    try:
        from scan_toolkit.agents import StaticAnalysisAgent

        agent = StaticAnalysisAgent()
        with session_scope(engine) as session:
            findings = agent.run(session, engagement_id, ir_path)
        typer.echo(f"Static Analysis Agent produced {len(findings)} findings.")
        for f in findings:
            typer.echo(f"  [{f.severity.value.upper()}] {f.title}")
    except LLMError as exc:
        typer.echo(f"[analyze] LLM error: {exc}", err=True)
        raise typer.Exit(1)
    except RuntimeError as exc:
        typer.echo(f"[analyze] {exc}", err=True)
        raise typer.Exit(1)


def _run_sca_agent(engine, engagement_id: str, ir_path):
    """Run the SCA Agent on the IR output."""
    from scan_toolkit.agents.llm_client import LLMError

    typer.echo("\nRunning SCA Agent...")
    try:
        from scan_toolkit.agents import SCAAgent

        agent = SCAAgent()
        with session_scope(engine) as session:
            findings = agent.run(session, engagement_id, ir_path)
        typer.echo(f"SCA Agent produced {len(findings)} findings.")
        for f in findings:
            typer.echo(f"  [{f.severity.value.upper()}] {f.title}")
    except LLMError as exc:
        typer.echo(f"[analyze] LLM error: {exc}", err=True)
        raise typer.Exit(1)
    except RuntimeError as exc:
        typer.echo(f"[analyze] {exc}", err=True)
        raise typer.Exit(1)
