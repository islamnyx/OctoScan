import typer

from scan_toolkit.db import init_db, session_scope
from scan_toolkit.stages import run_stage


def run_scan(
    engagement: str = typer.Option(..., "--engagement", help="Engagement ID"),
    stage_name: str = typer.Option("static", "--stage", help="static | sca (Phase 5+)"),
):
    """Run a scan stage (static now; sca/dynamic/api later) and store raw results."""
    engine = init_db()
    with session_scope(engine) as session:
        try:
            result = run_stage(session, engagement, stage_name)
        except ValueError as exc:
            typer.echo(f"[run] {exc}", err=True)
            raise typer.Exit(1)

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