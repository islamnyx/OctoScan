import typer


def run_stage(
    engagement: str = typer.Argument(..., help="Engagement ID"),
    stage_name: str = typer.Option("static", "--stage", help="static | sca | dynamic | api"),
):
    """Execute a scan stage (Phase 3+)."""
    typer.echo("[run] not implemented yet — Phase 3+")