import typer

from scan_toolkit.models import Platform


def create_engagement(
    client_name: str | None = typer.Option(None, "--client", help="Client name"),
    app_platform: Platform | None = typer.Option(None, "--platform", help="android | ios"),
    scope_notes: str | None = typer.Option(None, "--scope", help="Scope notes"),
):
    """Register a new engagement (Phase 2)."""
    typer.echo("[intake] not implemented yet — Phase 2")