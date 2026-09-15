import typer
from sqlalchemy.orm import Session

from scan_toolkit import artifacts, engagements
from scan_toolkit.db import init_db, session_scope
from scan_toolkit.models import EngagementStatus, Platform

app = typer.Typer(help="Engagement intake: create, validate, store artifacts.", no_args_is_help=True)


def _platform(value: str) -> Platform:
    try:
        return Platform(value.strip().lower())
    except ValueError:
        raise typer.BadParameter("platform must be 'android' or 'ios'")


@app.command()
def create(
    client_name: str = typer.Option(..., "--client", prompt="Client name"),
    app_platform: str = typer.Option(
        ..., "--platform", prompt="App platform (android|ios)"
    ),
    confirm_scope: bool = typer.Option(
        False, "--confirm-scope", help="Scope agreement confirmed"
    ),
    binary: str | None = typer.Option(
        None, "--binary", help="Path to the APK/IPA to copy into the engagement"
    ),
    api_docs: str | None = typer.Option(
        None, "--api-docs", help="Path to API docs (file or directory)"
    ),
    credentials: str | None = typer.Option(
        None, "--credentials", help="Path to test credentials file"
    ),
    api_in_scope: bool = typer.Option(
        False, "--api-in-scope", help="API/backend testing is in scope"
    ),
    app_version: str | None = typer.Option(None, "--app-version"),
    build_type: str | None = typer.Option(
        None, "--build-type", help="e.g. release or debug"
    ),
    scope_notes: str | None = typer.Option(None, "--scope-notes"),
    network_constraints: str | None = typer.Option(
        None, "--network-constraints", help="e.g. no external VPS, sandboxed LAN only"
    ),
):
    """Register a new engagement (status 'intake') and store its files."""
    platform = _platform(app_platform)
    try:
        engine = init_db()
    except Exception as exc:  # pragma: no cover - env/dir errors
        typer.echo(f"error initialising database: {exc}", err=True)
        raise typer.Exit(1)

    # capture everything we need to print BEFORE the session commits — relationships
    # like eng.intake would otherwise lazy-load on a detached instance.
    summary: dict | None = None
    missing: list[str] = []
    with session_scope(engine) as session:
        try:
            eng = engagements.create_engagement(
                session,
                client_name=client_name,
                app_platform=platform,
                scope_notes=scope_notes,
                app_version=app_version,
                build_type=build_type,
                scope_agreement_confirmed=confirm_scope,
                binary_source=binary,
                api_docs_source=api_docs,
                credentials_source=credentials,
                network_constraints=network_constraints,
                api_scan_in_scope=api_in_scope,
            )
        except ValueError as exc:
            typer.echo(f"[intake] blocked: {exc}", err=True)
            raise typer.Exit(1)
        missing = engagements.intake_missing_items(eng)
        summary = {
            "id": eng.id,
            "status": eng.status.value,
            "client_name": eng.client_name,
            "platform": eng.app_platform.value,
            "folder": str(artifacts.engagement_dir(eng.id)),
            "binary_path": eng.intake.binary_path,
            "api_docs_path": eng.intake.api_docs_path,
            "has_credentials": eng.intake.has_test_credentials,
            "credentials_filename": eng.intake.credentials_filename,
        }

    typer.echo(f"Created engagement {summary['id']}")
    typer.echo(
        f"Status: {summary['status']}  |  Client: {summary['client_name']}  |  "
        f"Platform: {summary['platform']}"
    )
    typer.echo(f"Artifact folder: {summary['folder']}")
    if summary["binary_path"]:
        typer.echo(f"Binary stored: {summary['binary_path']}")
    if summary["api_docs_path"]:
        typer.echo(f"API docs stored: {summary['api_docs_path']}")
    if summary["has_credentials"]:
        typer.echo(f"Test credentials stored: {summary['credentials_filename']}")

    if missing:
        typer.echo("")
        typer.echo("WARNING — intake incomplete; engagement cannot leave 'intake' yet:")
        for item in missing:
            typer.echo(f"  - {item}")
        typer.echo(f"Run: scan-toolkit intake validate {summary['id']}")
    else:
        typer.echo("")
        typer.echo("Intake complete. Run: scan-toolkit intake validate <id> to move to 'scanning'.")


@app.command()
def validate(engagement: str = typer.Argument(..., help="Engagement ID")):
    """Check intake completeness; if complete, advance the engagement to 'scanning'."""
    engine = init_db()
    with session_scope(engine) as session:
        eng = engagements.get_engagement(session, engagement)
        if eng is None:
            typer.echo(f"[intake] engagement {engagement!r} not found", err=True)
            raise typer.Exit(1)
        if eng.status is not EngagementStatus.intake:
            typer.echo(f"Engagement {engagement} is already at '{eng.status.value}' — nothing to validate.")
            raise typer.Exit(0)
        missing = engagements.intake_missing_items(eng)
        if missing:
            typer.echo(f"[intake] blocked — engagement {engagement} can't leave 'intake'. Missing:")
            for item in missing:
                typer.echo(f"  - {item}")
            raise typer.Exit(1)
        engagements.advance_engagement_status(session, eng, EngagementStatus.scanning)
    typer.echo(f"Engagement {engagement} validated and advanced to 'scanning'.")