"""scan-toolkit CLI entrypoint."""

import typer

from scan_toolkit.cli import register

app = typer.Typer(
    name="scan-toolkit",
    help="Mobile app security assessment toolkit.",
    no_args_is_help=True,
)


@app.callback()
def _configure() -> None:
    """Configure logging before every command (idempotent, Phase 11)."""
    from scan_toolkit.config import get_settings
    from scan_toolkit.logging_config import configure_logging

    configure_logging(get_settings().data_dir)


register(app)

if __name__ == "__main__":
    app()