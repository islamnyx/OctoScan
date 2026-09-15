"""scan-toolkit CLI entrypoint."""

import typer

from scan_toolkit.cli import register

app = typer.Typer(
    name="scan-toolkit",
    help="Mobile app security assessment toolkit.",
    no_args_is_help=True,
)

register(app)

if __name__ == "__main__":
    app()