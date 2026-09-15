"""CLI subcommands — wired onto the main Typer app via register().

intake/run/status/report are FLAT commands (scan-toolkit run --engagement X),
matching the CLI contract in the spec. Each cli module exposes a callback that
later phases flesh out.
"""

import typer

from scan_toolkit.cli import intake, report, run, status


def register(parent: typer.Typer) -> None:
    """Register all subcommand callbacks on the root Typer app."""
    parent.command(name="intake")(intake.create_engagement)
    parent.command(name="run")(run.run_stage)
    parent.command(name="status")(status.show_status)
    parent.command(name="report")(report.generate_report)