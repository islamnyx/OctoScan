"""CLI subcommands — wired onto the main Typer app via register().

intake/run/status/report are FLAT commands (scan-toolkit run --engagement X),
matching the CLI contract in the spec. Each cli module exposes a callback that
later phases flesh out.
"""

import typer

from scan_toolkit.cli import intake, report, run, status


def register(parent: typer.Typer) -> None:
    """Register all subcommands on the root Typer app.

    intake is a group (create + validate); run/status/report stay flat commands
    per the CLI contract in the spec (e.g. ``scan-toolkit run --stage static``).
    """
    parent.add_typer(intake.app, name="intake")
    parent.command(name="run")(run.run_stage)
    parent.command(name="status")(status.show_status)
    parent.command(name="report")(report.generate_report)