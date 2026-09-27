"""CLI subcommands — wired onto the main Typer app via register().

intake/run/status/report are FLAT commands (scan-toolkit run --engagement X),
matching the CLI contract in the spec. Each cli module exposes a callback that
later phases flesh out.
"""

import typer

from scan_toolkit.cli import correlate, intake, report, review, run, status, worker


def register(parent: typer.Typer) -> None:
    """Register all subcommands on the root Typer app.

    intake is a group (create + validate); run/status/report/worker/queue/
    correlate/review stay flat commands per the CLI contract in the spec.
    """
    parent.add_typer(intake.app, name="intake")
    parent.command(name="run")(run.run_scan)
    parent.command(name="status")(status.show_status)
    parent.command(name="report")(report.generate_report)
    parent.command(name="worker")(worker.run_worker)
    parent.command(name="queue")(worker.show_queue)
    parent.command(name="correlate")(correlate.correlate_findings)
    parent.command(name="review")(review.review_findings)
