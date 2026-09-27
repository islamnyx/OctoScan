"""Worker command — processes the job queue for resource-heavy stages."""

import typer

from scan_toolkit.db import init_db, session_scope
from scan_toolkit.queue import JobQueue, JobStatus


def run_worker(
    once: bool = typer.Option(
        False, "--once", help="Process pending jobs once and exit (no polling)"
    ),
    poll_interval: float = typer.Option(
        2.0, "--poll-interval", help="Seconds between queue polls (ignored with --once)"
    ),
):
    """Start the job queue worker to process dynamic/API scan stages.

    Without --once, the worker polls continuously until interrupted (Ctrl+C).
    With --once, it processes all currently pending jobs and exits.
    """
    engine = init_db()
    queue = JobQueue(engine)

    if once:
        typer.echo("Processing pending jobs (one pass)...")
        with session_scope(engine) as session:
            pending = queue.pending_jobs(session)
            count = len(pending)
        if count == 0:
            typer.echo("No pending jobs.")
            return
        typer.echo(f"Found {count} pending job(s).")
        results = queue.process_pending_sync()
        for r in results:
            status = r.get("status", "unknown")
            typer.echo(f"  Job {r['id']}: {status}")
            if r.get("error"):
                typer.echo(f"    Error: {r['error'][:200]}")
        typer.echo(f"Processed {len(results)} job(s).")
        return

    # Continuous polling mode.
    typer.echo(
        f"Starting job queue worker (max_concurrent={queue._max}, "
        f"poll_interval={poll_interval}s). Ctrl+C to stop."
    )
    queue.start_worker(poll_interval=poll_interval)
    try:
        import signal
        signal.pause()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        typer.echo("\nShutting down worker...")
        queue.shutdown()
        typer.echo("Worker stopped.")


def show_queue(
    engagement: str = typer.Option(None, "--engagement", help="Filter by engagement ID"),
):
    """Show current job queue state."""
    engine = init_db()
    queue = JobQueue(engine)
    with session_scope(engine) as session:
        jobs = queue.list_jobs(session, engagement_id=engagement)
        if not jobs:
            typer.echo("No jobs in queue.")
            return
        for job in jobs:
            d = job.to_dict()
            status = d["status"].upper()
            typer.echo(
                f"  {d['id']}  {status:<10}  stage={d['stage']:<8}  "
                f"engagement={d['engagement_id']}  created={d['created_at']}"
            )
            if d.get("error"):
                typer.echo(f"    error: {d['error'][:150]}")
