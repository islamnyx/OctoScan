"""Correlate command — dedup + attack chains across all agents' findings."""

import typer

from scan_toolkit.db import init_db, session_scope
from scan_toolkit.engagements import get_engagement


def correlate_findings(
    engagement: str = typer.Option(..., "--engagement", help="Engagement ID"),
):
    """Deduplicate findings and build attack chains (Phase 9).

    Runs the Correlation Agent once all stages report done: queued jobs
    settled and at least one Finding stored. Writes AttackChain rows,
    marks duplicates, and updates related_finding_ids.
    """
    from scan_toolkit.agents import CorrelationAgent
    from scan_toolkit.agents.correlation import stages_done
    from scan_toolkit.agents.llm_client import LLMError
    from scan_toolkit.audit import audit

    engine = init_db()
    with session_scope(engine) as session:
        try:
            eng = get_engagement(session, engagement)
        except ValueError:
            eng = None
        if eng is None:
            typer.echo(f"[correlate] engagement {engagement!r} not found", err=True)
            raise typer.Exit(1)

        ok, reason = stages_done(session, engagement)
        if not ok:
            typer.echo(f"[correlate] not ready: {reason}", err=True)
            raise typer.Exit(1)
        typer.echo(f"Correlating engagement {engagement} ({reason})...")

        try:
            summary = CorrelationAgent().run(session, engagement)
        except ValueError as exc:
            typer.echo(f"[correlate] {exc}", err=True)
            raise typer.Exit(1)
        except LLMError as exc:
            typer.echo(f"[correlate] LLM error: {exc}", err=True)
            raise typer.Exit(1)
        except RuntimeError as exc:
            typer.echo(f"[correlate] {exc}", err=True)
            raise typer.Exit(1)

        audit(
            session, "correlate", engagement_id=engagement,
            details=f"chains={len(summary['chains'])} "
                    f"duplicates={summary['duplicates_marked']} "
                    f"related={summary['related_updated']}",
        )

    typer.echo(f"Attack chains: {len(summary['chains'])}")
    for chain in summary["chains"]:
        typer.echo(
            f"  [{chain['combined_severity'].upper()}] "
            f"{', '.join(chain['finding_ids'])}"
        )
    typer.echo(f"Duplicates marked: {summary['duplicates_marked']}")
    typer.echo(f"Related links updated: {summary['related_updated']}")
