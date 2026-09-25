"""Review command — the human gate between scanning and reporting.

Findings land as ``new``; only ``confirmed`` findings reach the client
report (enforced by the Report Agent in code).  This command lists
findings and transitions their status::

    scan-toolkit review --engagement <id>                  # list findings
    scan-toolkit review --engagement <id> --confirm <f1> --confirm <f2>
    scan-toolkit review --engagement <id> --false-positive <f3>
    scan-toolkit review --engagement <id> --needs-review <f4>

IDs must belong to the engagement — unknown IDs fail loudly, nothing is
partially applied on error.
"""

import typer

from scan_toolkit.db import init_db, session_scope
from scan_toolkit.engagements import get_engagement
from scan_toolkit.models import Finding, FindingStatus


def review_findings(
    engagement: str = typer.Option(..., "--engagement", help="Engagement ID"),
    confirm: list[str] = typer.Option(None, "--confirm", help="Finding ID(s) to confirm"),
    false_positive: list[str] = typer.Option(
        None, "--false-positive", help="Finding ID(s) to dismiss"),
    needs_review: list[str] = typer.Option(
        None, "--needs-review", help="Finding ID(s) to flag for review"),
):
    engine = init_db()
    with session_scope(engine) as session:
        try:
            eng = get_engagement(session, engagement)
        except ValueError:
            eng = None
        if eng is None:
            typer.echo(f"[review] engagement {engagement!r} not found", err=True)
            raise typer.Exit(1)

        transitions = [
            (confirm or [], FindingStatus.confirmed),
            (false_positive or [], FindingStatus.false_positive),
            (needs_review or [], FindingStatus.needs_review),
        ]
        if any(ids for ids, _ in transitions):
            _apply(session, engagement, transitions)

        findings = (
            session.query(Finding)
            .filter(Finding.engagement_id == engagement)
            .order_by(Finding.created_at)
            .all()
        )
        if not findings:
            typer.echo("No findings for this engagement yet.")
            return
        for f in findings:
            typer.echo(
                f"  {f.id}  [{f.severity.value.upper():<8}] "
                f"{f.status.value:<14} ({f.source_agent.value}) {f.title[:70]}"
            )


def _apply(session, engagement_id: str, transitions: list) -> None:
    """Validate ALL ids first, then apply — never partially."""
    rows = {f.id: f for f in session.query(Finding).filter(
        Finding.engagement_id == engagement_id).all()}
    unknown = sorted({fid for ids, _ in transitions for fid in ids} - set(rows))
    if unknown:
        raise _fail(f"unknown finding id(s) for this engagement: {', '.join(unknown)}")
    seen: dict[str, FindingStatus] = {}
    for ids, status in transitions:
        for fid in ids:
            if fid in seen and seen[fid] is not status:
                raise _fail(f"finding {fid} given conflicting statuses")
            seen[fid] = status
    for fid, status in seen.items():
        rows[fid].status = status
        session.add(rows[fid])
    typer.echo(f"Updated {len(seen)} finding(s).")


def _fail(message: str) -> typer.Exit:
    typer.echo(f"[review] {message}", err=True)
    return typer.Exit(1)
