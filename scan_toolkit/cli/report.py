"""Report command — Markdown from confirmed findings + PDF/DOCX conversion."""

import typer

from scan_toolkit.db import init_db, session_scope
from scan_toolkit.engagements import get_engagement
from scan_toolkit.reports import SUPPORTED_FORMATS, convert_report


def generate_report(
    engagement: str = typer.Option(..., "--engagement", help="Engagement ID"),
    format: str = typer.Option("md", "--format", help="md, docx, pdf, or all"),
):
    """Produce the client report (Phase 10).

    Only ``confirmed`` findings are included — enforced by the Report Agent
    in code.  ``--format all`` writes .md + .docx + .pdf.
    """
    from scan_toolkit.agents import ReportAgent
    from scan_toolkit.agents.llm_client import LLMError
    from scan_toolkit.audit import audit

    want = [format.lower()] if format.lower() != "all" else ["md", "docx", "pdf"]
    for fmt in want:
        if fmt not in SUPPORTED_FORMATS:
            typer.echo(
                f"[report] unsupported format {format!r} "
                f"(use {', '.join([*SUPPORTED_FORMATS, 'all'])})", err=True)
            raise typer.Exit(1)

    engine = init_db()
    with session_scope(engine) as session:
        try:
            eng = get_engagement(session, engagement)
        except ValueError:
            eng = None
        if eng is None:
            typer.echo(f"[report] engagement {engagement!r} not found", err=True)
            raise typer.Exit(1)

        try:
            md_path, metadata = ReportAgent().run(session, engagement)
        except ValueError as exc:
            typer.echo(f"[report] {exc}", err=True)
            raise typer.Exit(1)
        except LLMError as exc:
            typer.echo(f"[report] LLM error: {exc}", err=True)
            raise typer.Exit(1)
        except RuntimeError as exc:
            typer.echo(f"[report] {exc}", err=True)
            raise typer.Exit(1)

        audit(
            session, "report", engagement_id=engagement,
            details=f"confirmed={metadata['total_findings']} "
                    f"chains={metadata['attack_chains']} file={md_path.name}",
        )

    typer.echo(f"Report written: {md_path}")
    by_sev = ", ".join(f"{k}={v}" for k, v in metadata["by_severity"].items())
    typer.echo(f"  {metadata['total_findings']} confirmed findings ({by_sev}), "
               f"{metadata['attack_chains']} chains")

    for fmt in want:
        if fmt == "md":
            continue
        try:
            out = convert_report(md_path, fmt)
        except (ValueError, RuntimeError) as exc:
            typer.echo(f"[report] conversion failed: {exc}", err=True)
            raise typer.Exit(1)
        typer.echo(f"Converted: {out}")
