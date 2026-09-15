"""Engagement lifecycle service — creation with intake, intake validation,
and status transitions.

An Engagement is created in status ``intake`` with whatever is provided (partial
intake allowed). Moving OUT of intake is gated: ``intake_missing_items()`` lists
what's still required, and ``advance_engagement_status()`` refuses non-forward
moves and refuses intake -> scanning while items are missing (clear error, never
silent).
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from sqlalchemy.orm import Session

from scan_toolkit import artifacts
from scan_toolkit.models import (
    Engagement,
    EngagementStatus,
    IntakeChecklist,
    Platform,
)

# linear status machine
_STATUS_ORDER = [
    EngagementStatus.intake,
    EngagementStatus.scanning,
    EngagementStatus.reviewing,
    EngagementStatus.delivered,
]


def get_engagement(session: Session, engagement_id: str) -> Engagement | None:
    artifacts.validate_engagement_id(engagement_id)
    return session.get(Engagement, engagement_id)


def _text(v) -> str:
    return str(v or "").strip()


def intake_missing_items(engagement: Engagement) -> list[str]:
    """Required-but-missing items, as human messages. Empty list = ready to scan."""
    missing: list[str] = []
    if not _text(engagement.client_name):
        missing.append("client_name is required")
    if engagement.app_platform is None:
        missing.append("app_platform (android/ios) is required")
    checklist: IntakeChecklist | None = engagement.intake
    if checklist is None:
        missing.append("intake checklist not recorded")
        return missing
    if not checklist.scope_agreement_confirmed:
        missing.append("scope agreement not confirmed")
    bin_path = checklist.binary_path
    if not bin_path or not Path(bin_path).exists():
        missing.append("app binary not stored (missing or unreadable)")
    if checklist.api_scan_in_scope and not checklist.has_test_credentials:
        missing.append(
            "API/backend testing is in scope but no test credentials are stored"
        )
    return missing


def create_engagement(
    session: Session,
    *,
    client_name: str,
    app_platform: Platform,
    scope_notes: str | None = None,
    app_version: str | None = None,
    build_type: str | None = None,
    scope_agreement_confirmed: bool = False,
    binary_source: str | Path | None = None,
    api_docs_source: str | Path | None = None,
    credentials_source: str | Path | None = None,
    network_constraints: str | None = None,
    api_scan_in_scope: bool = False,
) -> Engagement:
    """Create an Engagement (status ``intake``) and its IntakeChecklist.

    Inputs are validated fail-closed (a malformed binary path raises instead of
    silently proceeding). Still creates the record when some checklist items are
    absent — the gate lives on the intake -> scanning transition.
    """
    if not _text(client_name):
        raise ValueError("client_name is required")
    for label, src in (("binary", binary_source), ("api-docs", api_docs_source),
                       ("credentials", credentials_source)):
        if src:
            p = Path(src)
            if not p.exists():
                raise ValueError(f"{label} path does not exist: {src}")
            if label in ("binary", "credentials") and not p.is_file():
                raise ValueError(f"{label} path is not a file: {src}")

    eng = Engagement(
        client_name=_text(client_name),
        scope_notes=_text(scope_notes) or None,
        app_platform=app_platform,
        app_version=_text(app_version) or None,
        build_type=_text(build_type) or None,
        start_date=date.today(),
        status=EngagementStatus.intake,
    )
    session.add(eng)
    session.flush()
    eid = eng.id

    binary_path = binary_filename = None
    if binary_source:
        binary_path, binary_filename = artifacts.store_binary(eid, Path(binary_source).resolve())
    docs_path = None
    if api_docs_source:
        docs_path = artifacts.store_docs(eid, Path(api_docs_source).resolve())
    creds_path = creds_name = None
    if credentials_source:
        creds_path, creds_name = artifacts.store_credentials(eid, Path(credentials_source).resolve())

    checklist = IntakeChecklist(
        engagement_id=eid,
        scope_agreement_confirmed=scope_agreement_confirmed,
        binary_path=str(binary_path) if binary_path else None,
        binary_filename=binary_filename,
        api_docs_path=str(docs_path) if docs_path else None,
        has_test_credentials=creds_path is not None,
        credentials_filename=creds_name,
        network_constraints=_text(network_constraints) or None,
        api_scan_in_scope=api_scan_in_scope,
    )
    session.add(checklist)
    session.flush()

    artifacts.write_manifest(eid, {"engagement": eng.to_dict(), "intake": checklist.to_dict()})
    return eng


def advance_engagement_status(
    session: Session, engagement: Engagement, target: EngagementStatus
) -> None:
    """Move an engagement forward in the status machine.

    Guardrails:
      * backward moves raise (fail-closed).
      * intake -> scanning requires a complete intake checklist; otherwise raises
        ValueError listing exactly what's missing.
    """
    if target not in _STATUS_ORDER or engagement.status not in _STATUS_ORDER:
        raise ValueError(f"unknown status: {target}")
    cur, tgt = _STATUS_ORDER.index(engagement.status), _STATUS_ORDER.index(target)
    if tgt < cur:
        raise ValueError(
            f"cannot move engagement backward from {engagement.status.value} to {target.value}"
        )
    if tgt == cur:
        return
    if target is EngagementStatus.scanning:
        missing = intake_missing_items(engagement)
        if missing:
            raise ValueError(
                "Engagement not ready to leave intake:\n  - " + "\n  - ".join(missing)
            )
    engagement.status = target
    session.add(engagement)