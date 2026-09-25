"""Audit trail — who ran what, when (Phase 11).

Every mutating CLI command records an AuditEvent row in the same session as
its primary write, so the audit entry commits or rolls back atomically with
the action it describes.  The actor is the OS login name — correct for a
local-first single-user-per-machine toolkit.
"""

from __future__ import annotations

import getpass
import logging

from sqlalchemy.orm import Session

from scan_toolkit.models import AuditEvent

log = logging.getLogger(__name__)


def current_actor() -> str:
    """OS login name, ``unknown`` when it cannot be determined."""
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 — exotic environments (containers w/o passwd)
        return "unknown"


def audit(
    session: Session,
    action: str,
    *,
    engagement_id: str | None = None,
    details: str | None = None,
) -> AuditEvent:
    """Append an audit row (flushed; the caller owns commit/rollback).

    ``details`` must be a short secret-free summary — never credentials,
    tokens, or finding evidence.  Truncated defensively at 500 chars.
    """
    event = AuditEvent(
        actor=current_actor(),
        action=action,
        engagement_id=engagement_id,
        details=(details or "")[:500] or None,
    )
    session.add(event)
    session.flush()
    log.info("audit action=%s actor=%s engagement=%s %s",
             action, event.actor, engagement_id, event.details or "")
    return event


def recent(
    session: Session,
    *,
    engagement_id: str | None = None,
    limit: int = 20,
) -> list[AuditEvent]:
    """Newest-first audit rows, optionally scoped to one engagement."""
    query = session.query(AuditEvent).order_by(AuditEvent.created_at.desc())
    if engagement_id:
        query = query.filter(AuditEvent.engagement_id == engagement_id)
    return list(query.limit(limit).all())
