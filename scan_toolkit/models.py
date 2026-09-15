"""ORM models — Engagement, Finding, AttackChain.

The JSON schemas in the user's spec define the public interchange contract;
``to_dict()`` returns *exactly* those keys (enums → .value, dates isoformatted,
timestamps excluded).  The LLM normalizer in Phases 4–10 consumes this shape.
"""

from __future__ import annotations

import enum
from datetime import date, datetime, timezone
from uuid import uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from scan_toolkit.db import Base


# ---------------------------------------------------------------------------
# Enums (distinct names so they never collide with app.models.Severity etc.)
# ---------------------------------------------------------------------------

class SourceAgent(str, enum.Enum):
    static = "static"
    dynamic = "dynamic"
    sca = "sca"
    api = "api"


class Severity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Confidence(str, enum.Enum):
    high = "high"
    medium = "medium"
    low = "low"


class FindingStatus(str, enum.Enum):
    new = "new"
    confirmed = "confirmed"
    false_positive = "false_positive"
    duplicate = "duplicate"
    needs_review = "needs_review"


class Platform(str, enum.Enum):
    android = "android"
    ios = "ios"


class EngagementStatus(str, enum.Enum):
    intake = "intake"
    scanning = "scanning"
    reviewing = "reviewing"
    delivered = "delivered"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _new_id() -> str:
    return uuid4().hex[:12]


# reusable enum column factory — VARCHAR+CHECK on both SQLite and Postgres
def _enum_col(enum_cls: type[enum.Enum], *, nullable: bool = False, default=None) -> mapped_column:
    col_type = sa.Enum(
        enum_cls,
        values_callable=lambda e: [m.value for m in e],
        native_enum=False,
        name=enum_cls.__name__,
    )
    return mapped_column(col_type, nullable=nullable, default=default)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class Engagement(Base):
    __tablename__ = "engagements"

    id: Mapped[str] = mapped_column(sa.String(12), primary_key=True, default=_new_id)
    client_name: Mapped[str | None] = mapped_column(nullable=True)
    scope_notes: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    app_platform: Mapped[Platform | None] = _enum_col(Platform, nullable=True)
    app_version: Mapped[str | None] = mapped_column(nullable=True)
    build_type: Mapped[str | None] = mapped_column(nullable=True)
    start_date: Mapped[date | None] = mapped_column(nullable=True)
    status: Mapped[EngagementStatus] = _enum_col(EngagementStatus, default=EngagementStatus.intake)

    created_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        onupdate=func.now(), nullable=True
    )

    findings: Mapped[list[Finding]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    attack_chains: Mapped[list[AttackChain]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    intake: Mapped["IntakeChecklist | None"] = relationship(
        back_populates="engagement", uselist=False, cascade="all, delete-orphan"
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "client_name": self.client_name,
            "scope_notes": self.scope_notes,
            "app_platform": self.app_platform.value if self.app_platform else None,
            "app_version": self.app_version,
            "build_type": self.build_type,
            "start_date": self.start_date.isoformat() if self.start_date else None,
            "status": self.status.value,
        }


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(sa.String(12), primary_key=True, default=_new_id)
    engagement_id: Mapped[str] = mapped_column(sa.ForeignKey("engagements.id"), index=True)
    source_agent: Mapped[SourceAgent] = _enum_col(SourceAgent)
    category: Mapped[str | None] = mapped_column(nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(nullable=True)
    title: Mapped[str] = mapped_column(nullable=False)
    description: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    evidence: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    severity: Mapped[Severity] = _enum_col(Severity)
    confidence: Mapped[Confidence] = _enum_col(Confidence)
    affected_component: Mapped[str | None] = mapped_column(nullable=True)
    remediation_suggestion: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    status: Mapped[FindingStatus] = _enum_col(FindingStatus, default=FindingStatus.new)
    # soft references — no FK; can cross rows and engagements
    related_finding_ids: Mapped[list] = mapped_column(sa.JSON, default=list)

    created_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        onupdate=func.now(), nullable=True
    )

    engagement: Mapped[Engagement] = relationship(back_populates="findings")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "engagement_id": self.engagement_id,
            "source_agent": self.source_agent.value,
            "category": self.category,
            "cwe_id": self.cwe_id,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "affected_component": self.affected_component,
            "remediation_suggestion": self.remediation_suggestion,
            "status": self.status.value,
            "related_finding_ids": self.related_finding_ids or [],
        }


class AttackChain(Base):
    __tablename__ = "attack_chains"

    id: Mapped[str] = mapped_column(sa.String(12), primary_key=True, default=_new_id)
    engagement_id: Mapped[str] = mapped_column(sa.ForeignKey("engagements.id"), index=True)
    finding_ids: Mapped[list] = mapped_column(sa.JSON, default=list)
    narrative: Mapped[str] = mapped_column(sa.Text, nullable=False)
    combined_severity: Mapped[Severity] = _enum_col(Severity)

    created_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        onupdate=func.now(), nullable=True
    )

    engagement: Mapped[Engagement] = relationship(back_populates="attack_chains")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "engagement_id": self.engagement_id,
            "finding_ids": self.finding_ids or [],
            "narrative": self.narrative,
            "combined_severity": self.combined_severity.value,
        }


class IntakeChecklist(Base):
    """Intake checklist item — captured at engagement intake (Phase 2).

    Separate from Engagement so the core schema stays pristine. The checklist
    records *where* artifacts were stored (copied into the per-engagement folder
    for reproducibility) plus the flags the intake gate needs: scope agreement,
    and whether test credentials exist when API scanning is in scope.
    """

    __tablename__ = "intake_checklists"

    id: Mapped[str] = mapped_column(sa.String(12), primary_key=True, default=_new_id)
    engagement_id: Mapped[str] = mapped_column(
        sa.ForeignKey("engagements.id"), unique=True, index=True
    )
    scope_agreement_confirmed: Mapped[bool] = mapped_column(default=False)
    # stored (absolute) paths inside the engagement's artifact folder
    binary_path: Mapped[str | None] = mapped_column(nullable=True)
    binary_filename: Mapped[str | None] = mapped_column(nullable=True)
    api_docs_path: Mapped[str | None] = mapped_column(nullable=True)
    has_test_credentials: Mapped[bool] = mapped_column(default=False)
    credentials_filename: Mapped[str | None] = mapped_column(nullable=True)
    network_constraints: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    api_scan_in_scope: Mapped[bool] = mapped_column(default=False)

    created_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        onupdate=func.now(), nullable=True
    )

    engagement: Mapped[Engagement] = relationship(back_populates="intake")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "engagement_id": self.engagement_id,
            "scope_agreement_confirmed": self.scope_agreement_confirmed,
            "binary_path": self.binary_path,
            "binary_filename": self.binary_filename,
            "api_docs_path": self.api_docs_path,
            "has_test_credentials": self.has_test_credentials,
            "credentials_filename": self.credentials_filename,
            "network_constraints": self.network_constraints,
            "api_scan_in_scope": self.api_scan_in_scope,
        }