"""SQLite-backed job queue with concurrency limiting.

Why SQLite instead of Celery+Redis:
  * Zero external dependencies — the toolkit already uses SQLite.
  * A small security team on one machine (16-32 GB RAM) doesn't need
    distributed task routing.
  * Jobs are durable (survive process restarts) via the DB.
  * Concurrency limiting is a simple count query + semaphore.
  * Can swap to Celery+Redis later if multi-machine deployment is needed —
    the JobQueue interface stays the same.

Architecture:
  * ``ScanJob`` ORM model stores job state in the same toolkit.db.
  * ``JobQueue`` manages submission, polling, and execution.
  * Static/SCA stages bypass the queue (run inline).
  * Dynamic/API stages MUST go through the queue.
  * A background worker thread pool processes queued jobs up to
    MAX_CONCURRENT_DYNAMIC_JOBS at a time.
"""

from __future__ import annotations

import enum
import logging
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, Future
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, Session, mapped_column
from sqlalchemy.sql import func

from scan_toolkit.config import get_settings
from scan_toolkit.db import Base, create_engine, session_factory, session_scope

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Job status enum
# ---------------------------------------------------------------------------

class JobStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


# ---------------------------------------------------------------------------
# ORM model
# ---------------------------------------------------------------------------

def _new_job_id() -> str:
    return uuid4().hex[:12]


class ScanJob(Base):
    """A queued scan job — durable state for the concurrency-limited queue."""

    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(sa.String(12), primary_key=True, default=_new_job_id)
    engagement_id: Mapped[str] = mapped_column(sa.ForeignKey("engagements.id"), index=True)
    stage: Mapped[str] = mapped_column(nullable=False)  # "dynamic" or "api"
    status: Mapped[str] = mapped_column(
        sa.Enum(JobStatus, values_callable=lambda e: [m.value for m in e],
                native_enum=False, name="JobStatus"),
        default=JobStatus.pending,
    )
    analyze: Mapped[bool] = mapped_column(default=False)
    error: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    result_summary: Mapped[str | None] = mapped_column(sa.Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), default=lambda: datetime.now(timezone.utc)
    )
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "engagement_id": self.engagement_id,
            "stage": self.stage,
            "status": self.status.value if isinstance(self.status, JobStatus) else self.status,
            "analyze": self.analyze,
            "error": self.error,
            "result_summary": self.result_summary,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


# ---------------------------------------------------------------------------
# Stages that MUST go through the queue
# ---------------------------------------------------------------------------

QUEUED_STAGES = frozenset({"dynamic", "api"})
INLINE_STAGES = frozenset({"static", "sca"})


def requires_queue(stage: str) -> bool:
    """True if this stage must go through the concurrency-limited queue."""
    return stage in QUEUED_STAGES


# ---------------------------------------------------------------------------
# Job Queue
# ---------------------------------------------------------------------------

class JobQueue:
    """SQLite-backed job queue with a thread-pool executor.

    Usage::

        queue = JobQueue(engine)
        job = queue.submit(session, engagement_id="abc", stage="dynamic")
        queue.start_worker()   # begins processing pending jobs
        # ... later ...
        queue.shutdown()

    The worker polls the DB for pending jobs and runs them up to
    ``max_concurrent`` at a time.
    """

    def __init__(self, engine: sa.engine.Engine, *, max_concurrent: int | None = None):
        self._engine = engine
        self._max = max_concurrent or get_settings().max_concurrent_dynamic_jobs
        self._executor: ThreadPoolExecutor | None = None
        self._stop_event = threading.Event()
        self._poll_thread: threading.Thread | None = None
        self._futures: dict[str, Future] = {}
        # injectable stage runner for testing
        self._stage_runner: Callable | None = None

    # -- submission -------------------------------------------------------

    def submit(
        self,
        session: Session,
        *,
        engagement_id: str,
        stage: str,
        analyze: bool = False,
    ) -> ScanJob:
        """Enqueue a new job. Returns the ScanJob (status=pending)."""
        if stage not in QUEUED_STAGES:
            raise ValueError(
                f"Stage '{stage}' does not require queuing. "
                f"Run it inline (queued stages: {sorted(QUEUED_STAGES)})."
            )
        job = ScanJob(
            engagement_id=engagement_id,
            stage=stage,
            status=JobStatus.pending,
            analyze=analyze,
        )
        session.add(job)
        session.flush()
        log.info("Enqueued job %s: engagement=%s stage=%s", job.id, engagement_id, stage)
        return job

    # -- query ------------------------------------------------------------

    @staticmethod
    def get_job(session: Session, job_id: str) -> ScanJob | None:
        return session.get(ScanJob, job_id)

    @staticmethod
    def pending_jobs(session: Session) -> list[ScanJob]:
        return list(
            session.query(ScanJob)
            .filter(ScanJob.status == JobStatus.pending)
            .order_by(ScanJob.created_at)
            .all()
        )

    @staticmethod
    def running_count(session: Session) -> int:
        return session.query(ScanJob).filter(ScanJob.status == JobStatus.running).count()

    @staticmethod
    def list_jobs(
        session: Session,
        *,
        engagement_id: str | None = None,
        status: JobStatus | None = None,
    ) -> list[ScanJob]:
        q = session.query(ScanJob)
        if engagement_id:
            q = q.filter(ScanJob.engagement_id == engagement_id)
        if status:
            q = q.filter(ScanJob.status == status)
        return list(q.order_by(ScanJob.created_at.desc()).all())

    # -- worker -----------------------------------------------------------

    def start_worker(
        self,
        *,
        poll_interval: float = 2.0,
        stage_runner: Callable | None = None,
    ) -> None:
        """Start the background worker thread that processes queued jobs.

        Parameters
        ----------
        poll_interval : float
            Seconds between DB polls for new pending jobs.
        stage_runner : callable, optional
            ``stage_runner(engine, job)`` — injected for tests. If not
            provided, uses the real ``_execute_job`` which calls
            ``stages.run_stage``.
        """
        if self._poll_thread and self._poll_thread.is_alive():
            log.warning("Worker already running")
            return

        self._stage_runner = stage_runner
        self._stop_event.clear()
        self._executor = ThreadPoolExecutor(max_workers=self._max)
        self._poll_thread = threading.Thread(
            target=self._poll_loop,
            args=(poll_interval,),
            daemon=True,
            name="job-queue-worker",
        )
        self._poll_thread.start()
        log.info("Job queue worker started (max_concurrent=%d)", self._max)

    def shutdown(self, wait: bool = True) -> None:
        """Stop the worker and wait for running jobs to finish."""
        self._stop_event.set()
        if self._poll_thread:
            self._poll_thread.join(timeout=10)
        if self._executor:
            self._executor.shutdown(wait=wait)
        log.info("Job queue worker stopped")

    def _poll_loop(self, interval: float) -> None:
        """Continuously poll for pending jobs and dispatch them."""
        while not self._stop_event.is_set():
            try:
                self._dispatch_pending()
            except Exception:
                log.exception("Error in job queue poll loop")
            self._stop_event.wait(timeout=interval)

    def _dispatch_pending(self) -> None:
        """Check for pending jobs and submit them to the thread pool."""
        with session_scope(self._engine) as session:
            running = self.running_count(session)
            available_slots = self._max - running
            if available_slots <= 0:
                return

            pending = self.pending_jobs(session)
            to_dispatch = pending[:available_slots]

            for job in to_dispatch:
                job.status = JobStatus.running
                job.started_at = datetime.now(timezone.utc)
                session.add(job)
                # Capture values before session closes.
                job_id = job.id
                job_data = job.to_dict()

            # Commit the status updates.
            session.flush()

        # Submit to thread pool AFTER committing status.
        for job_data_item in [j.to_dict() for j in to_dispatch] if to_dispatch else []:
            jid = job_data_item["id"]
            future = self._executor.submit(self._run_job, jid)
            self._futures[jid] = future

    def _run_job(self, job_id: str) -> None:
        """Execute a single job (runs in a thread pool thread)."""
        try:
            if self._stage_runner:
                self._stage_runner(self._engine, job_id)
            else:
                _execute_job(self._engine, job_id)

            with session_scope(self._engine) as session:
                job = self.get_job(session, job_id)
                if job:
                    job.status = JobStatus.completed
                    job.completed_at = datetime.now(timezone.utc)
                    log.info("Job %s completed", job_id)

        except Exception as exc:
            log.exception("Job %s failed: %s", job_id, exc)
            try:
                with session_scope(self._engine) as session:
                    job = self.get_job(session, job_id)
                    if job:
                        job.status = JobStatus.failed
                        job.completed_at = datetime.now(timezone.utc)
                        job.error = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-500:]}"
            except Exception:
                log.exception("Failed to update job %s status to failed", job_id)

        finally:
            self._futures.pop(job_id, None)

    # -- process all (synchronous, for CLI) --------------------------------

    def process_pending_sync(self) -> list[dict]:
        """Process all pending jobs synchronously (blocking). For CLI use.

        Returns a list of job result dicts.
        """
        results = []
        while True:
            with session_scope(self._engine) as session:
                running = self.running_count(session)
                if running >= self._max:
                    break  # at capacity
                pending = self.pending_jobs(session)
                if not pending:
                    break
                job = pending[0]
                job.status = JobStatus.running
                job.started_at = datetime.now(timezone.utc)
                job_id = job.id
                session.flush()

            try:
                if self._stage_runner:
                    self._stage_runner(self._engine, job_id)
                else:
                    _execute_job(self._engine, job_id)

                with session_scope(self._engine) as session:
                    job = self.get_job(session, job_id)
                    if job:
                        job.status = JobStatus.completed
                        job.completed_at = datetime.now(timezone.utc)
                        results.append(job.to_dict())

            except Exception as exc:
                with session_scope(self._engine) as session:
                    job = self.get_job(session, job_id)
                    if job:
                        job.status = JobStatus.failed
                        job.completed_at = datetime.now(timezone.utc)
                        job.error = str(exc)
                        results.append(job.to_dict())

        return results


# ---------------------------------------------------------------------------
# Default job executor (calls stages.run_stage)
# ---------------------------------------------------------------------------

def _execute_job(engine: sa.engine.Engine, job_id: str) -> None:
    """Run the stage for a job. Called from the worker thread."""
    from scan_toolkit.stages import run_stage

    with session_scope(engine) as session:
        job = session.get(ScanJob, job_id)
        if not job:
            raise ValueError(f"Job {job_id} not found")

        result = run_stage(session, job.engagement_id, job.stage)
        job.result_summary = result.summary_line()

        # LLM agent pass (Phase 7+: api; Phase 8: dynamic).
        # Agent failures propagate -> the job is marked failed (fail loudly,
        # never silently drop the analysis the analyst asked for).
        if job.analyze and job.stage in ("api", "dynamic"):
            if job.stage == "api":
                from scan_toolkit.agents import APIBackendAgent

                agent = APIBackendAgent()
                label = "API"
            else:
                from scan_toolkit.agents import DynamicAnalysisAgent

                agent = DynamicAnalysisAgent()
                label = "Dynamic"
            findings = agent.run(session, job.engagement_id, result.ir_path)
            job.result_summary += f"\n{label} agent: {len(findings)} findings"
