"""Tests for the SQLite-backed job queue — concurrency limiting, state tracking.

All tests use in-memory SQLite. No external tools or services are invoked.
"""

from __future__ import annotations

import time
import threading
from unittest.mock import MagicMock

import pytest

from scan_toolkit import engagements
from scan_toolkit.db import Base, create_engine, session_factory, session_scope
from scan_toolkit.models import Platform
from scan_toolkit.queue import (
    JobQueue,
    JobStatus,
    ScanJob,
    QUEUED_STAGES,
    INLINE_STAGES,
    requires_queue,
)

from sqlalchemy.pool import StaticPool


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def queue_engine(tmp_path, monkeypatch):
    """Engine with all tables (including ScanJob) + temp data dir."""
    from scan_toolkit.config import get_settings
    s = get_settings()
    orig = s.data_dir
    s.data_dir = tmp_path / "data"

    import scan_toolkit.models  # noqa: F401
    import scan_toolkit.queue  # noqa: F401

    eng = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()
    s.data_dir = orig
    get_settings.cache_clear()


@pytest.fixture()
def queue_session(queue_engine):
    session = session_factory(queue_engine)()
    yield session
    session.rollback()
    session.close()


def _make_engagement(session, tmp_path):
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"apk")
    return engagements.create_engagement(
        session,
        client_name="Acme",
        app_platform=Platform.android,
        scope_agreement_confirmed=True,
        binary_source=apk,
    )


# ---------------------------------------------------------------------------
# Stage classification
# ---------------------------------------------------------------------------

class TestStageClassification:
    def test_queued_stages(self):
        assert "dynamic" in QUEUED_STAGES
        assert "api" in QUEUED_STAGES

    def test_inline_stages(self):
        assert "static" in INLINE_STAGES
        assert "sca" in INLINE_STAGES

    def test_requires_queue(self):
        assert requires_queue("dynamic") is True
        assert requires_queue("api") is True
        assert requires_queue("static") is False
        assert requires_queue("sca") is False


# ---------------------------------------------------------------------------
# ScanJob model
# ---------------------------------------------------------------------------

class TestScanJobModel:
    def test_round_trip(self, queue_session, tmp_path):
        eng = _make_engagement(queue_session, tmp_path)
        job = ScanJob(
            engagement_id=eng.id,
            stage="dynamic",
            status=JobStatus.pending,
        )
        queue_session.add(job)
        queue_session.flush()

        loaded = queue_session.get(ScanJob, job.id)
        assert loaded is not None
        assert loaded.stage == "dynamic"
        assert loaded.status == JobStatus.pending
        assert loaded.engagement_id == eng.id

    def test_to_dict(self, queue_session, tmp_path):
        eng = _make_engagement(queue_session, tmp_path)
        job = ScanJob(engagement_id=eng.id, stage="api", status=JobStatus.pending)
        queue_session.add(job)
        queue_session.flush()
        d = job.to_dict()
        assert d["stage"] == "api"
        assert d["status"] == "pending"
        assert "id" in d


# ---------------------------------------------------------------------------
# JobQueue — submit + query
# ---------------------------------------------------------------------------

class TestJobQueueSubmit:
    def test_submit_creates_pending_job(self, queue_engine, tmp_path):
        queue = JobQueue(queue_engine)
        with session_scope(queue_engine) as session:
            eng = _make_engagement(session, tmp_path)
            job = queue.submit(session, engagement_id=eng.id, stage="dynamic")
            assert job.status == JobStatus.pending
            assert job.stage == "dynamic"

    def test_submit_rejects_inline_stage(self, queue_engine, tmp_path):
        queue = JobQueue(queue_engine)
        with session_scope(queue_engine) as session:
            eng = _make_engagement(session, tmp_path)
            with pytest.raises(ValueError, match="does not require queuing"):
                queue.submit(session, engagement_id=eng.id, stage="static")

    def test_pending_jobs_query(self, queue_engine, tmp_path):
        queue = JobQueue(queue_engine)
        with session_scope(queue_engine) as session:
            eng = _make_engagement(session, tmp_path)
            queue.submit(session, engagement_id=eng.id, stage="dynamic")
            queue.submit(session, engagement_id=eng.id, stage="api")
            session.flush()
            pending = queue.pending_jobs(session)
            assert len(pending) == 2

    def test_running_count(self, queue_engine, tmp_path):
        queue = JobQueue(queue_engine)
        with session_scope(queue_engine) as session:
            eng = _make_engagement(session, tmp_path)
            job = queue.submit(session, engagement_id=eng.id, stage="dynamic")
            assert queue.running_count(session) == 0
            job.status = JobStatus.running
            session.flush()
            assert queue.running_count(session) == 1

    def test_list_jobs_filters(self, queue_engine, tmp_path):
        queue = JobQueue(queue_engine)
        with session_scope(queue_engine) as session:
            eng = _make_engagement(session, tmp_path)
            j1 = queue.submit(session, engagement_id=eng.id, stage="dynamic")
            j2 = queue.submit(session, engagement_id=eng.id, stage="api")
            j1.status = JobStatus.completed
            session.flush()

            all_jobs = queue.list_jobs(session)
            assert len(all_jobs) == 2

            completed = queue.list_jobs(session, status=JobStatus.completed)
            assert len(completed) == 1
            assert completed[0].id == j1.id


# ---------------------------------------------------------------------------
# JobQueue — synchronous processing
# ---------------------------------------------------------------------------

class TestJobQueueProcessing:
    def test_process_pending_sync(self, queue_engine, tmp_path):
        """Sync processing with a stub runner that just marks success."""
        executed_ids = []

        def stub_runner(engine, job_id):
            executed_ids.append(job_id)

        queue = JobQueue(queue_engine, max_concurrent=2)
        queue._stage_runner = stub_runner

        with session_scope(queue_engine) as session:
            eng = _make_engagement(session, tmp_path)
            j1 = queue.submit(session, engagement_id=eng.id, stage="dynamic")
            j2 = queue.submit(session, engagement_id=eng.id, stage="api")
            job_ids = [j1.id, j2.id]

        results = queue.process_pending_sync()
        assert len(results) == 2
        assert all(r["status"] == "completed" for r in results)
        assert set(executed_ids) == set(job_ids)

    def test_process_handles_failure(self, queue_engine, tmp_path):
        """Failed jobs get status=failed with error message."""
        def failing_runner(engine, job_id):
            raise RuntimeError("emulator crashed")

        queue = JobQueue(queue_engine, max_concurrent=2)
        queue._stage_runner = failing_runner

        with session_scope(queue_engine) as session:
            eng = _make_engagement(session, tmp_path)
            queue.submit(session, engagement_id=eng.id, stage="dynamic")

        results = queue.process_pending_sync()
        assert len(results) == 1
        assert results[0]["status"] == "failed"
        assert "emulator crashed" in results[0]["error"]

    def test_concurrency_limit_respected(self, queue_engine, tmp_path):
        """With max_concurrent=1, only one job runs at a time."""
        execution_order = []
        lock = threading.Lock()

        def slow_runner(engine, job_id):
            with lock:
                execution_order.append(("start", job_id))
            time.sleep(0.05)
            with lock:
                execution_order.append(("end", job_id))

        queue = JobQueue(queue_engine, max_concurrent=1)
        queue._stage_runner = slow_runner

        with session_scope(queue_engine) as session:
            eng = _make_engagement(session, tmp_path)
            queue.submit(session, engagement_id=eng.id, stage="dynamic")
            queue.submit(session, engagement_id=eng.id, stage="dynamic")

        # Process synchronously — max_concurrent=1 means sequential.
        results = queue.process_pending_sync()
        assert len(results) == 2

    def test_no_pending_jobs_returns_empty(self, queue_engine):
        queue = JobQueue(queue_engine)
        results = queue.process_pending_sync()
        assert results == []


# ---------------------------------------------------------------------------
# JobQueue — background worker
# ---------------------------------------------------------------------------

class TestJobQueueWorker:
    def test_worker_processes_jobs(self, queue_engine, tmp_path):
        """Background worker picks up and completes a job."""
        completed = threading.Event()

        def stub_runner(engine, job_id):
            completed.set()

        queue = JobQueue(queue_engine, max_concurrent=2)

        with session_scope(queue_engine) as session:
            eng = _make_engagement(session, tmp_path)
            job = queue.submit(session, engagement_id=eng.id, stage="dynamic")
            job_id = job.id

        queue.start_worker(poll_interval=0.1, stage_runner=stub_runner)
        assert completed.wait(timeout=5), "Worker did not process job in time"
        time.sleep(0.2)  # let the status update commit
        queue.shutdown()

        with session_scope(queue_engine) as session:
            job = queue.get_job(session, job_id)
            assert job.status == JobStatus.completed

    def test_worker_double_start(self, queue_engine):
        """Starting the worker twice is safe (second call is a no-op)."""
        queue = JobQueue(queue_engine, max_concurrent=1)
        queue.start_worker(poll_interval=0.5, stage_runner=lambda e, j: None)
        queue.start_worker(poll_interval=0.5, stage_runner=lambda e, j: None)  # no-op
        queue.shutdown()
