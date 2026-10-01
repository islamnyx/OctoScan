"""Strict pause/finish controls (Oct 2026): the worker must stop within
seconds of the button press, even mid-scanner — not at the next
between-scanners checkpoint (ZAP alone runs ~15 min as one step).
"""

from __future__ import annotations

import pytest

from app.models import ScanJob, ScanStatus
from app.scanners.base import BaseScanner, ScanStopped


class _Stopper(BaseScanner):
    name = "stopper"

    def run(self):
        self._check_stop("test")
        return []


def test_check_stop_silent_without_hook(tmp_path):
    s = _Stopper("http://127.0.0.1:9/", tmp_path)
    s._check_stop("test")  # must not raise


def test_check_stop_raises_with_reason():
    s = _Stopper.__new__(_Stopper)
    s.stop_check = lambda: "finish"
    with pytest.raises(ScanStopped) as ei:
        s._check_stop("test")
    assert ei.value.reason == "finish"


def test_zap_wait_scan_stops_without_io(tmp_path):
    """stop_check fires at the top of the poll loop — client=None proves
    no HTTP request is needed to honor the stop."""
    from app.scanners.zap_scanner import ZapScanner

    z = ZapScanner("http://127.0.0.1:9/", tmp_path)
    z.stop_check = lambda: "pause"
    with pytest.raises(ScanStopped) as ei:
        z._wait_scan(None, "http://unused/", "key", "1", timeout_s=60)
    assert ei.value.reason == "pause"


class _FakeZap(BaseScanner):
    """Raises its stop flag mid-run so the test exercises the
    mid-scanner ScanStopped path (not the between-checkpoints path)."""
    name = "zap"
    flag: str = "finish"

    def run(self):
        from app import control

        if self.flag == "finish":
            control.request_finish(self.workdir.name, "scan")
        else:
            control.request_pause(self.workdir.name, "scan")
        self._check_stop("fake-zap")
        return []


def _run_with_flag(tmp_path, monkeypatch, flag: str):
    import app.pipeline as pipe
    from app.config import settings
    from app.store import save_job

    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    monkeypatch.setattr(pipe, "SEQUENTIAL_ORDER", [_FakeZap])
    monkeypatch.setattr(pipe, "SCANNERS", [_FakeZap])
    _FakeZap.flag = flag
    job = ScanJob(target_url="http://127.0.0.1:9/", requested_scanners=["zap"])
    save_job(job)
    return pipe.run_scan(job.id)


def test_pipeline_finish_mid_scanner_finalizes_partials(tmp_path, monkeypatch):
    from app import activity

    job = _run_with_flag(tmp_path, monkeypatch, "finish")
    assert job.status == ScanStatus.completed
    assert "partial" in (job.error or "").lower()
    msgs = " ".join(e.get("msg", "") for e in activity.feed(job.id).get("events", []))
    assert "stopped by user (finish)" in msgs


def test_pipeline_pause_mid_scanner_pauses(tmp_path, monkeypatch):
    from app import activity

    job = _run_with_flag(tmp_path, monkeypatch, "pause")
    assert job.status == ScanStatus.paused
    msgs = " ".join(e.get("msg", "") for e in activity.feed(job.id).get("events", []))
    assert "stopped by user (pause)" in msgs
