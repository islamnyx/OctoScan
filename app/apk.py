"""APK / mobile bridge — exposes scan_toolkit engagements through the OctoScan API.

NEW file (hack/n3yx-scan-quality). Islam owns app/main.py + app/models.py, so
this module owns its own router + pydantic schemas and only needs a 2-line
mount in main.py (see docs/TEAM.md request):

    from app.apk import router as apk_router
    app.include_router(apk_router)

Endpoints (same X-API-Key guard as /api/*):
  POST /api/apk/scans        multipart upload (.apk/.ipa/.aab) -> intake + static stage
  GET  /api/apk/scans        list engagements (newest first)
  GET  /api/apk/scans/{id}   detail: engagement + findings + static stage summary
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from threading import Thread

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, UploadFile
from pydantic import BaseModel

from app.config import settings

router = APIRouter(prefix="/api/apk", tags=["apk"])

API_KEY = settings.api_key
MAX_UPLOAD_BYTES = 300 * 1024 * 1024
ALLOWED_SUFFIXES = {".apk", ".ipa", ".aab"}


def require_api_key(x_api_key: str = Header(default="")):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(403, "Invalid API key")
    return x_api_key


class ApkScanSummary(BaseModel):
    id: str
    client_name: str | None = None
    platform: str | None = None
    app_version: str | None = None
    status: str
    findings: int = 0
    static_status: str | None = None
    static_errors: int = 0


class ApkScanDetail(ApkScanSummary):
    binary_filename: str | None = None
    tools: list[dict] = []
    notes: list[str] = []
    errors: list[str] = []
    findings_detail: list[dict] = []


def _toolkit():
    from scan_toolkit import artifacts, engagements  # noqa: F401
    from scan_toolkit.db import init_db, session_scope
    from scan_toolkit.models import Engagement, Finding

    return artifacts, engagements, init_db, session_scope, Engagement, Finding


def _stage_summary(engagement_id: str) -> dict:
    from scan_toolkit import artifacts

    result_file = artifacts.engagement_dir(engagement_id) / "stages" / "static" / "stage_result.json"
    if not result_file.exists():
        return {"status": None, "tools": [], "notes": [], "errors": []}
    try:
        data = json.loads(result_file.read_text())
    except (json.JSONDecodeError, OSError):
        return {"status": "unreadable", "tools": [], "notes": [], "errors": ["unreadable stage_result.json"]}
    return {
        "status": data.get("status"),
        "tools": [
            {"tool": t.get("tool"), "findings": len(t.get("findings", [])), "errors": t.get("errors", [])}
            for t in data.get("tools", [])
        ],
        "notes": data.get("notes", []),
        "errors": data.get("errors", []),
    }


def _run_static_background(engagement_id: str) -> None:
    """Background worker: validate intake -> run static stage -> advance to reviewing."""
    try:
        from scan_toolkit.db import init_db, session_scope
        from scan_toolkit.engagements import advance_engagement_status, get_engagement
        from scan_toolkit.models import EngagementStatus
        from scan_toolkit.stages import run_stage

        engine = init_db()
        with session_scope(engine) as session:
            eng = get_engagement(session, engagement_id)
            if eng is None:
                return
            try:
                advance_engagement_status(session, eng, EngagementStatus.scanning)
            except ValueError:
                pass  # already past intake; still run the stage
        with session_scope(engine) as session:
            try:
                run_stage(session, engagement_id, "static")
            except ValueError:
                return
        with session_scope(engine) as session:
            eng = get_engagement(session, engagement_id)
            if eng is not None and eng.status == EngagementStatus.scanning:
                try:
                    advance_engagement_status(session, eng, EngagementStatus.reviewing)
                except ValueError:
                    pass
    except Exception:
        # Never crash the worker thread; errors live in stage_result.json / logs.
        return


@router.post("/scans", response_model=ApkScanSummary)
def create_apk_scan(
    file: UploadFile = File(...),
    client_name: str = Form(default="dashboard-upload"),
    platform: str = Form(default="android"),
    app_version: str | None = Form(default=None),
    api_key: str = Depends(require_api_key),
):
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise HTTPException(400, f"expected {'/'.join(sorted(ALLOWED_SUFFIXES))}, got {suffix or '(no extension)'}")
    platform_norm = (platform or "").strip().lower()
    if platform_norm not in ("android", "ios"):
        raise HTTPException(400, "platform must be 'android' or 'ios'")

    artifacts, engagements, init_db, session_scope, _, _ = _toolkit()
    from scan_toolkit.models import Platform

    # Stream upload to a temp file first (fail-closed on size).
    # Keep the original filename so engagement artifacts show app.apk,
    # not a tmp name — sanitized to a safe basename.
    import re as _re

    safe_name = _re.sub(r"[^A-Za-z0-9._-]", "_", Path(file.filename or "upload.apk").name)[:120] or "upload.apk"
    tmp_dir = Path(tempfile.mkdtemp(prefix="apk-upload-"))
    tmp_path = tmp_dir / safe_name
    try:
        total = 0
        with open(tmp_path, "wb") as out:
            while chunk := file.file.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, "APK too large (max 300 MB)")
                out.write(chunk)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, f"could not read upload: {exc}")

    try:
        engine = init_db()
    except Exception as exc:
        import shutil as _shutil

        _shutil.rmtree(tmp_dir, ignore_errors=True)
        raise HTTPException(500, f"toolkit db init failed: {exc}")

    with session_scope(engine) as session:
        try:
            eng = engagements.create_engagement(
                session,
                client_name=client_name.strip() or "dashboard-upload",
                app_platform=Platform(platform_norm),
                app_version=(app_version or "").strip() or None,
                scope_agreement_confirmed=True,  # dashboard upload implies scope
                binary_source=str(tmp_path),
            )
            eng_id = eng.id
            eng_status = eng.status.value
        except ValueError as exc:
            raise HTTPException(400, str(exc))
    import shutil as _shutil

    _shutil.rmtree(tmp_dir, ignore_errors=True)

    Thread(target=_run_static_background, args=(eng_id,), daemon=True).start()
    return ApkScanSummary(
        id=eng_id,
        client_name=client_name.strip() or "dashboard-upload",
        platform=platform_norm,
        app_version=(app_version or "").strip() or None,
        status=eng_status,
        findings=0,
        static_status=None,
        static_errors=0,
    )


@router.get("/scans", response_model=list[ApkScanSummary])
def list_apk_scans(api_key: str = Depends(require_api_key)):
    _, _, init_db, session_scope, Engagement, Finding = _toolkit()
    engine = init_db()
    out: list[ApkScanSummary] = []
    with session_scope(engine) as session:
        rows = session.query(Engagement).order_by(Engagement.created_at.desc()).limit(50).all()
        for eng in rows:
            n = session.query(Finding).filter(Finding.engagement_id == eng.id).count()
            stage = _stage_summary(eng.id)
            out.append(
                ApkScanSummary(
                    id=eng.id,
                    client_name=eng.client_name,
                    platform=eng.app_platform.value if eng.app_platform else None,
                    app_version=eng.app_version,
                    status=eng.status.value,
                    findings=n,
                    static_status=stage["status"],
                    static_errors=len(stage["errors"]),
                )
            )
    return out


@router.get("/scans/{scan_id}", response_model=ApkScanDetail)
def get_apk_scan(scan_id: str, api_key: str = Depends(require_api_key)):
    artifacts, engagements, init_db, session_scope, _, Finding = _toolkit()
    try:
        artifacts.validate_engagement_id(scan_id)
    except ValueError:
        raise HTTPException(400, "invalid scan id")
    engine = init_db()
    with session_scope(engine) as session:
        eng = engagements.get_engagement(session, scan_id)
        if eng is None:
            raise HTTPException(404, "apk scan not found")
        rows = session.query(Finding).filter(Finding.engagement_id == eng.id).all()
        findings = [r.to_dict() for r in rows]
        binary_filename = eng.intake.binary_filename if eng.intake else None
        summary = ApkScanDetail(
            id=eng.id,
            client_name=eng.client_name,
            platform=eng.app_platform.value if eng.app_platform else None,
            app_version=eng.app_version,
            status=eng.status.value,
            findings=len(findings),
            binary_filename=binary_filename,
            findings_detail=findings,
        )
    stage = _stage_summary(scan_id)
    summary.static_status = stage["status"]
    summary.static_errors = len(stage["errors"])
    summary.tools = stage["tools"]
    summary.notes = stage["notes"]
    summary.errors = stage["errors"]
    return summary
