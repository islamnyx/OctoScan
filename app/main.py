from threading import Thread
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException, Depends, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import HttpUrl

from app.config import ROOT, settings
from app.models import ScanJob, ScanRequest, ScanStatus, Severity
from app.pipeline import run_scan
from app.security import (
    SecurityHeadersMiddleware,
    SimpleRateLimiter,
    validate_scan_id,
    validate_target_url,
)
from app.store import list_jobs, load_job, save_job

STATIC_DIR = ROOT / "app" / "static"
API_KEY = settings.api_key

_limiter = SimpleRateLimiter(
    max_hits=settings.scan_rate_limit, window_s=settings.scan_rate_window_s
)


def require_api_key(x_api_key: str = Header(default="")):
    # BAC fix (OWASP A01): when API_KEY is set, EVERY /api/* route requires
    # it — previously only POST did, leaving scan history/findings public.
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(403, "Invalid API key")
    return x_api_key


app = FastAPI(title="Security Precheck", version="0.1.0")
app.add_middleware(SecurityHeadersMiddleware)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.on_event("startup")
def recover_orphaned_scans():
    # Threads die on restart, leaving jobs stuck in running forever.
    # Finalize them as failed so the dashboard stays accurate.
    for job in list_jobs():
        if job.status == ScanStatus.running:
            job.status = ScanStatus.failed
            job.finished_at = datetime.now(timezone.utc)
            job.error = "orphaned: server restarted mid-scan (recovered on startup)"
            save_job(job)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def dashboard():
    return FileResponse(STATIC_DIR / "index.html")


@app.post("/api/scans", response_model=ScanJob)
def create_scan(req: ScanRequest, request: Request, api_key: str = Depends(require_api_key)):
    # SSRF guard + scan-DoS rate limit (WSTG + SSRF skills).
    _limiter.check(request.client.host if request.client else "unknown")
    # Global concurrent-scan cap: each scan spawns nmap/nikto/nuclei/zap.
    # Unbounded POSTs = disk/CPU exhaustion.
    running = sum(1 for j in list_jobs() if j.status in (ScanStatus.queued, ScanStatus.running))
    if running >= 3:
        raise HTTPException(429, "too many concurrent scans (max 3), retry later")
    target = validate_target_url(str(req.target_url), settings.allow_private_targets)
    job = ScanJob(target_url=target)
    save_job(job)
    Thread(target=run_scan, args=(job.id,), daemon=True).start()
    return job


@app.get("/api/scans", response_model=list[ScanJob])
def scans(api_key: str = Depends(require_api_key)):
    return list_jobs()


@app.get("/api/scans/{scan_id}", response_model=ScanJob)
def get_scan(scan_id: str, api_key: str = Depends(require_api_key)):
    scan_id = validate_scan_id(scan_id)
    job = load_job(scan_id)
    if not job:
        raise HTTPException(404, "scan not found")
    return job


@app.get("/api/scans/{scan_id}/export")
def export_scan(scan_id: str, api_key: str = Depends(require_api_key)):
    scan_id = validate_scan_id(scan_id)
    job = load_job(scan_id)
    if not job:
        raise HTTPException(404, "scan not found")
    return JSONResponse(job.model_dump(mode="json"))


@app.get("/api/scans/{scan_id}/report")
def report_scan(scan_id: str, api_key: str = Depends(require_api_key)):
    scan_id = validate_scan_id(scan_id)
    job = load_job(scan_id)
    if not job:
        raise HTTPException(404, "scan not found")
    lines = [
        "Security Precheck Report",
        "=" * 40,
        f"Target: {job.target_url}",
        f"Scan ID: {job.id}",
        f"Status: {job.status}",
        f"Started: {job.started_at}",
        f"Finished: {job.finished_at}",
        f"Scanners: {', '.join(job.scanners_run)}",
        "",
        "Summary",
        "-" * 40,
    ]
    counts = job.counts()
    for sev in [Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.info]:
        lines.append(f"  {sev.value.upper():10}: {counts[sev.value]}")
    lines.append("")
    lines.append("Findings")
    lines.append("-" * 40)
    for f in job.findings:
        lines.append(f"[{f.severity.value.upper()}] {f.title}")
        lines.append(f"  Scanner: {f.scanner}")
        lines.append(f"  Location: {f.location}")
        merged_count = (f.raw or {}).get("merged_count")
        if merged_count and merged_count > 1:
            sources = ", ".join((f.raw or {}).get("merged_sources") or [])
            lines.append(f"  Merged: {merged_count}x ({sources})")
            all_urls = (f.raw or {}).get("affected_urls") or []
            shown = all_urls[:5]
            for u in shown:
                lines.append(f"    - {u}")
            if len(all_urls) > len(shown):
                lines.append(f"    … and {len(all_urls) - len(shown)} more (full list in JSON export)")
        if f.description:
            lines.append(f"  Description: {f.description}")
        if f.evidence:
            lines.append(f"  Evidence: {f.evidence}")
        if f.recommendation:
            lines.append(f"  Recommendation: {f.recommendation}")
        if f.cve:
            lines.append(f"  CVE: {f.cve}")
        lines.append("")
    return PlainTextResponse("\n".join(lines))
