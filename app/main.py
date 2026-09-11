from threading import Thread
from datetime import datetime

from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import HttpUrl

from app.config import ROOT, settings
from app.models import ScanJob, ScanRequest, Severity
from app.pipeline import run_scan
from app.store import list_jobs, load_job, save_job

STATIC_DIR = ROOT / "app" / "static"
API_KEY = settings.api_key


def require_api_key(x_api_key: str = Header(default="")):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(403, "Invalid API key")
    return x_api_key


app = FastAPI(title="Security Precheck", version="0.1.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def dashboard():
    return FileResponse(STATIC_DIR / "index.html")


@app.post("/api/scans", response_model=ScanJob)
def create_scan(req: ScanRequest, api_key: str = Depends(require_api_key)):
    job = ScanJob(target_url=str(req.target_url))
    save_job(job)
    Thread(target=run_scan, args=(job.id,), daemon=True).start()
    return job


@app.get("/api/scans", response_model=list[ScanJob])
def scans():
    return list_jobs()


@app.get("/api/scans/{scan_id}", response_model=ScanJob)
def get_scan(scan_id: str):
    job = load_job(scan_id)
    if not job:
        raise HTTPException(404, "scan not found")
    return job


@app.get("/api/scans/{scan_id}/export")
def export_scan(scan_id: str):
    job = load_job(scan_id)
    if not job:
        raise HTTPException(404, "scan not found")
    return JSONResponse(job.model_dump(mode="json"))


@app.get("/api/scans/{scan_id}/report")
def report_scan(scan_id: str):
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
        if f.description:
            lines.append(f"  Description: {f.description}")
        if f.recommendation:
            lines.append(f"  Recommendation: {f.recommendation}")
        if f.cve:
            lines.append(f"  CVE: {f.cve}")
        lines.append("")
    return PlainTextResponse("\n".join(lines))
