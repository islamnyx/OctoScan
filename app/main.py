from threading import Thread
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException, Depends, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import HttpUrl

from app.config import ROOT, settings
from app.models import (
    AIConfigRequest,
    AIConfigResponse,
    AIProviderRequest,
    RepoScanJob,
    RepoScanRequest,
    ScanJob,
    ScanRequest,
    ScanStatus,
    Severity,
)
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
    job = ScanJob(target_url=target, requested_scanners=req.scanners or [])
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
        f"Quality gate: {job.gate}",
        *[f"  FAIL: {d}" for d in (job.gate_details or [])],
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


# ---- Phase 2: BYO AI + repo scans (additive, same auth/validation) ----


@app.get("/api/ai/config", response_model=AIConfigResponse)
def ai_config(api_key: str = Depends(require_api_key)):
    from app import ai as ai_layer

    return AIConfigResponse(**ai_layer.masked(ai_layer.load_config()))


@app.put("/api/ai/config", response_model=AIConfigResponse)
def ai_save_config(req: AIConfigRequest, api_key: str = Depends(require_api_key)):
    from app import ai as ai_layer

    if req.base_url and not req.base_url.startswith(("http://", "https://")):
        raise HTTPException(400, "base_url must be http(s)")
    cfg = ai_layer.save_config(req.provider, req.base_url, req.api_key, req.model)
    return AIConfigResponse(**ai_layer.masked(cfg))


@app.get("/api/ai/providers")
def ai_providers(api_key: str = Depends(require_api_key)):
    from app import ai as ai_layer

    return ai_layer.list_providers()


@app.post("/api/ai/providers")
def ai_provider_save(req: AIProviderRequest, api_key: str = Depends(require_api_key)):
    from app import ai as ai_layer

    try:
        ai_layer.upsert_provider(
            name=req.name, provider=req.provider, base_url=req.base_url,
            api_key=req.api_key, model=req.model, activate=req.activate,
        )
    except Exception as exc:
        raise HTTPException(502, str(exc)[:500])
    return ai_layer.list_providers()


@app.post("/api/ai/providers/{name}/activate")
def ai_provider_activate(name: str, api_key: str = Depends(require_api_key)):
    from app import ai as ai_layer

    try:
        ai_layer.activate_provider(name)
    except Exception as exc:
        raise HTTPException(404, str(exc)[:300])
    return ai_layer.list_providers()


@app.delete("/api/ai/providers/{name}")
def ai_provider_delete(name: str, api_key: str = Depends(require_api_key)):
    from app import ai as ai_layer

    ai_layer.delete_provider(name)
    return ai_layer.list_providers()


@app.post("/api/ai/test")
def ai_test(req: AIConfigRequest | None = None, api_key: str = Depends(require_api_key)):
    from app import ai as ai_layer

    cfg = ai_layer.load_config()
    if req and req.name and not (req.base_url or req.api_key):
        saved = {p["name"]: p for p in ai_layer.list_providers()["providers"]}
        p = saved.get(req.name)
        if p:
            cfg = {"provider": p["provider"], "base_url": p["base_url"],
                   "api_key": p["api_key"] if p["has_key"] else "", "model": p["model"]}
    elif req and (req.base_url or req.model):
        cfg = {
            "provider": req.provider or cfg.get("provider", ""),
            "base_url": req.base_url or cfg.get("base_url", ""),
            "api_key": req.api_key if req.api_key else cfg.get("api_key", ""),
            "model": req.model or cfg.get("model", ""),
        }
    try:
        return ai_layer.test_connection(cfg)
    except Exception as exc:
        raise HTTPException(502, str(exc)[:500])


@app.post("/api/ai/models")
def ai_models(req: AIConfigRequest | None = None, api_key: str = Depends(require_api_key)):
    """Model list from the provider (OpenAI-compatible GET /models).

    Accepts the form's current provider/base/key so the picker works
    BEFORE the config is saved; falls back to the saved config.
    """
    from app import ai as ai_layer

    cfg = ai_layer.load_config()
    if req and req.name and not (req.base_url or req.api_key):
        saved = {p["name"]: p for p in ai_layer.list_providers()["providers"]}
        p = saved.get(req.name)
        if p:
            cfg = {"provider": p["provider"], "base_url": p["base_url"],
                   "api_key": p["api_key"] if p["has_key"] else "", "model": p["model"]}
    elif req and (req.base_url or req.api_key):
        cfg = {
            "provider": req.provider or cfg.get("provider", ""),
            "base_url": req.base_url or cfg.get("base_url", ""),
            "api_key": req.api_key if req.api_key else cfg.get("api_key", ""),
            "model": req.model or cfg.get("model", ""),
        }
    try:
        return ai_layer.list_models(cfg)
    except Exception as exc:
        raise HTTPException(502, str(exc)[:500])


@app.get("/api/scans/{scan_id}/activity")
def scan_activity(scan_id: str, api_key: str = Depends(require_api_key)):
    from app import activity

    scan_id = validate_scan_id(scan_id)
    return activity.feed(scan_id)


@app.get("/api/repo-scans/{scan_id}/activity")
def repo_scan_activity(scan_id: str, api_key: str = Depends(require_api_key)):
    from app import activity

    scan_id = validate_scan_id(scan_id)
    return activity.feed(scan_id)


@app.post("/api/repo-scans", response_model=RepoScanJob)
def create_repo_scan(req: RepoScanRequest, request: Request, api_key: str = Depends(require_api_key)):
    from app.repo import validate_branch, validate_repo_url
    from app.repo_pipeline import run_repo_scan
    from app.repo_store import save_repo_job

    _limiter.check(request.client.host if request.client else "unknown")
    repo_url = validate_repo_url(req.repo_url)
    branch = validate_branch(req.branch)
    job = RepoScanJob(repo_url=repo_url, branch=branch, ai_requested=req.include_ai, requested_scanners=req.scanners or [])
    save_repo_job(job)
    Thread(
        target=run_repo_scan,
        args=(job.id,),
        kwargs={"run_ai": req.include_ai, "ai_model": req.ai_model},
        daemon=True,
    ).start()
    return job


@app.get("/api/repo-scans", response_model=list[RepoScanJob])
def repo_scans(api_key: str = Depends(require_api_key)):
    from app.repo_store import list_repo_jobs

    return list_repo_jobs()


@app.get("/api/repo-scans/{scan_id}", response_model=RepoScanJob)
def get_repo_scan(scan_id: str, api_key: str = Depends(require_api_key)):
    from app.repo_store import load_repo_job

    scan_id = validate_scan_id(scan_id)
    job = load_repo_job(scan_id)
    if not job:
        raise HTTPException(404, "repo scan not found")
    return job


@app.post("/api/repo-scans/{scan_id}/ai-analyze", response_model=RepoScanJob)
def repo_ai_analyze(scan_id: str, api_key: str = Depends(require_api_key)):
    from app import ai as ai_layer
    from app import ai_review
    from app.normalize import prioritize
    from app.repo_store import load_repo_job, repo_workdir, save_repo_job

    scan_id = validate_scan_id(scan_id)
    job = load_repo_job(scan_id)
    if not job:
        raise HTTPException(404, "repo scan not found")
    if job.status not in (ScanStatus.completed, ScanStatus.failed):
        raise HTTPException(409, "scan still running")
    try:
        # Regenerate: drop previous AI findings, model re-reads the code.
        job.findings = [f for f in job.findings if f.scanner not in ("ai-code-review",)]
        workdir = repo_workdir(job.id)
        if workdir.exists():
            review = ai_review.review_codebase(workdir, job.repo_url)
            job.findings = prioritize(job.findings + review)
            if "ai-code-review" not in job.scanners_run:
                job.scanners_run.append("ai-code-review")
        job.ai = ai_layer.analyze_findings(job.repo_url, job.findings)
        if "ai" not in job.scanners_run:
            job.scanners_run.append("ai")
        save_repo_job(job)
    except Exception as exc:
        raise HTTPException(502, str(exc)[:500])
    return job


@app.post("/api/scans/{scan_id}/ai-analyze", response_model=ScanJob)
def scan_ai_analyze(scan_id: str, api_key: str = Depends(require_api_key)):
    from app import ai as ai_layer

    scan_id = validate_scan_id(scan_id)
    job = load_job(scan_id)
    if not job:
        raise HTTPException(404, "scan not found")
    if job.status not in (ScanStatus.completed, ScanStatus.failed):
        raise HTTPException(409, "scan still running")
    try:
        analysis = ai_layer.analyze_findings(job.target_url, job.findings)
    except Exception as exc:
        raise HTTPException(502, str(exc)[:500])
    # Persist as a finding-free sidecar in raw of an info finding? Keep
    # ScanJob schema stable: store summary inside error-adjacent field is
    # wrong, so append an `ai` info finding carrying the summary.
    from app.models import Finding

    job.findings.append(
        Finding(
            scanner="ai",
            title=f"AI triage ({analysis.model or analysis.provider or 'configured'})",
            severity=Severity.info,
            description=analysis.summary[:2000],
            evidence="; ".join(analysis.prioritized_fixes)[:1000],
            location=job.target_url,
            recommendation="; ".join(analysis.prioritized_fixes)[:1000] or "See AI summary.",
            raw={"provider": analysis.provider, "model": analysis.model,
                  "false_positive_notes": analysis.false_positive_notes},
        )
    )
    if "ai" not in job.scanners_run:
        job.scanners_run.append("ai")
    save_job(job)
    return job


# ---- Run controls: pause / resume / finish (long scans) ----


def _running_count() -> int:
    return sum(1 for j in list_jobs() if j.status in (ScanStatus.queued, ScanStatus.running))


@app.post("/api/scans/{scan_id}/pause", response_model=ScanJob)
def pause_scan(scan_id: str, api_key: str = Depends(require_api_key)):
    from app import control

    scan_id = validate_scan_id(scan_id)
    job = load_job(scan_id)
    if not job:
        raise HTTPException(404, "scan not found")
    if job.status != ScanStatus.running:
        raise HTTPException(409, f"scan is {job.status}, nothing to pause")
    control.request_pause(scan_id, "scan")
    return job


@app.post("/api/scans/{scan_id}/resume", response_model=ScanJob)
def resume_scan(scan_id: str, request: Request, api_key: str = Depends(require_api_key)):
    from app import control

    scan_id = validate_scan_id(scan_id)
    job = load_job(scan_id)
    if not job:
        raise HTTPException(404, "scan not found")
    if job.status != ScanStatus.paused:
        raise HTTPException(409, f"scan is {job.status}, nothing to resume")
    if _running_count() >= 3:
        raise HTTPException(429, "too many concurrent scans (max 3), retry later")
    control.clear_pause(scan_id, "scan")
    Thread(target=run_scan, args=(job.id,), daemon=True).start()
    return job


@app.post("/api/scans/{scan_id}/finish", response_model=ScanJob)
def finish_scan(scan_id: str, api_key: str = Depends(require_api_key)):
    from app import control
    from app.pipeline import finalize_scan

    scan_id = validate_scan_id(scan_id)
    job = load_job(scan_id)
    if not job:
        raise HTTPException(404, "scan not found")
    if job.status not in (ScanStatus.running, ScanStatus.paused):
        raise HTTPException(409, f"scan is {job.status}, nothing to finish")
    if job.status == ScanStatus.paused:
        prior = [job.error] if job.error else []
        return finalize_scan(job, list(job.findings), prior, early=True)
    control.request_finish(scan_id, "scan")
    return job


@app.post("/api/repo-scans/{scan_id}/pause", response_model=RepoScanJob)
def pause_repo_scan(scan_id: str, api_key: str = Depends(require_api_key)):
    from app import control
    from app.repo_store import load_repo_job

    scan_id = validate_scan_id(scan_id)
    job = load_repo_job(scan_id)
    if not job:
        raise HTTPException(404, "repo scan not found")
    if job.status != ScanStatus.running:
        raise HTTPException(409, f"scan is {job.status}, nothing to pause")
    control.request_pause(scan_id, "repo")
    return job


@app.post("/api/repo-scans/{scan_id}/resume", response_model=RepoScanJob)
def resume_repo_scan(scan_id: str, request: Request, api_key: str = Depends(require_api_key)):
    from app import control
    from app.repo_pipeline import run_repo_scan
    from app.repo_store import load_repo_job

    scan_id = validate_scan_id(scan_id)
    job = load_repo_job(scan_id)
    if not job:
        raise HTTPException(404, "repo scan not found")
    if job.status != ScanStatus.paused:
        raise HTTPException(409, f"scan is {job.status}, nothing to resume")
    if _running_count() >= 3:
        raise HTTPException(429, "too many concurrent scans (max 3), retry later")
    control.clear_pause(scan_id, "repo")
    Thread(target=run_repo_scan, args=(job.id,), kwargs={"run_ai": job.ai_requested}, daemon=True).start()
    return job


@app.post("/api/repo-scans/{scan_id}/finish", response_model=RepoScanJob)
def finish_repo_scan(scan_id: str, api_key: str = Depends(require_api_key)):
    from app import control
    from app.repo_pipeline import finalize_repo_job
    from app.repo_store import load_repo_job

    scan_id = validate_scan_id(scan_id)
    job = load_repo_job(scan_id)
    if not job:
        raise HTTPException(404, "repo scan not found")
    if job.status not in (ScanStatus.running, ScanStatus.paused):
        raise HTTPException(409, f"scan is {job.status}, nothing to finish")
    if job.status == ScanStatus.paused:
        prior = [job.error] if job.error else []
        return finalize_repo_job(job, list(job.findings), prior, early=True)
    control.request_finish(scan_id, "repo")
    return job


# ---- Dedicated pages: every scan gets its own result + status URL ----


def _page(name: str):
    return FileResponse(STATIC_DIR / name)


@app.get("/scans/{scan_id}")
def scan_result_page(scan_id: str):
    scan_id = validate_scan_id(scan_id)
    if not load_job(scan_id):
        raise HTTPException(404, "scan not found")
    return _page("scan.html")


@app.get("/scans/{scan_id}/status")
def scan_status_page(scan_id: str):
    scan_id = validate_scan_id(scan_id)
    if not load_job(scan_id):
        raise HTTPException(404, "scan not found")
    return _page("status.html")


@app.get("/repos/{scan_id}")
def repo_result_page(scan_id: str):
    from app.repo_store import load_repo_job

    scan_id = validate_scan_id(scan_id)
    if not load_repo_job(scan_id):
        raise HTTPException(404, "repo scan not found")
    return _page("scan.html")


@app.get("/repos/{scan_id}/status")
def repo_status_page(scan_id: str):
    from app.repo_store import load_repo_job

    scan_id = validate_scan_id(scan_id)
    if not load_repo_job(scan_id):
        raise HTTPException(404, "repo scan not found")
    return _page("status.html")
