from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT / ".env", extra="ignore")

    app_host: str = "127.0.0.1"
    app_port: int = 8000
    data_dir: Path = ROOT / "data"
    nmap_bin: str = "nmap"
    nikto_bin: str = "nikto"
    nuclei_bin: str = "nuclei"
    zap_bin: str = "/usr/share/zaproxy/zap.sh"
    testssl_bin: Path = ROOT / "resources" / "testssl.sh" / "testssl.sh"
    zap_port: int = 8090
    zap_base_url: str = "http://127.0.0.1:8090"
    zap_api_key: str = ""
    # AJAX spider cage (2026-10-02: enabled by default, but bounded — the
    # 2026-09-13 OOM was 12 browsers + unlimited states + 60-min cap on a
    # 130-node tree -> 11.8G peak -> systemd-oomd SIGKILLed java+firefox.
    # 1 browser + 200 states + depth 5 + 5 min finds SPA routes (/rest/*,
    # /#/...) at ~1-2 GB peak. Options are set per-scan via the ZAP API
    # and restored afterwards; stray firefox processes are reaped by PID
    # (pre-existing PIDs — e.g. your desktop browser — are never touched).
    zap_enable_ajax_spider: bool = True
    zap_ajax_timeout_seconds: int = 300
    zap_ajax_browsers: int = 1
    zap_ajax_max_depth: int = 5
    zap_ajax_max_states: int = 200
    zap_ajax_max_minutes: int = 5
    # Skip AJAX when the box is this short on free memory (ZAP + 1 headless
    # firefox need ~1.5 GB headroom). Read from /proc/meminfo; unreadable =
    # fail-open (run anyway).
    zap_ajax_min_free_mb: int = 1500
    # Active scan cap: recurse=false + top-N dynamic URLs only. Static assets
    # (.js/.css/.map/fonts/images) never carry ascan vulns, only noise.
    zap_ascan_recurse: bool = False
    zap_ascan_max_targets: int = 20
    # Shared ascan budget (timeout fix 2026-09-13): one total budget for all
    # targets instead of dividing per-target (60s each timed out on Juice
    # Shop's 103s/host). Env-overridable so full-strength validation runs
    # can raise it without code changes.
    # Full-coverage tune 2026-09-16: 4/20 targets in 450s meant slow hosts
    # ate the budget. Now a longer shared budget (1200s) with a tighter
    # per-target cap (150s) plus throttled threads (below) so all 20 get a
    # turn without hammering the target (lab flapping on 2026-09-16) or RAM.
    zap_ascan_budget_seconds: int = 1200
    zap_ascan_per_target_seconds: int = 150
    # Active-scan politeness (2026-09-16): default 24 threads/host floods
    # small lab targets into crashes/rate-limits. 6 threads + 50ms delay
    # keeps full template depth at lower pressure. Set per-scan via the ZAP
    # API (previous daemon values restored afterwards).
    zap_ascan_thread_per_host: int = 6
    zap_ascan_delay_ms: int = 50
    nuclei_severity: str = "critical,high,medium,low"
    # Don't DoS the target: full template set at nuclei defaults (25
    # concurrent, 150 req/s) OOM-killed Juice Shop in testing (3 GB heap).
    # Throttling keeps full depth, just slower. Exclude 'dos' templates
    # (memory bombs, ReDoS) — they crash staging apps instead of testing them.
    nuclei_rate_limit: int = 50
    nuclei_concurrency: int = 10
    nuclei_bulk_size: int = 25
    nuclei_exclude_tags: str = "dos"
    # Second pass: exposure/misconfiguration/JWT templates at these
    # severities. The main pass gates on severity (info excluded), which
    # hides genuine exposure signals (public Swagger UI, metrics pages,
    # JWT misconfigurations). Tag-scoped and throttled like the main run;
    # info findings never fail the gate.
    nuclei_extra_tags: str = "exposure,misconfiguration,jwt"
    nuclei_extra_severities: str = "info,low,medium,high,critical"
    scan_timeout_seconds: int = 900
    # ZAP runs first and alone (daemon memory, spider output); the rest
    # share a pool. 3 workers cut ~30 min wall time toward ~15 on lab
    # targets without flapping them (nikto+nuclei+nmap side by side).
    scan_max_parallel: int = 3
    api_key: str = ""
    # SSRF guard: false (default) blocks private/loopback/metadata targets.
    # Set ALLOW_PRIVATE_TARGETS=true in .env for lab scans (Juice Shop on localhost).
    allow_private_targets: bool = False
    scan_rate_limit: int = 10
    scan_rate_window_s: int = 60
    # ---- Phase 2: repo / source scans ----
    git_bin: str = "git"
    gitleaks_bin: str = "gitleaks"
    semgrep_bin: str = "semgrep"
    osv_bin: str = "osv-scanner"
    # Cap on grouped OSV findings per scan (NodeGoat: ~110 distinct CVEs).
    # Bounds dashboard rows / job.json size; AI triage separately takes top 40.
    osv_max_groups: int = 300
    repos_dir: Path = ROOT / "data" / "repos"
    repo_clone_timeout_s: int = 120
    repo_max_files: int = 20000
    repo_max_bytes: int = 200 * 1024 * 1024
    # ---- Phase 2: BYO AI (OpenAI-compatible) ----
    # Any provider exposing POST {base}/chat/completions works:
    # OpenAI, OpenRouter, Together, Groq, Ollama, LM Studio, vLLM, custom.
    ai_provider: str = ""
    ai_base_url: str = ""
    ai_api_key: str = ""
    ai_model: str = ""
    ai_timeout_s: int = 60
    ai_max_tokens: int = 2000
    # AI code review bounds: which/how much code the model reads.
    # 8 files/90k missed django.nV's SQLi (views.py never sampled);
    # 16 files/160k covers real app code while capping Groq costs.
    ai_review_max_files: int = 20
    ai_review_max_bytes: int = 160_000
    ai_review_max_tokens: int = 500
    # Two-phase review (nominate from listing, then batched reading):
    # related files in one prompt give the model route->sink context.
    ai_review_batch_files: int = 3
    ai_review_batch_chars: int = 36_000


settings = Settings()
settings.data_dir.mkdir(parents=True, exist_ok=True)
(settings.data_dir / "scans").mkdir(parents=True, exist_ok=True)
(settings.repos_dir if isinstance(settings.repos_dir, Path) else ROOT / "data" / "repos").mkdir(parents=True, exist_ok=True)
