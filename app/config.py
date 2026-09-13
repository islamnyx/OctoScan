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
    # OOM guard (2026-09-13: AJAX spider spawned ~18 firefox-esr + 4G ZAP heap
    # on Juice Shop's 130-node tree -> 11.8G peak -> systemd-oomd SIGKILLed
    # java + firefox + uvicorn together). AJAX off by default; enable only
    # for JS-heavy SPAs when you have RAM headroom.
    zap_enable_ajax_spider: bool = False
    zap_ajax_timeout_seconds: int = 60
    # Active scan cap: recurse=false + top-N dynamic URLs only. Static assets
    # (.js/.css/.map/fonts/images) never carry ascan vulns, only noise.
    zap_ascan_recurse: bool = False
    zap_ascan_max_targets: int = 20
    # Shared ascan budget (timeout fix 2026-09-13): one total budget for all
    # targets instead of dividing per-target (60s each timed out on Juice
    # Shop's 103s/host). Env-overridable so full-strength validation runs
    # can raise it without code changes; capped saved us from OOM, keep 600.
    zap_ascan_budget_seconds: int = 600
    zap_ascan_per_target_seconds: int = 300
    nuclei_severity: str = "critical,high,medium,low"
    # Don't DoS the target: full template set at nuclei defaults (25
    # concurrent, 150 req/s) OOM-killed Juice Shop in testing (3 GB heap).
    # Throttling keeps full depth, just slower. Exclude 'dos' templates
    # (memory bombs, ReDoS) — they crash staging apps instead of testing them.
    nuclei_rate_limit: int = 50
    nuclei_concurrency: int = 10
    nuclei_bulk_size: int = 25
    nuclei_exclude_tags: str = "dos"
    scan_timeout_seconds: int = 900
    scan_max_parallel: int = 1
    api_key: str = ""
    # SSRF guard: false (default) blocks private/loopback/metadata targets.
    # Set ALLOW_PRIVATE_TARGETS=true in .env for lab scans (Juice Shop on localhost).
    allow_private_targets: bool = False
    scan_rate_limit: int = 10
    scan_rate_window_s: int = 60


settings = Settings()
settings.data_dir.mkdir(parents=True, exist_ok=True)
(settings.data_dir / "scans").mkdir(parents=True, exist_ok=True)
