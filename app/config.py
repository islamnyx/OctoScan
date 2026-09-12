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
