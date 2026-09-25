"""Configuration — reads SCAN_TOOLKIT_* env vars and root .env via pydantic-settings.

Why SCAN_TOOLKIT_ prefix: the root .env is shared with the web app (app/config.py),
which uses unprefixed DATA_DIR / API_KEY / etc.  Without a prefix the two namespaces
would silently collide or cross-populate.
"""

from functools import lru_cache
from pathlib import Path

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ROOT / ".env",
        env_prefix="SCAN_TOOLKIT_",
        extra="ignore",
    )

    # ---- storage ----
    data_dir: Path = ROOT / "data"
    db_url: str = ""  # auto-derived from data_dir when empty (see validator below)

    # ---- LLM (placeholder — unused until Phase 4) ----
    anthropic_api_key: str = ""

    # ---- resource limits (Phase 6) ----
    max_concurrent_dynamic_jobs: int = 2

    # ---- tool paths (reserved — unused until Phase 3+) ----
    apktool_bin: str = "apktool"
    jadx_bin: str = "jadx"
    semgrep_bin: str = "semgrep"
    mobsf_base_url: str = "http://127.0.0.1:8000"
    mobsf_api_key: str = ""

    # ---- tool execution ----
    tool_timeout_seconds: int = 600

    # ---- Semgrep config ----
    semgrep_rules_dir: Path = ROOT / "scan_toolkit" / "rules" / "semgrep"
    semgrep_extra_configs: str = ""

    @model_validator(mode="after")
    def _derive_db_url(self) -> "Settings":
        if not self.db_url:
            db_path = self.data_dir / "toolkit.db"
            self.db_url = f"sqlite+pysqlite:///{db_path.as_posix()}"
        return self


def ensure_runtime_dirs() -> None:
    """Create data_dir (and its scans subdir) — called from init_db(), never at import."""
    settings = get_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    (settings.data_dir / "scans").mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()