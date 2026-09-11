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
    zap_bin: str = "/usr/share/zaproxy/zap.sh"
    testssl_bin: Path = ROOT / "resources" / "testssl.sh" / "testssl.sh"
    zap_port: int = 8090
    zap_base_url: str = "http://127.0.0.1:8090"
    zap_api_key: str = "test"
    scan_timeout_seconds: int = 900
    api_key: str = ""


settings = Settings()
settings.data_dir.mkdir(parents=True, exist_ok=True)
(settings.data_dir / "scans").mkdir(parents=True, exist_ok=True)
