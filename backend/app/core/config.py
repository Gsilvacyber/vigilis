import logging
import os
from dataclasses import dataclass

from dotenv import load_dotenv

_log = logging.getLogger(__name__)

load_dotenv()

_DEFAULT_DEMO_KEY = "socai-demo-key-do-not-use-in-production"


@dataclass(frozen=True)
class Settings:
    app_env: str
    app_port: int
    database_url: str
    webhook_default_url: str
    app_create_tables: bool
    demo_api_key: str
    grouping_window_minutes: int = 60
    correlation_window_hours: int = 72
    redis_url: str = ""
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    greynoise_api_key: str = ""
    enable_local_feeds: bool = True
    feed_update_hours: int = 24


def _get_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


settings = Settings(
    app_env=os.getenv("APP_ENV", "local"),
    app_port=int(os.getenv("APP_PORT", "8000")),
    database_url=os.getenv("DATABASE_URL", "postgresql+psycopg2://socai:socai@localhost:5432/socai"),
    webhook_default_url=os.getenv("WEBHOOK_DEFAULT_URL", ""),
    app_create_tables=_get_bool("APP_CREATE_TABLES", True),
    demo_api_key=os.getenv("DEMO_API_KEY", _DEFAULT_DEMO_KEY),
    grouping_window_minutes=int(os.getenv("GROUPING_WINDOW_MINUTES", "60")),
    correlation_window_hours=int(os.getenv("CORRELATION_WINDOW_HOURS", "72")),
    redis_url=os.getenv("REDIS_URL", ""),
    virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY", ""),
    abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", ""),
    otx_api_key=os.getenv("OTX_API_KEY", ""),
    greynoise_api_key=os.getenv("GREYNOISE_API_KEY", ""),
    enable_local_feeds=os.getenv("ENABLE_LOCAL_FEEDS", "true").lower() in ("true", "1", "yes"),
    feed_update_hours=int(os.getenv("FEED_UPDATE_HOURS", "24")),
)


# ── Startup Warnings ─────────────────────────────────────
def _validate_settings() -> None:
    """Log warnings for unsafe production defaults."""
    if settings.app_env == "prod":
        if settings.demo_api_key == _DEFAULT_DEMO_KEY:
            raise RuntimeError(
                "FATAL: DEMO_API_KEY is the well-known default value. "
                "Set DEMO_API_KEY to a strong random value before running in production. "
                "This is a hard fail, not a warning — the default key is publicly known."
            )
        if settings.app_create_tables:
            _log.warning(
                "APP_CREATE_TABLES=true in production. Consider using "
                "Alembic migrations instead for safer schema management."
            )


_validate_settings()

