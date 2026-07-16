"""Application configuration — env-driven, minimal footprint."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SQUIDSEC2_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "SquidSeC2"
    host: str = "0.0.0.0"
    port: int = 8443
    debug: bool = False
    data_dir: Path = Path("data")
    db_path: Path | None = None
    admin_token_bootstrap: str | None = None
    cors_origins: list[str] = Field(default_factory=lambda: ["*"])
    max_body_bytes: int = 1_048_576
    event_buffer_size: int = 500
    default_listener_port: int = 4444
    mcp_enabled: bool = True
    ai_enabled: bool = True
    audit_retention_days: int = 90
    rate_limit_per_minute: int = 120

    @property
    def database_path(self) -> Path:
        if self.db_path is not None:
            return self.db_path
        return self.data_dir / "squidsec2.db"


@lru_cache
def get_settings() -> Settings:
    return Settings()
