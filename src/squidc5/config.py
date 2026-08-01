"""Application configuration — env-driven, minimal footprint."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SQUIDC5_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "SquidC5"
    host: str = "0.0.0.0"
    port: int = 8443
    debug: bool = False
    data_dir: Path = Path("data")
    db_path: Path | None = None
    admin_token_bootstrap: str | None = None
    # Secure default: no wildcard CORS. Same-origin /ops needs no CORS.
    # Set SQUIDC5_CORS_ORIGINS='["https://ops.example"]' only if required.
    cors_origins: list[str] = Field(default_factory=list)
    max_body_bytes: int = 1_048_576
    event_buffer_size: int = 500
    default_listener_port: int = 4444
    # MCP off by default — enable explicitly when external AI is required
    mcp_enabled: bool = False
    ai_enabled: bool = True
    audit_retention_days: int = 90
    rate_limit_per_minute: int = 60
    # Stricter per-IP cap on failed authentications (credential stuffing)
    auth_fail_limit_per_minute: int = 20
    # Plugin HMAC secret (env or data_dir/plugin_signing.secret). Never use the legacy default in prod.
    plugin_signing_secret: str | None = None
    # Master key for at-rest encryption (LLM API keys). Or data_dir/secrets.key.
    secrets_key: str | None = None
    # Reverse-shell auto-stabilization (stage-2 reconnect agents)
    shell_auto_stabilize: bool = True
    # Host/IP implants should call back to (defaults to request/local bind if empty)
    public_host: str = ""
    public_ip: str = ""  # A-record for OAST DNS answers (SQUIDC5_PUBLIC_IP)
    shell_stabilize_delay_sec: float = 0.8
    shell_probe_wait_sec: float = 1.5
    # OAST Collaborator (SQUIDC5_OAST_*)
    oast_enabled: bool = True
    oast_zone: str = "oast.lab.invalid"
    oast_http_port: int = 80
    oast_rate_limit_per_minute: int = 120
    # Hardened defaults
    expose_health_details: bool = False
    security_headers: bool = True
    # TLS: unique self-signed cert under data_dir/tls/ (ops UI, API, MCP)
    tls_enabled: bool = True
    tls_cert_file: Path | None = None  # override paths if set (both must be set)
    tls_key_file: Path | None = None
    tls_force_new: bool = False  # regenerate cert/key on next start

    def resolve_db_path(self) -> Path:
        if self.db_path is not None:
            return self.db_path
        return self.data_dir / "squidc5.db"


@lru_cache
def get_settings() -> Settings:
    return Settings()
