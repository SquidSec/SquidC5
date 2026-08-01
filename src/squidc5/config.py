"""Application configuration — env-driven, minimal footprint."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator, model_validator
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
    # Local LLM (Ollama-compatible) — only when explicitly enabled
    local_llm_enabled: bool = False
    local_llm_base_url: str = "http://127.0.0.1:11434/v1"
    local_llm_model: str = "llama3.2"
    audit_retention_days: int = 90
    rate_limit_per_minute: int = 60
    # Stricter per-IP cap on failed authentications (credential stuffing)
    auth_fail_limit_per_minute: int = 20
    # Plugin HMAC secret (env or data_dir/plugin_signing.secret). Never use the legacy default in prod.
    plugin_signing_secret: str | None = None
    # Master key for at-rest encryption (LLM API keys). Or data_dir/secrets.key.
    secrets_key: str | None = None
    # Implant beacon AEAD (ChaCha20-Poly1305). PSK auto-generated under data/implant_psk.txt
    implant_psk: str | None = None
    implant_require_auth: bool = True
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
    log_json: bool = False
    # TLS: unique self-signed cert under data_dir/tls/ (ops UI, API, MCP)
    tls_enabled: bool = True
    tls_cert_file: Path | None = None  # override paths if set (both must be set)
    tls_key_file: Path | None = None
    tls_force_new: bool = False  # regenerate cert/key on next start

    @field_validator("port", "default_listener_port", "oast_http_port")
    @classmethod
    def _port_range(cls, v: int) -> int:
        if not 1 <= int(v) <= 65535:
            raise ValueError("port must be 1-65535")
        return int(v)

    @field_validator("max_body_bytes", "rate_limit_per_minute", "auth_fail_limit_per_minute")
    @classmethod
    def _non_negative(cls, v: int) -> int:
        if int(v) < 0:
            raise ValueError("must be >= 0")
        return int(v)

    @model_validator(mode="after")
    def _cross_field(self) -> Settings:
        cert = self.tls_cert_file
        key = self.tls_key_file
        if (cert is None) ^ (key is None):
            raise ValueError("SQUIDC5_TLS_CERT_FILE and SQUIDC5_TLS_KEY_FILE must both be set or both unset")
        if self.tls_enabled and cert is not None and key is not None:
            if not Path(cert).is_file():
                raise ValueError(f"TLS cert file not found: {cert}")
            if not Path(key).is_file():
                raise ValueError(f"TLS key file not found: {key}")
        if self.shell_auto_stabilize and not (self.public_host or "").strip() and not self.debug:
            # Warn-level only at runtime; hard fail would break many lab installs.
            # Production operators should set public_host — enforced as soft check in validate().
            pass
        if self.audit_retention_days < 1:
            raise ValueError("audit_retention_days must be >= 1")
        return self

    def resolve_db_path(self) -> Path:
        if self.db_path is not None:
            return self.db_path
        return self.data_dir / "squidc5.db"

    def validate_runtime(self) -> list[str]:
        """Extra runtime checks. Returns warnings; raises ValueError on hard errors."""
        warnings: list[str] = []
        if self.shell_auto_stabilize and not (self.public_host or "").strip():
            warnings.append(
                "SQUIDC5_PUBLIC_HOST is empty while shell_auto_stabilize is on — "
                "stage-2 implants may reconnect to the wrong host"
            )
        if self.tls_enabled and self.tls_cert_file and self.tls_key_file:
            if not Path(self.tls_cert_file).is_file() or not Path(self.tls_key_file).is_file():
                raise ValueError("TLS cert/key pair missing on disk")
        return warnings


@lru_cache
def get_settings() -> Settings:
    return Settings()
