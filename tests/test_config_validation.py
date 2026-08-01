"""Startup config validation (B08)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from squidc5.config import Settings


def test_port_out_of_range():
    with pytest.raises(ValidationError):
        Settings(port=0)
    with pytest.raises(ValidationError):
        Settings(port=70000)


def test_tls_pair_must_be_both_or_neither(tmp_path: Path):
    cert = tmp_path / "c.pem"
    cert.write_text("x", encoding="utf-8")
    with pytest.raises(ValidationError, match="both"):
        Settings(tls_cert_file=cert, tls_key_file=None)
    with pytest.raises(ValidationError, match="both"):
        Settings(tls_cert_file=None, tls_key_file=tmp_path / "k.pem")


def test_tls_files_must_exist_when_set(tmp_path: Path):
    with pytest.raises(ValidationError, match="not found"):
        Settings(
            tls_enabled=True,
            tls_cert_file=tmp_path / "missing.crt",
            tls_key_file=tmp_path / "missing.key",
        )


def test_tls_pair_ok_when_files_exist(tmp_path: Path):
    c = tmp_path / "server.crt"
    k = tmp_path / "server.key"
    c.write_text("cert", encoding="utf-8")
    k.write_text("key", encoding="utf-8")
    s = Settings(tls_enabled=True, tls_cert_file=c, tls_key_file=k, debug=True)
    assert s.tls_cert_file == c
    assert s.validate_runtime()  # may warn about public_host


def test_negative_rate_limit_rejected():
    with pytest.raises(ValidationError):
        Settings(rate_limit_per_minute=-1)


def test_audit_retention_min():
    with pytest.raises(ValidationError):
        Settings(audit_retention_days=0)


def test_public_host_warning_when_stabilize(tmp_path: Path):
    s = Settings(
        data_dir=tmp_path,
        shell_auto_stabilize=True,
        public_host="",
        debug=True,
    )
    warns = s.validate_runtime()
    assert any("PUBLIC_HOST" in w for w in warns)
