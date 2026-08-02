"""Per-instance self-signed TLS certificate generation and paths."""

from __future__ import annotations

import ipaddress
import logging
import secrets
import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

log = logging.getLogger("squidc5.tls")

CERT_DIRNAME = "tls"
CERT_FILENAME = "server.crt"
KEY_FILENAME = "server.key"
INSTANCE_ID_FILENAME = "instance_id"


def tls_material_paths(data_dir: Path) -> tuple[Path, Path]:
    """Return (cert_path, key_path) under data_dir/tls/."""
    base = Path(data_dir) / CERT_DIRNAME
    return base / CERT_FILENAME, base / KEY_FILENAME


def _instance_id(tls_dir: Path) -> str:
    path = tls_dir / INSTANCE_ID_FILENAME
    if path.is_file():
        existing = path.read_text(encoding="utf-8").strip()
        if existing:
            return existing
    iid = secrets.token_hex(8)
    path.write_text(iid + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return iid


def _san_entries(public_host: str, extra_hosts: list[str] | None = None) -> list[x509.GeneralName]:
    names: list[x509.GeneralName] = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv6Address("::1")),
    ]
    seen: set[str] = {"localhost", "127.0.0.1", "::1"}

    def add_host(raw: str) -> None:
        h = (raw or "").strip()
        if not h or h in seen:
            return
        seen.add(h)
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(h)))
            return
        except ValueError:
            pass
        # Strip scheme/port if operator pasted a URL
        if "://" in h:
            h = h.split("://", 1)[1]
        h = h.split("/", 1)[0].split(":", 1)[0]
        if not h or h in seen:
            return
        seen.add(h)
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError:
            names.append(x509.DNSName(h))

    add_host(public_host)
    for h in extra_hosts or []:
        add_host(h)
    try:
        add_host(socket.gethostname())
    except OSError:
        pass
    return names


def generate_self_signed(
    cert_path: Path,
    key_path: Path,
    *,
    public_host: str = "",
    instance_id: str = "",
    days: int = 825,
) -> None:
    """Write a new unique self-signed server certificate and private key."""
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    iid = instance_id or secrets.token_hex(8)
    cn = f"squidc5-{iid}"
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SquidC5 Instance"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(_san_entries(public_host)),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
    )
    cert = builder.sign(private_key=key, algorithm=hashes.SHA256())

    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    key_path.write_bytes(key_bytes)
    cert_path.write_bytes(cert_bytes)
    try:
        key_path.chmod(0o600)
        cert_path.chmod(0o644)
    except OSError:
        pass


def ensure_instance_tls(
    data_dir: Path,
    *,
    public_host: str = "",
    force_new: bool = False,
) -> tuple[Path, Path, bool]:
    """
    Ensure data_dir/tls/server.crt + server.key exist.

    Returns (cert_path, key_path, created) where created is True if newly generated.
    Each new instance gets a unique cert (random serial + CN/instance id).
    """
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    tls_dir = data_dir / CERT_DIRNAME
    tls_dir.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = tls_material_paths(data_dir)
    iid = _instance_id(tls_dir)

    if not force_new and cert_path.is_file() and key_path.is_file():
        if cert_path.stat().st_size > 0 and key_path.stat().st_size > 0:
            return cert_path, key_path, False

    generate_self_signed(
        cert_path,
        key_path,
        public_host=public_host or "",
        instance_id=iid,
    )
    log.warning(
        "Generated unique instance TLS certificate -> %s (self-signed; browsers will warn)",
        cert_path,
    )
    return cert_path, key_path, True
