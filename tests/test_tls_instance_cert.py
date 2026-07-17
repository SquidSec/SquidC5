"""Per-instance TLS certificate generation."""

from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from squidc5.tls.certs import ensure_instance_tls, generate_self_signed, tls_material_paths


def test_tls_paths(tmp_path: Path) -> None:
    cert, key = tls_material_paths(tmp_path)
    assert cert.name == "server.crt"
    assert key.name == "server.key"
    assert cert.parent == tmp_path / "tls"


def test_generate_unique_certs(tmp_path: Path) -> None:
    c1, k1 = tmp_path / "a.crt", tmp_path / "a.key"
    c2, k2 = tmp_path / "b.crt", tmp_path / "b.key"
    generate_self_signed(c1, k1, public_host="10.0.0.5", instance_id="aaaa")
    generate_self_signed(c2, k2, public_host="10.0.0.5", instance_id="bbbb")
    assert c1.read_bytes() != c2.read_bytes()
    assert k1.read_bytes() != k2.read_bytes()

    cert1 = x509.load_pem_x509_certificate(c1.read_bytes())
    cert2 = x509.load_pem_x509_certificate(c2.read_bytes())
    assert cert1.serial_number != cert2.serial_number
    cn1 = cert1.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    cn2 = cert2.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    assert "aaaa" in str(cn1)
    assert "bbbb" in str(cn2)

    san = cert1.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns = san.get_values_for_type(x509.DNSName)
    ips = [str(i) for i in san.get_values_for_type(x509.IPAddress)]
    assert "localhost" in dns
    assert "127.0.0.1" in ips
    assert "10.0.0.5" in ips


def test_ensure_instance_tls_idempotent(tmp_path: Path) -> None:
    data = tmp_path / "data"
    cert, key, created = ensure_instance_tls(data, public_host="c2.lab")
    assert created is True
    assert cert.is_file() and key.is_file()
    body1 = cert.read_bytes()

    cert2, key2, created2 = ensure_instance_tls(data, public_host="c2.lab")
    assert created2 is False
    assert cert2 == cert and key2 == key
    assert cert.read_bytes() == body1

    _, _, created3 = ensure_instance_tls(data, force_new=True)
    assert created3 is True
    assert cert.read_bytes() != body1


def test_key_is_private(tmp_path: Path) -> None:
    cert, key, _ = ensure_instance_tls(tmp_path / "d")
    serialization.load_pem_private_key(key.read_bytes(), password=None)
    x509.load_pem_x509_certificate(cert.read_bytes())
