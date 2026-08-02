"""Classify inbound reverse-shell traffic vs scanners / false positives."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Classification:
    is_shell: bool
    reason: str
    confidence: float


# TLS ClientHello / Handshake
_TLS_RE = re.compile(rb"^\x16\x03[\x00-\x03]")
# HTTP(S) probes
_HTTP_RE = re.compile(
    rb"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|CONNECT|PATCH|PRI)[\s/]",
    re.I,
)
# SSH scanners hitting wrong port
_SSH_RE = re.compile(rb"^SSH-")
# Common proxy/VPN binary handshakes
_BINARY_MAGIC = (
    b"\x00\x00",  # often empty length frames
)

# Printable-ish shell / stage2 markers
_SHELL_MARKERS = (
    b"SC5_STABLE",
    b"SC5_OS=",
    b"bash",
    b"sh-",
    b"uid=",
    b"$ ",
    b"# ",
    b"PS ",
    b"Microsoft Windows",
    b"whoami",
    b"Linux",
)


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 1.0
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data)


def classify_inbound(data: bytes | str, *, min_bytes: int = 1) -> Classification:
    """
    Return whether inbound bytes look like a real reverse shell vs scanner noise.

    TLS ClientHello on 443 (e.g. mass scanners, SNI to random hosts) is the
    common false positive - reject immediately.
    """
    if isinstance(data, str):
        raw = data.encode("utf-8", errors="surrogateescape")
    else:
        raw = data

    if not raw:
        # No data yet - indeterminate; treat as potential shell (wait for probe)
        return Classification(True, "no_data_yet", 0.3)

    sample = raw[:512]

    if _TLS_RE.search(sample):
        return Classification(False, "tls_handshake", 0.99)
    if sample[:3] == b"\x16\x03\x01" or sample[:3] == b"\x16\x03\x02" or sample[:3] == b"\x16\x03\x03":
        return Classification(False, "tls_clienthello", 0.99)
    if _HTTP_RE.search(sample):
        return Classification(False, "http_probe", 0.95)
    if _SSH_RE.search(sample):
        return Classification(False, "ssh_banner", 0.9)
    # DTLS / SSL2 legacy
    if sample[0:1] == b"\x80" and len(sample) > 2:
        return Classification(False, "ssl2_or_binary", 0.7)

    # High binary content without shell markers = scanner / protocol mismatch
    ratio = _printable_ratio(sample)
    has_marker = any(m.lower() in sample.lower() for m in _SHELL_MARKERS)
    if has_marker:
        return Classification(True, "shell_marker", 0.95)

    if ratio < 0.55 and len(sample) >= 16:
        return Classification(False, "binary_noise", 0.85)

    # Null-heavy
    if sample.count(0) > max(4, len(sample) // 5):
        return Classification(False, "null_bytes", 0.8)

    # Looks mostly text - likely interactive shell or OS probe response
    if ratio >= 0.7:
        return Classification(True, "printable_text", 0.7)

    if len(sample) < min_bytes:
        return Classification(True, "short_indeterminate", 0.4)

    return Classification(False, "unrecognized_binary", 0.6)
