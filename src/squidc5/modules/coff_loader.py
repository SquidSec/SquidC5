"""Minimal COFF/BOF metadata loader (lab). Does not execute untrusted code in CI.

Full Windows COFF execution runs only inside sc5beacon when SC5_ALLOW_BOF=1.
This module validates object headers and returns a run plan for the agent.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

# COFF file header (IMAGE_FILE_HEADER) — 20 bytes
# Machine, NumberOfSections, TimeDateStamp, PointerToSymbolTable,
# NumberOfSymbols, SizeOfOptionalHeader, Characteristics


def parse_coff_header(data: bytes) -> dict[str, Any]:
    if len(data) < 20:
        raise ValueError("COFF too small")
    (
        machine,
        nsections,
        ts,
        symptr,
        nsyms,
        opt_sz,
        chars,
    ) = struct.unpack_from("<HHIIIHH", data, 0)
    machines = {
        0x14C: "i386",
        0x8664: "amd64",
        0x1C0: "arm",
        0xAA64: "arm64",
    }
    return {
        "machine": hex(machine),
        "arch": machines.get(machine, "unknown"),
        "sections": nsections,
        "symbols": nsyms,
        "characteristics": hex(chars),
        "timestamp": ts,
        "symtab_ptr": symptr,
        "optional_header_size": opt_sz,
        "valid_header": True,
    }


def plan_bof_run(
    *,
    module_id: str,
    object_path: Path | None = None,
    object_b64: str | None = None,
    entry: str = "go",
) -> dict[str, Any]:
    """Build agent task args for bof:run (agent performs load when allowed)."""
    meta: dict[str, Any] = {
        "module_id": module_id,
        "entry": entry,
        "requires_env": "SC5_ALLOW_BOF=1",
        "note": "Authorized lab only — agent refuses without SC5_ALLOW_BOF",
    }
    if object_path and object_path.is_file():
        raw = object_path.read_bytes()
        try:
            meta["coff"] = parse_coff_header(raw)
        except ValueError as e:
            meta["coff_error"] = str(e)
        meta["size"] = len(raw)
        meta["sha256_prefix"] = __import__("hashlib").sha256(raw).hexdigest()[:16]
    if object_b64:
        meta["object_b64"] = object_b64
        meta["has_payload"] = True
    return {
        "command": "bof:run",
        "args": meta,
    }
