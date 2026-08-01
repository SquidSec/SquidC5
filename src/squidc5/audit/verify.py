"""Verify audit log hash chain integrity."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def compute_chain_hash(
    prev: str,
    ts: float,
    actor: str,
    actor_type: str,
    action: str,
    resource: str | None,
    details: str,
    risk_score: int,
    allowed: int,
) -> str:
    material = (
        f"{prev}|{ts}|{actor}|{actor_type}|{action}|{resource or ''}|"
        f"{details}|{risk_score}|{allowed}"
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def verify_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """rows ordered by id ascending."""
    prev = ""
    checked = 0
    broken_at: int | None = None
    for row in rows:
        details = row.get("details") or "{}"
        if isinstance(details, dict):
            details = json.dumps(details, sort_keys=True, separators=(",", ":"))
        expected_prev = row.get("prev_hash") or ""
        if expected_prev != prev and checked > 0:
            # first row may have empty prev
            if not (checked == 0 and expected_prev == ""):
                broken_at = int(row.get("id") or checked)
                break
        chain = row.get("chain_hash") or ""
        if not chain:
            checked += 1
            prev = chain
            continue
        calc = compute_chain_hash(
            prev if checked > 0 else (expected_prev or ""),
            float(row.get("ts") or 0),
            str(row.get("actor") or ""),
            str(row.get("actor_type") or ""),
            str(row.get("action") or ""),
            row.get("resource"),
            details if isinstance(details, str) else "{}",
            int(row.get("risk_score") or 0),
            int(row.get("allowed") if row.get("allowed") is not None else 1),
        )
        # Prefer stored prev linkage
        calc2 = compute_chain_hash(
            expected_prev,
            float(row.get("ts") or 0),
            str(row.get("actor") or ""),
            str(row.get("actor_type") or ""),
            str(row.get("action") or ""),
            row.get("resource"),
            details if isinstance(details, str) else "{}",
            int(row.get("risk_score") or 0),
            int(row.get("allowed") if row.get("allowed") is not None else 1),
        )
        if chain not in (calc, calc2) and checked > 0:
            broken_at = int(row.get("id") or checked)
            break
        prev = chain
        checked += 1
    return {
        "ok": broken_at is None,
        "checked": checked,
        "broken_at_id": broken_at,
    }
