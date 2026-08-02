"""Verify audit log hash chain integrity (must match db.store.audit insert)."""

from __future__ import annotations

import hashlib
import hmac
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
    """Same formula as Database.audit() - stable float formatting."""
    ts_s = format(float(ts), ".12f")
    material = (
        f"{prev}|{ts_s}|{actor}|{actor_type}|{action}|{resource or ''}|"
        f"{details}|{risk_score}|{allowed}"
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _details_str(row: dict[str, Any]) -> str:
    details = row.get("details")
    if details is None:
        return "{}"
    if isinstance(details, dict):
        return json.dumps(details, sort_keys=True, separators=(",", ":"))
    if isinstance(details, str):
        # Re-canonicalize if possible
        try:
            obj = json.loads(details)
            if isinstance(obj, dict):
                return json.dumps(obj, sort_keys=True, separators=(",", ":"))
        except json.JSONDecodeError:
            pass
        return details
    return "{}"


def verify_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Validate chain_hash using stored prev_hash and sequential linkage.

    rows must be ordered by id ascending.
    """
    checked = 0
    broken_at: int | None = None
    last_chain = ""
    for i, row in enumerate(rows):
        rid = int(row.get("id") or i)
        chain = (row.get("chain_hash") or "").strip()
        prev = (row.get("prev_hash") or "").strip()
        if not chain:
            # legacy rows without chain - skip crypto check but track linkage gap
            checked += 1
            last_chain = ""
            continue
        # Sequential: after first chained row, prev must equal previous chain
        if i > 0 and last_chain and prev != last_chain:
            broken_at = rid
            break
        details = _details_str(row)
        allowed = row.get("allowed")
        if allowed is True:
            allowed_i = 1
        elif allowed is False:
            allowed_i = 0
        else:
            allowed_i = int(allowed if allowed is not None else 1)
        calc = compute_chain_hash(
            prev,
            float(row.get("ts") or 0),
            str(row.get("actor") or ""),
            str(row.get("actor_type") or ""),
            str(row.get("action") or ""),
            row.get("resource"),
            details,
            int(row.get("risk_score") or 0),
            allowed_i,
        )
        if not hmac.compare_digest(calc, chain):
            broken_at = rid
            break
        last_chain = chain
        checked += 1
    return {
        "ok": broken_at is None,
        "checked": checked,
        "broken_at_id": broken_at,
    }
