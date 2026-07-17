"""Beacon / session anomaly suggestions (deterministic heuristics)."""

from __future__ import annotations

from typing import Any


def analyze_beacon_behavior(sessions: list[dict[str, Any]], metrics: dict[str, float] | None = None) -> dict[str, Any]:
    """Return anomaly flags and remediation suggestions for operators."""
    metrics = metrics or {}
    findings: list[dict[str, str]] = []
    active = [s for s in sessions if (s.get("status") or "") == "active"]
    beacons = [s for s in active if (s.get("kind") or "") == "beacon"]
    shells = [s for s in active if (s.get("kind") or "") in ("reverse_shell", "tcp")]

    if len(beacons) > 50:
        findings.append(
            {
                "severity": "medium",
                "code": "beacon_volume",
                "detail": f"{len(beacons)} active beacons — consider reaping stale hosts",
                "suggest": "Run sessions reap; tighten sleep/jitter profiles",
            }
        )
    unverified = [s for s in shells if not s.get("verified")]
    if unverified:
        findings.append(
            {
                "severity": "high",
                "code": "unverified_shells",
                "detail": f"{len(unverified)} reverse shells not verified",
                "suggest": "Enable exec probe; drop echo-only sessions",
            }
        )
    false_pos = float(metrics.get("shell.false_positive") or 0)
    if false_pos > 20:
        findings.append(
            {
                "severity": "low",
                "code": "noise_listeners",
                "detail": f"High false-shell count ({int(false_pos)})",
                "suggest": "Move reverse-shell ports off common scanner targets; keep false_shell_filter on",
            }
        )
    if not findings:
        findings.append(
            {
                "severity": "info",
                "code": "nominal",
                "detail": "No heuristic anomalies",
                "suggest": "Continue monitoring timeline and heatmap",
            }
        )
    return {
        "active_sessions": len(active),
        "beacons": len(beacons),
        "shells": len(shells),
        "findings": findings,
    }
