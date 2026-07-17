"""Policy-railed Admin AI task chaining (deterministic, max steps, HITL-aware)."""

from __future__ import annotations

from typing import Any

from squidc5.ai.admin_ai import ALLOWED_CAPABILITIES, sanitize_untrusted

# Fixed playbooks only — no free-form agent planning
PLAYBOOKS: dict[str, list[dict[str, str]]] = {
    "recon_then_classify": [
        {"capability": "recon_assist", "input_from": "user"},
        {"capability": "shell_classify", "input_from": "prev_result"},
    ],
    "payload_then_recon": [
        {"capability": "payload_template", "input_from": "user"},
        {"capability": "recon_assist", "input_from": "user"},
    ],
    "doc_outline": [
        {"capability": "doc_generate", "input_from": "user"},
    ],
}


class AIChainRunner:
    """Runs allow-listed playbooks with max_steps and sanitization."""

    def __init__(self, admin_ai: Any, max_steps: int = 3) -> None:
        self.admin_ai = admin_ai
        self.max_steps = max_steps

    def list_playbooks(self) -> list[dict[str, Any]]:
        return [
            {"id": k, "steps": [s["capability"] for s in v], "length": len(v)}
            for k, v in PLAYBOOKS.items()
        ]

    async def run(
        self,
        playbook_id: str,
        user_data: str,
        actor: str = "admin",
        llm_id: str | None = None,
        max_steps: int | None = None,
    ) -> dict[str, Any]:
        steps = PLAYBOOKS.get(playbook_id)
        if not steps:
            raise ValueError(f"Unknown playbook: {playbook_id}. Allowed: {list(PLAYBOOKS)}")
        limit = min(max_steps or self.max_steps, self.max_steps, len(steps))
        safe = sanitize_untrusted(user_data, max_chars=512)
        results: list[dict[str, Any]] = []
        prev: Any = safe
        for i, step in enumerate(steps[:limit]):
            cap = step["capability"]
            if cap not in ALLOWED_CAPABILITIES:
                raise ValueError(f"Playbook step capability not allowed: {cap}")
            inp = safe if step.get("input_from") == "user" else (
                json_safe(prev) if step.get("input_from") == "prev_result" else safe
            )
            out = await self.admin_ai.run(
                capability=cap,
                user_data=str(inp)[:512],
                actor=actor,
                llm_id=llm_id,
            )
            results.append({"step": i + 1, "capability": cap, "result": out.get("result"), "mode": out.get("mode")})
            prev = out.get("result")
        return {
            "playbook": playbook_id,
            "steps_run": len(results),
            "max_steps": limit,
            "results": results,
            "mode": "chained",
        }


def json_safe(obj: Any) -> str:
    import json

    try:
        return json.dumps(obj, default=str)[:512]
    except Exception:
        return str(obj)[:512]
