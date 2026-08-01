"""Optional structured JSON logging."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        # Never attach common secret-like extras if present
        for key in ("token", "api_key", "password", "authorization"):
            if hasattr(record, key):
                payload[key] = "[redacted]"
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(*, json_logs: bool = False, debug: bool = False) -> None:
    root = logging.getLogger()
    level = logging.DEBUG if debug else logging.INFO
    # Reset handlers for idempotent test/app start
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    if json_logs:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
        )
    root.addHandler(handler)
    root.setLevel(level)
