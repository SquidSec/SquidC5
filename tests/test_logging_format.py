"""JSON structured logging (B06)."""

from __future__ import annotations

import json
import logging

from squidc5.logging_setup import JsonFormatter, configure_logging


def test_json_formatter_parses():
    fmt = JsonFormatter()
    record = logging.LogRecord(
        name="squidc5.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello %s",
        args=("world",),
        exc_info=None,
    )
    line = fmt.format(record)
    data = json.loads(line)
    assert data["msg"] == "hello world"
    assert data["level"] == "INFO"
    assert data["logger"] == "squidc5.test"
    assert "ts" in data


def test_json_formatter_redacts_token_attr():
    fmt = JsonFormatter()
    record = logging.LogRecord(
        name="squidc5.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="auth event",
        args=(),
        exc_info=None,
    )
    record.token = "sc5_should_not_leak"  # type: ignore[attr-defined]
    data = json.loads(fmt.format(record))
    assert data["token"] == "[redacted]"


def test_configure_logging_json_mode():
    configure_logging(json_logs=True, debug=False)
    root = logging.getLogger()
    assert root.handlers
    assert isinstance(root.handlers[0].formatter, JsonFormatter)
