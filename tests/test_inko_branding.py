"""INKO (Intelligent Neural Kinetic Operator) branding in chat system prompt."""

from squidc5.ai.ops_tools import CHAT_SYSTEM_PROMPT


def test_chat_system_prompt_uses_inko_name() -> None:
    assert "INKO" in CHAT_SYSTEM_PROMPT
    assert "Intelligent Neural Kinetic Operator" in CHAT_SYSTEM_PROMPT
    assert "use the name INKO" in CHAT_SYSTEM_PROMPT


def test_chat_system_prompt_does_not_use_legacy_ink_alone() -> None:
    # Avoid regressing to short brand "INK" as the operator name.
    assert "You are INK " not in CHAT_SYSTEM_PROMPT
    assert "name INK." not in CHAT_SYSTEM_PROMPT
