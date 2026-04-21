from __future__ import annotations

from app import ai_client
from app.settings import settings


def test_redaction_scrubs_sensitive_prompt_tokens():
    raw = (
        "token=abc12345SECRET67890 "
        "password=supersecret "
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "
        "api_key=sk-1234567890abcdefghijklmnopqrstuvwxyz"
    )
    redacted, count = ai_client._redact_prompt(raw)
    assert count >= 3
    assert "supersecret" not in redacted
    assert "sk-1234567890abcdefghijklmnopqrstuvwxyz" not in redacted
    assert "[REDACTED" in redacted


def test_generate_text_sanitizes_before_provider_call(monkeypatch):
    captured: dict[str, str] = {}
    monkeypatch.setattr(ai_client, "ai_enabled", lambda: True)
    monkeypatch.setattr(ai_client, "_provider_name", lambda: "openai")
    monkeypatch.setattr(ai_client, "model_name", lambda: "unit-test-model")
    monkeypatch.setattr(settings, "AI_PROMPT_MAX_CHARS", 120)
    monkeypatch.setattr(settings, "AI_PROMPT_REDACTION_ENABLED", True)

    def _fake_openai(*, system_prompt: str, user_prompt: str, **_kwargs):
        captured["system_prompt"] = system_prompt
        captured["user_prompt"] = user_prompt
        return "ok"

    monkeypatch.setattr(ai_client, "_generate_openai", _fake_openai)
    out = ai_client.generate_text(
        system_prompt="system password=supersecret",
        user_prompt="api_key=sk-1234567890abcdefghijklmnopqrstuvwxyz",
        max_tokens=20,
    )
    assert out == "ok"
    assert "supersecret" not in captured["system_prompt"]
    assert "sk-1234567890abcdefghijklmnopqrstuvwxyz" not in captured["user_prompt"]
    assert "[REDACTED" in captured["system_prompt"] + captured["user_prompt"]
