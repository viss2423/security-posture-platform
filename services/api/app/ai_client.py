"""AI provider client for SecPlat enrichment features."""

from __future__ import annotations

import json
import re

import httpx

from app.otel import start_span
from app.settings import settings


class AIClientError(RuntimeError):
    """Raised when AI generation is unavailable or fails."""


_PROMPT_REDACTION_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.IGNORECASE | re.DOTALL,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}"), "Bearer [REDACTED_TOKEN]"),
    (
        re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*[^\s,;]+"),
        r"\1=[REDACTED_SECRET]",
    ),
    (
        re.compile(r"(?i)\b(api[_\-]?key|secret|token)\s*[:=]\s*[^\s,;]+"),
        r"\1=[REDACTED_SECRET]",
    ),
)


def _provider_name() -> str:
    return (getattr(settings, "AI_PROVIDER", "ollama") or "ollama").strip().lower()


def ai_enabled() -> bool:
    return bool(getattr(settings, "AI_ENABLED", False))


def model_name() -> str:
    provider = _provider_name()
    if provider == "openai":
        return str(getattr(settings, "OPENAI_MODEL", "gpt-4.1-mini"))
    return str(getattr(settings, "OLLAMA_MODEL", "llama3.1:8b"))


def provider_name() -> str:
    return _provider_name()


def _truncate_prompt(value: str) -> str:
    max_chars = max(256, int(getattr(settings, "AI_PROMPT_MAX_CHARS", 12000) or 12000))
    return str(value or "")[:max_chars]


def _redact_prompt(value: str) -> tuple[str, int]:
    if not bool(getattr(settings, "AI_PROMPT_REDACTION_ENABLED", True)):
        return value, 0
    redacted = str(value or "")
    replacements = 0
    for pattern, replacement in _PROMPT_REDACTION_PATTERNS:
        redacted, count = pattern.subn(replacement, redacted)
        replacements += count
    return redacted, replacements


def _sanitize_prompts(system_prompt: str, user_prompt: str) -> tuple[str, str, int]:
    system_text = _truncate_prompt(system_prompt)
    user_text = _truncate_prompt(user_prompt)
    system_sanitized, system_redactions = _redact_prompt(system_text)
    user_sanitized, user_redactions = _redact_prompt(user_text)
    return system_sanitized, user_sanitized, int(system_redactions + user_redactions)


def generate_text(
    *,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 500,
    timeout_seconds: float | None = None,
) -> str:
    """Generate text from configured provider."""
    if not ai_enabled():
        raise AIClientError("ai_disabled")
    provider = _provider_name()
    safe_system_prompt, safe_user_prompt, redaction_count = _sanitize_prompts(
        system_prompt, user_prompt
    )
    with start_span(
        "gen_ai.request",
        attributes={
            "gen_ai.system": provider,
            "gen_ai.request.model": model_name(),
            "gen_ai.request.max_tokens": int(max_tokens),
            "gen_ai.prompt.redactions": redaction_count,
            "gen_ai.prompt.system_chars": len(safe_system_prompt),
            "gen_ai.prompt.user_chars": len(safe_user_prompt),
        },
    ) as span:
        if provider == "openai":
            out = _generate_openai(
                system_prompt=safe_system_prompt,
                user_prompt=safe_user_prompt,
                max_tokens=max_tokens,
                timeout_seconds=timeout_seconds,
            )
            span.set_attribute("gen_ai.response.provider", "openai")
            return out
        if provider == "ollama":
            out = _generate_ollama(
                system_prompt=safe_system_prompt,
                user_prompt=safe_user_prompt,
                max_tokens=max_tokens,
                timeout_seconds=timeout_seconds,
            )
            span.set_attribute("gen_ai.response.provider", "ollama")
            return out
        raise AIClientError(f"unsupported_ai_provider:{provider}")


def _generate_ollama(
    *,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int,
    timeout_seconds: float | None = None,
) -> str:
    base = (
        (getattr(settings, "OLLAMA_BASE_URL", "http://localhost:11434") or "").strip().rstrip("/")
    )
    model = model_name()
    if not base:
        raise AIClientError("ollama_base_url_missing")
    payload = {
        "model": model,
        "prompt": f"{system_prompt.strip()}\n\n{user_prompt.strip()}",
        "stream": False,
        "options": {
            "temperature": float(getattr(settings, "AI_TEMPERATURE", 0.2)),
            "num_predict": max(64, max_tokens),
        },
    }
    keep_alive = getattr(settings, "OLLAMA_KEEP_ALIVE", None)
    if keep_alive:
        payload["keep_alive"] = keep_alive
    timeout = (
        float(timeout_seconds)
        if timeout_seconds is not None
        else float(getattr(settings, "AI_TIMEOUT_SECONDS", 60))
    )
    try:
        with httpx.Client(timeout=timeout) as client:
            r = client.post(f"{base}/api/generate", json=payload)
            r.raise_for_status()
            data = r.json()
    except httpx.HTTPStatusError as e:
        msg = (e.response.text or "").strip() if e.response is not None else str(e)
        raise AIClientError(f"ollama_http_error:{msg[:300]}") from e
    except Exception as e:
        raise AIClientError(f"ollama_request_failed:{e}") from e
    out = (data.get("response") or "").strip() if isinstance(data, dict) else ""
    if not out:
        raise AIClientError("ollama_empty_response")
    return out


def _generate_openai(
    *,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int,
    timeout_seconds: float | None = None,
) -> str:
    api_key = (getattr(settings, "OPENAI_API_KEY", None) or "").strip()
    if not api_key:
        raise AIClientError("openai_api_key_missing")
    model = model_name()
    base = (
        (getattr(settings, "OPENAI_BASE_URL", "https://api.openai.com/v1") or "")
        .strip()
        .rstrip("/")
    )
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt.strip()},
            {"role": "user", "content": user_prompt.strip()},
        ],
        "temperature": float(getattr(settings, "AI_TEMPERATURE", 0.2)),
        "max_tokens": max(64, max_tokens),
    }
    timeout = (
        float(timeout_seconds)
        if timeout_seconds is not None
        else float(getattr(settings, "AI_TIMEOUT_SECONDS", 60))
    )
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    try:
        with httpx.Client(timeout=timeout) as client:
            r = client.post(f"{base}/chat/completions", headers=headers, json=payload)
            r.raise_for_status()
            data = r.json()
    except httpx.HTTPStatusError as e:
        msg = (e.response.text or "").strip() if e.response is not None else str(e)
        raise AIClientError(f"openai_http_error:{msg[:300]}") from e
    except Exception as e:
        raise AIClientError(f"openai_request_failed:{e}") from e

    content = _extract_openai_content(data)
    if not content:
        raise AIClientError("openai_empty_response")
    return content


def _extract_openai_content(data: object) -> str:
    if not isinstance(data, dict):
        return ""
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    first = choices[0]
    if not isinstance(first, dict):
        return ""
    msg = first.get("message")
    if not isinstance(msg, dict):
        return ""
    content = msg.get("content")
    if isinstance(content, str):
        return content.strip()
    # Newer APIs may return a structured array for content.
    if isinstance(content, list):
        chunks: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text_part = item.get("text")
                if isinstance(text_part, str):
                    chunks.append(text_part)
        return "\n".join(chunks).strip()
    return ""


def compact_json(value: object, *, max_chars: int = 8000) -> str:
    """Stable, size-limited JSON for prompts."""
    try:
        raw = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    except Exception:
        raw = str(value)
    return raw[: max(256, int(max_chars))]
