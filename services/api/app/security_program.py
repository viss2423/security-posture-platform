"""Security program metadata used by disclosure and trust endpoints."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from .settings import settings

PLACEHOLDER_MARKERS = ("secplat.local", ".local", ".invalid", "example.com")


def _looks_placeholder(value: str | None) -> bool:
    lowered = str(value or "").strip().lower()
    if not lowered:
        return True
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def build_security_program() -> dict[str, Any]:
    return {
        "security_frameworks": [
            {
                "name": "NIST SSDF (SP 800-218)",
                "purpose": "Secure SDLC baseline",
                "adoption": "active",
            },
            {
                "name": "OWASP SAMM",
                "purpose": "Maturity tracking",
                "adoption": "active",
            },
            {
                "name": "OWASP ASVS",
                "purpose": "Verification requirements",
                "adoption": "active",
            },
            {
                "name": "OWASP API Security Top 10 (2023)",
                "purpose": "API threat modeling and tests",
                "adoption": "active",
            },
        ],
        "vulnerability_disclosure": {
            "security_txt": "/.well-known/security.txt",
            "contact_email": settings.SECURITY_CONTACT_EMAIL,
            "contact_url": str(getattr(settings, "SECURITY_CONTACT_URL", "") or "").strip() or None,
            "policy_url": settings.SECURITY_POLICY_URL,
            "report_endpoint": str(
                getattr(settings, "SECURITY_REPORT_INTAKE_PATH", "") or ""
            ).strip()
            or "/security/report",
            "configured": not _looks_placeholder(settings.SECURITY_CONTACT_EMAIL)
            and not _looks_placeholder(settings.SECURITY_POLICY_URL),
            "intake_sla_hours": 24,
            "triage_sla_business_days": 3,
            "status_update_cadence_days": 7,
        },
        "verification_focus": [
            "authorization object-path checks",
            "token lifecycle and session management",
            "secure configuration and defaults",
            "audit log integrity",
            "admin/dangerous action approvals",
        ],
    }


def render_security_txt(*, canonical_base: str) -> str:
    base = (canonical_base or "").rstrip("/")
    expires_at = datetime.now(UTC) + timedelta(days=max(7, int(settings.SECURITY_TTL_DAYS)))
    lines = [
        f"Contact: mailto:{settings.SECURITY_CONTACT_EMAIL}",
        f"Expires: {expires_at.isoformat().replace('+00:00', 'Z')}",
        "Preferred-Languages: en",
        f"Canonical: {base}/.well-known/security.txt",
        f"Policy: {settings.SECURITY_POLICY_URL}",
    ]
    contact_url = str(getattr(settings, "SECURITY_CONTACT_URL", "") or "").strip()
    if contact_url:
        lines.append(f"Contact: {contact_url}")
    return "\n".join(lines) + "\n"
