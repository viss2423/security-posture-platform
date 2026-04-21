"""Customer rollout and support readiness metadata."""

from __future__ import annotations

from typing import Any


def build_readiness_contract() -> dict[str, Any]:
    return {
        "contract_version": "2026-03-08",
        "rollout_stages": ["design-partner", "beta", "general-availability"],
        "support_sla": {
            "sev1": {"initial_response_minutes": 30, "status_update_minutes": 60},
            "sev2": {"initial_response_minutes": 120, "status_update_minutes": 240},
            "sev3": {"initial_response_business_hours": 8, "status_update_business_hours": 24},
        },
        "operational_requirements": [
            "incident runbooks with named owner",
            "postmortem for sev1/sev2 incidents",
            "release gate enforcement via error budgets",
            "backup restore verification evidence",
            "runtime db role posture checks",
        ],
    }
