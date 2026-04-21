"""Release and upgrade policy metadata."""

from __future__ import annotations

from typing import Any


def build_upgrade_policy_contract() -> dict[str, Any]:
    return {
        "contract_version": "2026-03-08",
        "versioning": {
            "api": "semantic-versioning",
            "db_schema": "forward-compatible migrations; avoid destructive changes in minors",
            "worker_compatibility": "workers must remain compatible across one minor API upgrade",
        },
        "upgrade_order": [
            "Run DB migrations",
            "Upgrade API deployment",
            "Upgrade asynchronous workers",
            "Upgrade correlator/notifier services",
            "Run post-upgrade smoke checks",
        ],
        "rollback_policy": {
            "safe_rollback": [
                "API and workers can roll back within the same schema-compatible release window",
            ],
            "forward_fix_required": [
                "Irreversible schema/data migrations require forward fixes",
            ],
        },
    }
