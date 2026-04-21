"""Optional startup seeding for cyberlab demo data.

This module populates a deterministic, idempotent baseline dataset so the
website shows telemetry, alerts, detections, attack-lab runs, incidents, and
repository findings on a fresh environment.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
from sqlalchemy import text

from .alerts_v2 import upsert_security_alert
from .attack_lab import create_incident_for_alert
from .db import SessionLocal
from .detections import run_detection_rule
from .request_context import tenant_id_ctx
from .risk_scoring import recompute_finding_risk
from .routers.findings import FindingUpsertBody, upsert_finding_record
from .settings import settings
from .telemetry import _read_events_from_file, ingest_telemetry_events, run_network_anomaly_job

logger = logging.getLogger("secplat.demo_seed")

SEED_ACTION = "cyberlab_demo_seed"
SEED_ACTOR = "system-cyberlab-seed"
DEMO_TELEMETRY_EVENT_LIMIT = 500
CURATED_SITE_NOISE_ASSET_PREFIXES = (
    "ai-feedback-",
    "alert-ai-",
    "asset-ai-",
    "as-dst-",
    "as-src-",
    "attack-lab-asset-",
    "auto-plbk-",
    "job-triage-",
    "alert-enrich-",
    "telemetry-asset-",
    "incident-risk-",
    "alert-guardrail-",
    "threat-asset-",
    "rbac-asset-",
    "ai-guardrail-",
    "cowrie-asset-",
    "ai-finding-",
    "repo-summary-",
    "telemetry-lineage-",
    "repo-posture-",
    "det-v2-",
    "corr-asset-",
    "det-sim-",
    "incident-auto-",
    "phase1-observability-",
    "phase3-onboarding-",
    "phase5-release-gate-",
    "phase1-trace",
    "graph-asset-",
    "cyberlab-asset-",
    "debug-alert-",
    "example-com",
    "extweb-k8s-",
    "live-job-triage-",
    "repo-job-",
    "repo-scan-",
    "timeline-asset-",
    "risk-asset-",
    "audit-asset-",
    "repo-dependency-",
    "secplat-repo",
    "threat-campaign-asset-",
    "threat-lab-asset",
    "tmp-shape",
    "tmp-risk",
    "alert-m3",
)
CURATED_SITE_NOISE_INCIDENT_TITLE_PATTERNS = (
    "AI feedback incident %",
    "AI feedback RBAC incident %",
    "Alert incident for alert-ai%",
    "Finding: phase1-%",
    "Guardrail test %",
    "Auto incident:%",
    "Incident with linked risk context%",
    "Link alert test%",
    "Note test incident%",
    "Status test incident%",
    "Idempotent incident%",
    "Test incident from pytest%",
    "Unified timeline incident %",
    "Attack graph incident %",
    "Risk incident %",
    "Automation incident for auto-plbk%",
    "Attack-lab incident: Attack-lab detected open ports on verify-web%",
    "Collaboration endpoint test%",
    "Finding: % on juice-shop",
    "Finding: % on secplat-api",
    "Finding: % on verify-web",
    "Phase 3 incident for %",
    "Audit incident %",
)
CURATED_SITE_NOISE_FINDING_KEY_PATTERNS = (
    "phase1-finding-%",
    "tmp-risk:%",
)
CURATED_SITE_NOISE_FINDING_TITLES = (
    "HTTP request failed",
    "Phase1 Trace Finding",
    "finding to label",
    "rbac finding",
)
CURATED_SITE_NOISE_ALERT_TITLE_PATTERNS = ("Attack-lab detected open ports on verify-web%",)
CURATED_SITE_NOISE_ATTACK_LAB_TARGET_PATTERNS = ("verify-web",)
CURATED_SITE_NOISE_REQUESTED_BY_PATTERNS = (
    "pytest",
    "phase%",
    "manual-phase5-debug%",
    "phase5-maintenance%",
)
CURATED_SITE_NOISE_THREAT_SOURCE_PATTERNS = (
    "abuseipdb-s100-mirror",
    "binary-defense-banlist",
    "ciarmy-badguys",
    "lab-demo",
    "manual-lab",
    "openphish-urls",
    "pytest-%",
    "manual-fix-%",
)
CURATED_SITE_NOISE_CAMPAIGN_PATTERNS = ("pytest-campaign-%",)


def _current_tenant_id(tenant_id: str | None = None) -> str:
    candidate = tenant_id if tenant_id is not None else tenant_id_ctx.get("default")
    normalized = str(candidate or "").strip()
    return normalized or "default"


def _pin_session_tenant(db, tenant_id: str) -> None:
    db.execute(
        text("SELECT set_config('secplat.tenant_id', :tenant_id, false)"),
        {"tenant_id": tenant_id},
    )


def _to_like_patterns(prefixes: tuple[str, ...]) -> list[str]:
    return [value if "%" in value else f"{value}%" for value in prefixes]


def _cleanup_curated_site_noise(
    db,
    *,
    preserve_asset_keys: list[str] | None = None,
) -> dict[str, int]:
    preserve_keys = [
        str(value).strip() for value in (preserve_asset_keys or []) if str(value).strip()
    ]
    asset_patterns = _to_like_patterns(CURATED_SITE_NOISE_ASSET_PREFIXES)
    alert_title_patterns = _to_like_patterns(CURATED_SITE_NOISE_ALERT_TITLE_PATTERNS)
    attack_lab_target_patterns = _to_like_patterns(CURATED_SITE_NOISE_ATTACK_LAB_TARGET_PATTERNS)
    threat_source_patterns = _to_like_patterns(CURATED_SITE_NOISE_THREAT_SOURCE_PATTERNS)
    asset_rows = (
        db.execute(
            text(
                """
                SELECT asset_id, asset_key
                FROM assets
                WHERE asset_key LIKE ANY(CAST(:asset_patterns AS text[]))
                  AND (
                    :preserve_empty
                    OR asset_key <> ALL(CAST(:preserve_asset_keys AS text[]))
                  )
                """
            ),
            {
                "asset_patterns": asset_patterns,
                "preserve_asset_keys": preserve_keys or [""],
                "preserve_empty": len(preserve_keys) == 0,
            },
        )
        .mappings()
        .all()
    )
    asset_ids = [int(row["asset_id"]) for row in asset_rows if row.get("asset_id") is not None]
    asset_keys = [str(row["asset_key"]) for row in asset_rows if row.get("asset_key")]

    incident_id_rows = list(
        db.execute(
            text(
                """
                SELECT DISTINCT ia.incident_id
                FROM incident_alerts ia
                WHERE ia.asset_key = ANY(CAST(:asset_keys AS text[]))
                """
            ),
            {"asset_keys": asset_keys or [""]},
        )
        .mappings()
        .all()
    )
    incident_id_rows.extend(
        db.execute(
            text(
                """
                SELECT id AS incident_id
                FROM incidents
                WHERE title LIKE ANY(CAST(:title_patterns AS text[]))
                """
            ),
            {"title_patterns": list(CURATED_SITE_NOISE_INCIDENT_TITLE_PATTERNS)},
        )
        .mappings()
        .all()
    )
    incident_ids = sorted(
        {int(row["incident_id"]) for row in incident_id_rows if row.get("incident_id") is not None}
    )

    cleanup: dict[str, int] = {}

    cleanup["incidents"] = int(
        db.execute(
            text(
                """
                DELETE FROM incidents
                WHERE id = ANY(CAST(:incident_ids AS integer[]))
                """
            ),
            {"incident_ids": incident_ids or [0]},
        ).rowcount
        or 0
    )
    cleanup["alert_ai_guidance"] = int(
        db.execute(
            text(
                """
                DELETE FROM alert_ai_guidance
                WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                   OR asset_key LIKE ANY(CAST(:asset_patterns AS text[]))
                """
            ),
            {"asset_keys": asset_keys or [""], "asset_patterns": asset_patterns},
        ).rowcount
        or 0
    )
    cleanup["asset_ai_diagnoses"] = int(
        db.execute(
            text(
                """
                DELETE FROM asset_ai_diagnoses
                WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                   OR asset_key LIKE ANY(CAST(:asset_patterns AS text[]))
                """
            ),
            {"asset_keys": asset_keys or [""], "asset_patterns": asset_patterns},
        ).rowcount
        or 0
    )
    cleanup["threat_ioc_sightings"] = int(
        db.execute(
            text(
                """
                DELETE FROM threat_ioc_sightings
                WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                   OR asset_key LIKE ANY(CAST(:asset_patterns AS text[]))
                   OR threat_ioc_id IN (
                        SELECT id
                        FROM threat_iocs
                        WHERE source LIKE ANY(CAST(:source_patterns AS text[]))
                   )
                """
            ),
            {
                "asset_keys": asset_keys or [""],
                "asset_patterns": asset_patterns,
                "source_patterns": threat_source_patterns,
            },
        ).rowcount
        or 0
    )
    cleanup["threat_ioc_asset_matches"] = int(
        db.execute(
            text(
                """
                DELETE FROM threat_ioc_asset_matches
                WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                   OR asset_key LIKE ANY(CAST(:asset_patterns AS text[]))
                   OR threat_ioc_id IN (
                        SELECT id
                        FROM threat_iocs
                        WHERE source LIKE ANY(CAST(:source_patterns AS text[]))
                   )
                """
            ),
            {
                "asset_keys": asset_keys or [""],
                "asset_patterns": asset_patterns,
                "source_patterns": threat_source_patterns,
            },
        ).rowcount
        or 0
    )
    cleanup["asset_anomaly_scores"] = int(
        db.execute(
            text(
                """
                DELETE FROM asset_anomaly_scores
                WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                   OR asset_key LIKE ANY(CAST(:asset_patterns AS text[]))
                """
            ),
            {"asset_keys": asset_keys or [""], "asset_patterns": asset_patterns},
        ).rowcount
        or 0
    )
    cleanup["security_alerts"] = int(
        db.execute(
            text(
                """
                DELETE FROM security_alerts
                WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                   OR asset_key LIKE ANY(CAST(:asset_patterns AS text[]))
                   OR title LIKE ANY(CAST(:alert_title_patterns AS text[]))
                """
            ),
            {
                "asset_keys": asset_keys or [""],
                "asset_patterns": asset_patterns,
                "alert_title_patterns": alert_title_patterns,
            },
        ).rowcount
        or 0
    )
    cleanup["security_events"] = int(
        db.execute(
            text(
                """
                DELETE FROM security_events
                WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                   OR asset_key LIKE ANY(CAST(:asset_patterns AS text[]))
                """
            ),
            {"asset_keys": asset_keys or [""], "asset_patterns": asset_patterns},
        ).rowcount
        or 0
    )
    cleanup["attack_lab_runs"] = int(
        db.execute(
            text(
                """
                DELETE FROM attack_lab_runs
                WHERE target_asset_key = ANY(CAST(:asset_keys AS text[]))
                   OR target_asset_key LIKE ANY(CAST(:asset_patterns AS text[]))
                   OR target_asset_key LIKE ANY(CAST(:attack_lab_target_patterns AS text[]))
                """
            ),
            {
                "asset_keys": asset_keys or [""],
                "asset_patterns": asset_patterns,
                "attack_lab_target_patterns": attack_lab_target_patterns,
            },
        ).rowcount
        or 0
    )
    cleanup["scan_jobs"] = int(
        db.execute(
            text(
                """
                DELETE FROM scan_jobs
                WHERE target_asset_id = ANY(CAST(:asset_ids AS integer[]))
                   OR requested_by LIKE ANY(CAST(:requested_by_patterns AS text[]))
                   OR (
                        job_type = 'threat_intel_refresh'
                        AND (
                          requested_by = 'pytest'
                          OR job_params_json::text LIKE '%pytest-%'
                          OR job_params_json::text LIKE '%manual-fix-%'
                        )
                      )
                """
            ),
            {
                "asset_ids": asset_ids or [0],
                "requested_by_patterns": list(CURATED_SITE_NOISE_REQUESTED_BY_PATTERNS),
            },
        ).rowcount
        or 0
    )
    cleanup["findings"] = int(
        db.execute(
            text(
                """
                DELETE FROM findings
                WHERE asset_id = ANY(CAST(:asset_ids AS integer[]))
                   OR finding_key LIKE ANY(CAST(:finding_key_patterns AS text[]))
                   OR title = ANY(CAST(:finding_titles AS text[]))
                """
            ),
            {
                "asset_ids": asset_ids or [0],
                "finding_key_patterns": list(CURATED_SITE_NOISE_FINDING_KEY_PATTERNS),
                "finding_titles": list(CURATED_SITE_NOISE_FINDING_TITLES),
            },
        ).rowcount
        or 0
    )
    cleanup["threat_ioc_campaigns"] = int(
        db.execute(
            text(
                """
                DELETE FROM threat_ioc_campaigns
                WHERE campaign_tag LIKE ANY(CAST(:campaign_patterns AS text[]))
                """
            ),
            {"campaign_patterns": list(CURATED_SITE_NOISE_CAMPAIGN_PATTERNS)},
        ).rowcount
        or 0
    )
    cleanup["threat_iocs"] = int(
        db.execute(
            text(
                """
                DELETE FROM threat_iocs
                WHERE source LIKE ANY(CAST(:source_patterns AS text[]))
                """
            ),
            {"source_patterns": threat_source_patterns},
        ).rowcount
        or 0
    )
    cleanup["risk_entity_snapshots"] = int(
        db.execute(
            text(
                """
                DELETE FROM risk_entity_snapshots
                WHERE entity_key = ANY(CAST(:asset_keys AS text[]))
                   OR entity_key LIKE ANY(CAST(:asset_patterns AS text[]))
                """
            ),
            {"asset_keys": asset_keys or [""], "asset_patterns": asset_patterns},
        ).rowcount
        or 0
    )
    cleanup["audit_events"] = int(
        db.execute(
            text(
                """
                DELETE FROM audit_events
                WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                   OR asset_key LIKE ANY(CAST(:asset_patterns AS text[]))
                """
            ),
            {"asset_keys": asset_keys or [""], "asset_patterns": asset_patterns},
        ).rowcount
        or 0
    )
    cleanup["assets"] = int(
        db.execute(
            text(
                """
                DELETE FROM assets
                WHERE asset_id = ANY(CAST(:asset_ids AS integer[]))
                """
            ),
            {"asset_ids": asset_ids or [0]},
        ).rowcount
        or 0
    )
    db.commit()
    return cleanup


def _merge_cleanup_count(cleanup: dict[str, int], key: str, deleted_rows: int | None) -> None:
    cleanup[key] = int(cleanup.get(key, 0) or 0) + int(deleted_rows or 0)


def _opensearch_doc_id(asset_key: str, org_id: str | None) -> str:
    normalized_org_id = str(org_id or "").strip()
    normalized_asset_key = str(asset_key or "").strip()
    if normalized_org_id and normalized_org_id != "default":
        return f"{normalized_org_id}::{normalized_asset_key}"
    return normalized_asset_key


def _criticality_number(value: Any) -> int:
    if isinstance(value, int):
        return value
    normalized = str(value or "").strip().lower()
    if normalized == "high":
        return 2
    if normalized == "low":
        return 4
    return 3


def _status_shape(status: str | None) -> tuple[str, int, int]:
    normalized = str(status or "").strip().lower()
    if normalized in {"up", "green"}:
        return "up", 1, 100
    if normalized in {"stale", "amber", "warning"}:
        return "stale", 0, 60
    if normalized in {"down", "red"}:
        return "down", -2, 0
    return "unknown", -1, 0


def _search_asset_doc(row: dict[str, Any]) -> dict[str, Any]:
    created_at = row.get("created_at")
    updated_at = row.get("updated_at")
    return {
        "asset_id": row.get("asset_id"),
        "org_id": row.get("org_id") or "default",
        "asset_key": row.get("asset_key"),
        "type": row.get("type"),
        "name": row.get("name"),
        "owner": row.get("owner"),
        "owner_team": row.get("owner_team"),
        "owner_email": row.get("owner_email"),
        "asset_type": row.get("asset_type"),
        "environment": row.get("environment"),
        "criticality": row.get("criticality"),
        "verified": bool(row.get("verified")),
        "verification_method": row.get("verification_method"),
        "verification_token": row.get("verification_token"),
        "address": row.get("address"),
        "port": row.get("port"),
        "is_active": bool(row.get("is_active", True)),
        "tags": row.get("tags") or [],
        "metadata": row.get("metadata") or {},
        "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else created_at,
        "updated_at": updated_at.isoformat() if hasattr(updated_at, "isoformat") else updated_at,
    }


def _status_doc_for_asset(row: dict[str, Any], existing: dict[str, Any] | None) -> dict[str, Any]:
    existing_doc = dict(existing or {})
    fallback_seen = row.get("updated_at") or row.get("created_at") or datetime.now(UTC)
    fallback_seen_iso = (
        fallback_seen.isoformat() if hasattr(fallback_seen, "isoformat") else str(fallback_seen)
    )
    fallback_status, fallback_status_num, fallback_posture_score = _status_shape(
        "up" if row.get("verified") else "unknown"
    )
    status, status_num, posture_score = _status_shape(existing_doc.get("status") or fallback_status)
    if existing_doc.get("posture_score") is not None:
        try:
            posture_score = int(existing_doc["posture_score"])
        except (TypeError, ValueError):
            posture_score = fallback_posture_score
    posture_state = str(existing_doc.get("posture_state") or "").strip().lower()
    if posture_state not in {"green", "amber", "red"}:
        posture_state = (
            "green" if posture_score >= 80 else "amber" if posture_score >= 50 else "red"
        )
    last_seen = existing_doc.get("last_seen") or fallback_seen_iso
    last_status_change = existing_doc.get("last_status_change") or last_seen
    doc = {
        "@timestamp": datetime.now(UTC).isoformat(),
        "org_id": row.get("org_id") or "default",
        "asset_key": row.get("asset_key"),
        "name": row.get("name"),
        "type": row.get("type"),
        "environment": row.get("environment"),
        "criticality": _criticality_number(row.get("criticality")),
        "owner": row.get("owner"),
        "owner_team": row.get("owner_team"),
        "status": status,
        "status_num": status_num,
        "code": int(existing_doc.get("code") or (200 if status == "up" else 0)),
        "latency_ms": int(existing_doc.get("latency_ms") or 0),
        "last_seen": last_seen,
        "source_event_timestamp": existing_doc.get("source_event_timestamp") or last_seen,
        "staleness_seconds": int(existing_doc.get("staleness_seconds") or 0),
        "posture_score": posture_score,
        "posture_state": posture_state,
        "last_status_change": last_status_change,
    }
    return doc


def _sync_curated_site_opensearch_assets(db) -> dict[str, int]:
    base_url = str(getattr(settings, "OPENSEARCH_URL", "http://localhost:9200") or "").rstrip("/")
    assets_index = str(getattr(settings, "OPENSEARCH_ASSETS_INDEX", "secplat-assets") or "").strip()
    status_index = str(
        getattr(settings, "OPENSEARCH_STATUS_INDEX", "secplat-asset-status") or ""
    ).strip()
    if not base_url or not assets_index or not status_index:
        return {"assets_docs_upserted": 0, "status_docs_upserted": 0, "docs_deleted": 0}

    rows = (
        db.execute(
            text(
                """
                SELECT
                  asset_id,
                  org_id,
                  asset_key,
                  type,
                  name,
                  owner,
                  owner_team,
                  owner_email,
                  asset_type,
                  environment,
                  criticality,
                  verified,
                  verification_method,
                  verification_token,
                  address,
                  port,
                  is_active,
                  tags,
                  metadata,
                  created_at,
                  updated_at
                FROM assets
                ORDER BY asset_key ASC
                """
            )
        )
        .mappings()
        .all()
    )
    if not rows:
        return {"assets_docs_upserted": 0, "status_docs_upserted": 0, "docs_deleted": 0}

    valid_asset_keys = {
        str(row.get("asset_key") or "").strip() for row in rows if row.get("asset_key")
    }
    existing_status_by_asset_key: dict[str, dict[str, Any]] = {}
    deleted_docs = 0

    with httpx.Client(timeout=15.0) as client:

        def _search(index: str) -> list[dict[str, Any]]:
            response = client.post(
                f"{base_url}/{index}/_search",
                json={"size": 2000, "query": {"match_all": {}}},
            )
            response.raise_for_status()
            return response.json().get("hits", {}).get("hits", [])

        for index in (assets_index, status_index):
            try:
                hits = _search(index)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 404:
                    continue
                raise
            for hit in hits:
                source = hit.get("_source") or {}
                asset_key = str(source.get("asset_key") or source.get("asset_id") or "").strip()
                if index == status_index and asset_key:
                    existing_status_by_asset_key[asset_key] = source
                if asset_key and asset_key in valid_asset_keys:
                    continue
                doc_id = str(hit.get("_id") or "").strip()
                if not doc_id:
                    continue
                delete_response = client.delete(
                    f"{base_url}/{index}/_doc/{quote(doc_id, safe='')}",
                )
                if delete_response.status_code not in {200, 202, 404}:
                    delete_response.raise_for_status()
                deleted_docs += 1

        assets_docs_upserted = 0
        status_docs_upserted = 0
        for row in rows:
            asset_key = str(row.get("asset_key") or "").strip()
            org_id = str(row.get("org_id") or "default").strip() or "default"
            if not asset_key:
                continue
            doc_id = _opensearch_doc_id(asset_key, org_id)
            asset_response = client.put(
                f"{base_url}/{assets_index}/_doc/{quote(doc_id, safe='')}",
                json=_search_asset_doc(dict(row)),
            )
            asset_response.raise_for_status()
            assets_docs_upserted += 1

            status_response = client.put(
                f"{base_url}/{status_index}/_doc/{quote(doc_id, safe='')}",
                json=_status_doc_for_asset(dict(row), existing_status_by_asset_key.get(asset_key)),
            )
            status_response.raise_for_status()
            status_docs_upserted += 1

        client.post(f"{base_url}/{assets_index}/_refresh").raise_for_status()
        client.post(f"{base_url}/{status_index}/_refresh").raise_for_status()

    return {
        "assets_docs_upserted": assets_docs_upserted,
        "status_docs_upserted": status_docs_upserted,
        "docs_deleted": deleted_docs,
    }


def _seed_marker_exists(db, *, seed_version: str) -> bool:
    row = (
        db.execute(
            text(
                """
                SELECT id
                FROM audit_events
                WHERE action = :action
                  AND details ->> 'seed_version' = :seed_version
                ORDER BY id DESC
                LIMIT 1
                """
            ),
            {"action": SEED_ACTION, "seed_version": seed_version},
        )
        .mappings()
        .first()
    )
    return bool(row)


def _write_seed_marker(
    db,
    *,
    seed_version: str,
    asset_key: str,
    repo_asset_key: str,
    details: dict[str, Any],
) -> None:
    payload = {
        "seed_version": seed_version,
        "asset_key": asset_key,
        "repo_asset_key": repo_asset_key,
        **details,
    }
    db.execute(
        text(
            """
            INSERT INTO audit_events(action, user_name, asset_key, details)
            VALUES (:action, :user_name, :asset_key, CAST(:details AS jsonb))
            """
        ),
        {
            "action": SEED_ACTION,
            "user_name": SEED_ACTOR,
            "asset_key": asset_key,
            "details": json.dumps(payload),
        },
    )
    db.commit()


def _ensure_asset(
    db,
    *,
    tenant_id: str,
    asset_key: str,
    type_name: str,
    name: str,
    address: str,
    owner: str,
    environment: str,
    criticality: str,
    asset_type: str = "external_web",
    tags: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> int:
    row = (
        db.execute(
            text("SELECT asset_id FROM assets WHERE asset_key = :asset_key"),
            {"asset_key": asset_key},
        )
        .mappings()
        .first()
    )
    if row:
        asset_id = int(row["asset_id"])
        db.execute(
            text(
                """
                UPDATE assets
                SET type = :type_name,
                    name = :name,
                    address = :address,
                    owner = :owner,
                    environment = :environment,
                    criticality = :criticality,
                    asset_type = :asset_type,
                    metadata = CAST(:metadata AS jsonb),
                    org_id = :org_id
                WHERE asset_id = :asset_id
                """
            ),
            {
                "asset_id": asset_id,
                "type_name": type_name,
                "name": name,
                "address": address,
                "owner": owner,
                "environment": environment,
                "criticality": criticality,
                "asset_type": asset_type,
                "metadata": json.dumps(metadata or {}),
                "org_id": tenant_id,
            },
        )
        db.commit()
        return asset_id

    created = (
        db.execute(
            text(
                """
                INSERT INTO assets(
                  org_id, asset_key, type, name, address, owner, environment, criticality,
                  asset_type, tags, metadata, verified
                )
                VALUES(
                  :org_id, :asset_key, :type_name, :name, :address, :owner, :environment, :criticality,
                  :asset_type, CAST(:tags AS text[]), CAST(:metadata AS jsonb), TRUE
                )
                RETURNING asset_id
                """
            ),
            {
                "org_id": tenant_id,
                "asset_key": asset_key,
                "type_name": type_name,
                "name": name,
                "address": address,
                "owner": owner,
                "environment": environment,
                "criticality": criticality,
                "asset_type": asset_type,
                "tags": tags or [],
                "metadata": json.dumps(metadata or {}),
            },
        )
        .mappings()
        .first()
    )
    db.commit()
    if not created:
        raise RuntimeError(f"failed_to_create_asset:{asset_key}")
    return int(created["asset_id"])


def _ensure_detection_rule(db, *, name: str, source: str) -> dict[str, Any]:
    existing = (
        db.execute(
            text("SELECT rule_id FROM detection_rules WHERE name = :name"),
            {"name": name},
        )
        .mappings()
        .first()
    )
    if existing:
        rule_id = int(existing["rule_id"])
        db.execute(
            text(
                """
                UPDATE detection_rules
                SET description = :description,
                    source = :source,
                    severity = 'high',
                    enabled = TRUE,
                    definition_json = CAST(:definition_json AS jsonb),
                    updated_at = NOW()
                WHERE rule_id = :rule_id
                """
            ),
            {
                "rule_id": rule_id,
                "description": "Demo rule: detect Cowrie failed logins",
                "source": source,
                "definition_json": json.dumps(
                    {
                        "condition_mode": "all",
                        "conditions": [
                            {"field": "event_type", "op": "eq", "value": "cowrie.login.failed"}
                        ],
                    }
                ),
            },
        )
    else:
        row = (
            db.execute(
                text(
                    """
                    INSERT INTO detection_rules(
                      name, description, source, rule_format, severity, enabled, definition_json, created_by
                    )
                    VALUES(
                      :name, :description, :source, 'json', 'high', TRUE, CAST(:definition_json AS jsonb), :created_by
                    )
                    RETURNING rule_id
                    """
                ),
                {
                    "name": name,
                    "description": "Demo rule: detect Cowrie failed logins",
                    "source": source,
                    "definition_json": json.dumps(
                        {
                            "condition_mode": "all",
                            "conditions": [
                                {"field": "event_type", "op": "eq", "value": "cowrie.login.failed"}
                            ],
                        }
                    ),
                    "created_by": SEED_ACTOR,
                },
            )
            .mappings()
            .first()
        )
        if not row:
            raise RuntimeError("failed_to_create_demo_detection_rule")
        rule_id = int(row["rule_id"])
    db.commit()
    row = (
        db.execute(
            text("SELECT * FROM detection_rules WHERE rule_id = :rule_id"),
            {"rule_id": rule_id},
        )
        .mappings()
        .first()
    )
    if not row:
        raise RuntimeError("failed_to_load_demo_detection_rule")
    return dict(row)


def _upsert_demo_iocs(db, *, source: str, indicators: list[tuple[str, str]]) -> int:
    normalized = {
        (str(indicator_type).strip().lower(), str(indicator).strip().lower())
        for indicator_type, indicator in indicators
        if str(indicator_type).strip().lower() in {"ip", "domain"} and str(indicator).strip()
    }
    existing_rows = (
        db.execute(
            text(
                """
                SELECT id, indicator_type, indicator
                FROM threat_iocs
                WHERE source = :source
                """
            ),
            {"source": source},
        )
        .mappings()
        .all()
    )
    for row in existing_rows:
        key = (
            str(row.get("indicator_type") or "").strip().lower(),
            str(row.get("indicator") or "").strip().lower(),
        )
        if key not in normalized:
            db.execute(
                text(
                    """
                    UPDATE threat_iocs
                    SET is_active = FALSE, updated_at = NOW()
                    WHERE id = :id
                    """
                ),
                {"id": int(row["id"])},
            )

    inserted = 0
    for indicator_type, indicator in sorted(normalized):
        db.execute(
            text(
                """
                INSERT INTO threat_iocs(
                  source, indicator, indicator_type, feed_url, first_seen_at, last_seen_at,
                  is_active, metadata, created_at, updated_at
                )
                VALUES(
                  :source, :indicator, :indicator_type, NULL, NOW(), NOW(),
                  TRUE, CAST(:metadata AS jsonb), NOW(), NOW()
                )
                ON CONFLICT (source, indicator_type, indicator) DO UPDATE
                SET last_seen_at = NOW(),
                    is_active = TRUE,
                    metadata = EXCLUDED.metadata,
                    updated_at = NOW()
                """
            ),
            {
                "source": source,
                "indicator": indicator,
                "indicator_type": indicator_type,
                "metadata": json.dumps({"seeded": True, "source": source}),
            },
        )
        inserted += 1
    db.commit()
    return inserted


def _seed_demo_ioc_matches(
    db,
    *,
    asset_id: int,
    asset_key: str,
    asset_address: str,
    source: str,
) -> int:
    asset_row = (
        db.execute(
            text(
                """
                SELECT asset_id
                FROM assets
                WHERE asset_key = :asset_key
                """
            ),
            {"asset_key": asset_key},
        )
        .mappings()
        .first()
    )
    if not asset_row or asset_row.get("asset_id") is None:
        raise RuntimeError(f"demo_asset_not_found_for_ioc_match:{asset_key}")
    asset_id = int(asset_row["asset_id"])
    normalized_address = str(asset_address or "").strip().lower()
    ioc_rows = (
        db.execute(
            text(
                """
                SELECT id, indicator_type, indicator
                FROM threat_iocs
                WHERE source = :source
                  AND is_active = TRUE
                """
            ),
            {"source": source},
        )
        .mappings()
        .all()
    )
    ioc_ids = [int(row["id"]) for row in ioc_rows if row.get("id") is not None]
    if ioc_ids:
        db.execute(
            text(
                """
                DELETE FROM threat_ioc_asset_matches
                WHERE threat_ioc_id = ANY(CAST(:ioc_ids AS integer[]))
                  AND asset_id = :asset_id
                """
            ),
            {"ioc_ids": ioc_ids, "asset_id": asset_id},
        )
        db.execute(
            text(
                """
                DELETE FROM threat_ioc_sightings
                WHERE threat_ioc_id = ANY(CAST(:ioc_ids AS integer[]))
                  AND asset_id = :asset_id
                """
            ),
            {"ioc_ids": ioc_ids, "asset_id": asset_id},
        )
    inserted = 0
    for row in ioc_rows:
        threat_ioc_id = int(row["id"])
        indicator_type = str(row.get("indicator_type") or "").strip().lower()
        indicator = str(row.get("indicator") or "").strip().lower()
        matched = (
            indicator_type == "ip" and bool(normalized_address) and indicator == normalized_address
        )
        match_count = 1 if matched else 0
        db.execute(
            text(
                """
                UPDATE threat_iocs
                SET last_match_count = :match_count,
                    updated_at = NOW()
                WHERE id = :threat_ioc_id
                """
            ),
            {"threat_ioc_id": threat_ioc_id, "match_count": match_count},
        )
        if not matched:
            continue
        db.execute(
            text(
                """
                INSERT INTO threat_ioc_asset_matches(
                  threat_ioc_id, asset_id, asset_key, match_field, matched_value,
                  first_seen_at, last_seen_at, metadata
                )
                VALUES(
                  :threat_ioc_id, :asset_id, :asset_key, 'address', :matched_value,
                  NOW(), NOW(), CAST(:metadata AS jsonb)
                )
                ON CONFLICT (threat_ioc_id, asset_id, match_field, matched_value)
                DO UPDATE SET
                  asset_key = EXCLUDED.asset_key,
                  last_seen_at = EXCLUDED.last_seen_at,
                  metadata = EXCLUDED.metadata
                """
            ),
            {
                "threat_ioc_id": threat_ioc_id,
                "asset_id": asset_id,
                "asset_key": asset_key,
                "matched_value": normalized_address,
                "metadata": json.dumps({"source": source, "seeded": True}),
            },
        )
        db.execute(
            text(
                """
                INSERT INTO threat_ioc_sightings(
                  threat_ioc_id, asset_id, asset_key, match_field, matched_value,
                  source_event_id, source_event_ref, source_tool, sighted_at, context_json
                )
                VALUES(
                  :threat_ioc_id, :asset_id, :asset_key, 'address', :matched_value,
                  NULL, :source_event_ref, 'demo_seed', NOW(), CAST(:context_json AS jsonb)
                )
                """
            ),
            {
                "threat_ioc_id": threat_ioc_id,
                "asset_id": asset_id,
                "asset_key": asset_key,
                "matched_value": normalized_address,
                "source_event_ref": f"demo-seed:{threat_ioc_id}:{asset_key}:address:{normalized_address}",
                "context_json": json.dumps({"source": source, "seeded": True}),
            },
        )
        inserted += 1
    db.commit()
    return inserted


def _seed_repository_findings(db, *, repo_asset_key: str) -> int:
    seeded = 0
    demo_findings = [
        FindingUpsertBody(
            finding_key=f"{repo_asset_key}:trivy:docker-root-user",
            asset_key=repo_asset_key,
            source="trivy_fs",
            category="misconfiguration",
            title="Image user should not be 'root'",
            severity="high",
            confidence="high",
            evidence="Docker image executes as root user in runtime stage.",
            remediation="Set a non-root USER in the final image stage.",
            scanner_metadata_json={"scanner": "trivy", "seeded": True},
        ),
        FindingUpsertBody(
            finding_key=f"{repo_asset_key}:osv:demo-cve",
            asset_key=repo_asset_key,
            source="osv_scanner",
            category="dependency",
            title="Demo vulnerable package version detected",
            severity="medium",
            confidence="high",
            vulnerability_id="CVE-DEMO-2026-0001",
            package_ecosystem="npm",
            package_name="demo-lib",
            package_version="1.0.0",
            fixed_version="1.0.1",
            evidence="Version 1.0.0 is marked vulnerable in demo dataset.",
            remediation="Upgrade demo-lib to >= 1.0.1.",
            scanner_metadata_json={"scanner": "osv", "seeded": True},
        ),
    ]
    for finding in demo_findings:
        result = upsert_finding_record(db, finding)
        if not result.get("updated"):
            seeded += 1
    db.commit()
    return seeded


def _create_job(db, *, job_type: str, params: dict[str, Any]) -> int:
    tenant_id = _current_tenant_id()
    row = (
        db.execute(
            text(
                """
                INSERT INTO scan_jobs(org_id, job_type, requested_by, status, job_params_json)
                VALUES (:org_id, :job_type, :requested_by, 'queued', CAST(:job_params_json AS jsonb))
                RETURNING job_id
                """
            ),
            {
                "org_id": tenant_id,
                "job_type": job_type,
                "requested_by": SEED_ACTOR,
                "job_params_json": json.dumps(params),
            },
        )
        .mappings()
        .first()
    )
    db.commit()
    if not row:
        raise RuntimeError(f"failed_to_create_job:{job_type}")
    return int(row["job_id"])


def _seed_attack_lab_demo_run(
    db,
    *,
    asset_id: int,
    asset_key: str,
    target: str,
) -> dict[str, int | None]:
    result_payload: dict[str, Any] = {
        "engine": "synthetic-demo",
        "seeded": True,
        "target": target,
        "open_ports": [80, 443],
        "finding_count": 2,
        "findings": [
            "Synthetic demo scan identified HTTPS and HTTP services exposed to the lab network.",
            "Synthetic demo scan recommends validating TLS posture before GA.",
        ],
    }
    alert = upsert_security_alert(
        db,
        source="attack_lab",
        alert_type="port_scan",
        title=f"Attack-lab detected open ports on {target}",
        description="Synthetic demo run identified the seeded attack-lab target as reachable.",
        dedupe_key=f"attack-lab:demo-port-scan:{asset_key}",
        severity="medium",
        asset_key=asset_key,
        context_json={"task_type": "port_scan", "target": target, "seeded": True},
        payload_json=result_payload,
    )
    alert_id = int(alert["alert_id"])
    existing_incident = (
        db.execute(
            text(
                """
                SELECT incident_id
                FROM incident_alerts
                WHERE alert_id = :alert_id
                ORDER BY incident_id DESC
                LIMIT 1
                """
            ),
            {"alert_id": alert_id},
        )
        .mappings()
        .first()
    )
    if existing_incident and existing_incident.get("incident_id") is not None:
        incident_id = int(existing_incident["incident_id"])
    else:
        incident_id = create_incident_for_alert(
            db,
            alert=alert,
            requested_by=SEED_ACTOR,
            title=f"Attack-lab incident: {alert.get('title')}",
            severity=str(alert.get("severity") or "medium"),
        )

    result_payload["alert"] = {
        "alert_id": alert_id,
        "source": alert.get("source"),
        "severity": alert.get("severity"),
        "status": alert.get("status"),
    }
    result_payload["incident_id"] = incident_id

    log_line = (
        f"[{datetime.now(UTC).isoformat().replace('+00:00', 'Z')}] "
        f"Seeded synthetic attack-lab port scan for {target}"
    )
    job_params_json = {
        "task_type": "port_scan",
        "target": target,
        "asset_key": asset_key,
        "seeded": True,
        "engine": "synthetic-demo",
    }
    existing_job = (
        db.execute(
            text(
                """
                SELECT job_id
                FROM scan_jobs
                WHERE job_type = 'attack_lab_run'
                  AND requested_by = :requested_by
                  AND target_asset_id = :target_asset_id
                ORDER BY job_id DESC
                LIMIT 1
                """
            ),
            {"requested_by": SEED_ACTOR, "target_asset_id": asset_id},
        )
        .mappings()
        .first()
    )
    if existing_job and existing_job.get("job_id") is not None:
        job_id = int(existing_job["job_id"])
        db.execute(
            text(
                """
                UPDATE scan_jobs
                SET status = 'done',
                    requested_by = :requested_by,
                    target_asset_id = :target_asset_id,
                    started_at = COALESCE(started_at, NOW() - INTERVAL '15 seconds'),
                    finished_at = NOW(),
                    error = NULL,
                    job_params_json = CAST(:job_params_json AS jsonb),
                    log_output = :log_output
                WHERE job_id = :job_id
                """
            ),
            {
                "job_id": job_id,
                "requested_by": SEED_ACTOR,
                "target_asset_id": asset_id,
                "job_params_json": json.dumps(job_params_json),
                "log_output": log_line,
            },
        )
    else:
        created_job = (
            db.execute(
                text(
                    """
                    INSERT INTO scan_jobs(
                      job_type, requested_by, target_asset_id, status,
                      started_at, finished_at, error, job_params_json, log_output
                    )
                    VALUES (
                      'attack_lab_run',
                      :requested_by,
                      :target_asset_id,
                      'done',
                      NOW() - INTERVAL '15 seconds',
                      NOW(),
                      NULL,
                      CAST(:job_params_json AS jsonb),
                      :log_output
                    )
                    RETURNING job_id
                    """
                ),
                {
                    "requested_by": SEED_ACTOR,
                    "target_asset_id": asset_id,
                    "job_params_json": json.dumps(job_params_json),
                    "log_output": log_line,
                },
            )
            .mappings()
            .first()
        )
        if not created_job:
            raise RuntimeError("failed_to_create_demo_attack_lab_job")
        job_id = int(created_job["job_id"])

    existing_run = (
        db.execute(
            text(
                """
                SELECT run_id
                FROM attack_lab_runs
                WHERE task_type = 'port_scan'
                  AND requested_by = :requested_by
                  AND target_asset_key = :target_asset_key
                ORDER BY run_id DESC
                LIMIT 1
                """
            ),
            {"requested_by": SEED_ACTOR, "target_asset_key": asset_key},
        )
        .mappings()
        .first()
    )
    if existing_run and existing_run.get("run_id") is not None:
        run_id = int(existing_run["run_id"])
        db.execute(
            text(
                """
                UPDATE attack_lab_runs
                SET target_asset_id = :target_asset_id,
                    target = :target,
                    status = 'done',
                    requested_by = :requested_by,
                    started_at = COALESCE(started_at, NOW() - INTERVAL '15 seconds'),
                    finished_at = NOW(),
                    error = NULL,
                    output_json = CAST(:output_json AS jsonb)
                WHERE run_id = :run_id
                """
            ),
            {
                "run_id": run_id,
                "target_asset_id": asset_id,
                "target": target,
                "requested_by": SEED_ACTOR,
                "output_json": json.dumps(result_payload),
            },
        )
    else:
        created_run = (
            db.execute(
                text(
                    """
                    INSERT INTO attack_lab_runs(
                      task_type, target_asset_id, target_asset_key, target,
                      status, requested_by, started_at, finished_at, output_json
                    )
                    VALUES (
                      'port_scan',
                      :target_asset_id,
                      :target_asset_key,
                      :target,
                      'done',
                      :requested_by,
                      NOW() - INTERVAL '15 seconds',
                      NOW(),
                      CAST(:output_json AS jsonb)
                    )
                    RETURNING run_id
                    """
                ),
                {
                    "target_asset_id": asset_id,
                    "target_asset_key": asset_key,
                    "target": target,
                    "requested_by": SEED_ACTOR,
                    "output_json": json.dumps(result_payload),
                },
            )
            .mappings()
            .first()
        )
        if not created_run:
            raise RuntimeError("failed_to_create_demo_attack_lab_run")
        run_id = int(created_run["run_id"])

    db.commit()
    return {"job_id": job_id, "run_id": run_id, "incident_id": incident_id, "alert_id": alert_id}


def run_cyberlab_auto_seed(*, force: bool = False, tenant_id: str | None = None) -> dict[str, Any]:
    seed_version = str(settings.CYBERLAB_AUTO_SEED_ONCE_VERSION or "v1").strip() or "v1"
    asset_key = str(settings.CYBERLAB_DEMO_ASSET_KEY or "cyberlab-demo-asset").strip()
    repo_asset_key = str(settings.CYBERLAB_DEMO_REPO_ASSET_KEY or "cyberlab-demo-repo").strip()
    if not asset_key:
        raise RuntimeError("CYBERLAB_DEMO_ASSET_KEY must not be empty")
    if not repo_asset_key:
        raise RuntimeError("CYBERLAB_DEMO_REPO_ASSET_KEY must not be empty")

    effective_tenant_id = _current_tenant_id(tenant_id)
    tenant_token = tenant_id_ctx.set(effective_tenant_id)
    db = SessionLocal()
    try:
        _pin_session_tenant(db, effective_tenant_id)
        if not force and _seed_marker_exists(db, seed_version=seed_version):
            return {"seeded": False, "reason": "already_seeded", "seed_version": seed_version}

        demo_asset_address = "172.20.0.15"
        demo_asset_id = _ensure_asset(
            db,
            tenant_id=effective_tenant_id,
            asset_key=asset_key,
            type_name="external_web",
            name=f"{asset_key}.lab.local",
            address=demo_asset_address,
            owner="soc-lab",
            environment="prod",
            criticality="high",
            asset_type="external_web",
            tags=["cyberlab", "telemetry", "demo"],
            metadata={"seeded": True, "seed_version": seed_version},
        )
        _ensure_asset(
            db,
            tenant_id=effective_tenant_id,
            asset_key=repo_asset_key,
            type_name="app",
            name="Cyberlab Demo Repository",
            address="repo://cyberlab-demo",
            owner="platform-security",
            environment="dev",
            criticality="medium",
            asset_type="repository",
            tags=["repository", "seeded", "demo"],
            metadata={"seeded": True, "seed_version": seed_version},
        )

        ioc_source = str(settings.CYBERLAB_DEMO_IOC_SOURCE or "cyberlab-demo").strip().lower()
        ioc_count = _upsert_demo_iocs(
            db,
            source=ioc_source,
            indicators=[
                ("ip", "203.0.113.10"),
                ("ip", "198.51.100.22"),
                ("ip", "172.20.0.15"),
                ("domain", "bad.example"),
            ],
        )
        ioc_asset_matches = _seed_demo_ioc_matches(
            db,
            asset_id=demo_asset_id,
            asset_key=asset_key,
            asset_address=demo_asset_address,
            source=ioc_source,
        )

        telemetry_totals: dict[str, Any] = {}
        for source, path in {
            "suricata": settings.TELEMETRY_SURICATA_LOG_PATH,
            "zeek": settings.TELEMETRY_ZEEK_LOG_PATH,
            "auditd": settings.TELEMETRY_AUDITD_LOG_PATH,
            "cowrie": settings.TELEMETRY_COWRIE_LOG_PATH,
        }.items():
            if not path:
                telemetry_totals[source] = {
                    "processed_events": 0,
                    "alert_updates": 0,
                    "reason": "path_missing",
                }
                continue
            file_path = Path(path)
            if not file_path.exists():
                telemetry_totals[source] = {
                    "processed_events": 0,
                    "alert_updates": 0,
                    "reason": "file_missing",
                    "path": str(file_path),
                }
                continue
            events = _read_events_from_file(str(file_path))
            if len(events) > DEMO_TELEMETRY_EVENT_LIMIT:
                events = events[-DEMO_TELEMETRY_EVENT_LIMIT:]
            summary = ingest_telemetry_events(
                db,
                source=source,
                events=events,
                default_asset_key=asset_key,
                create_alerts=True,
                collector=f"demo_seed.file.{source}",
                raw_path=str(file_path),
            )
            telemetry_totals[source] = summary
        db.commit()

        now = datetime.now(UTC)
        custom_events: list[dict[str, Any]] = []
        for hour_back in (4, 3, 2):
            for idx in range(2):
                custom_events.append(
                    {
                        "event_type": "baseline",
                        "title": "Baseline traffic",
                        "severity": "low",
                        "src_ip": f"10.0.{hour_back}.{idx + 10}",
                        "dst_ip": "172.20.0.15",
                        "protocol": "tcp",
                        "event_time": (now - timedelta(hours=hour_back, minutes=idx))
                        .isoformat()
                        .replace("+00:00", "Z"),
                    }
                )
        for idx in range(30):
            custom_events.append(
                {
                    "event_type": "burst",
                    "title": "Traffic burst",
                    "severity": "medium",
                    "src_ip": f"10.200.1.{(idx % 20) + 1}",
                    "dst_ip": "172.20.0.15",
                    "protocol": "tcp",
                    "event_time": (now - timedelta(minutes=idx % 45))
                    .isoformat()
                    .replace("+00:00", "Z"),
                }
            )
        custom_summary = ingest_telemetry_events(
            db,
            source="custom",
            events=custom_events,
            default_asset_key=asset_key,
            create_alerts=False,
            collector="demo_seed.synthetic.custom",
            raw_path="demo-seed://custom-events",
        )
        db.commit()

        anomaly_job_id = _create_job(
            db,
            job_type="network_anomaly_score",
            params={"lookback_hours": 8, "threshold": 1.5},
        )
        run_network_anomaly_job(anomaly_job_id)

        rule_name = f"cyberlab-demo-cowrie-login-failed-{seed_version}"
        rule_row = _ensure_detection_rule(db, name=rule_name, source="cowrie")
        detection_result = run_detection_rule(
            db,
            rule_row=rule_row,
            lookback_hours=72,
            executed_by=SEED_ACTOR,
            create_alerts=True,
        )
        db.commit()

        attack_lab_demo = _seed_attack_lab_demo_run(
            db,
            asset_id=demo_asset_id,
            asset_key=asset_key,
            target=demo_asset_address,
        )

        seeded_findings = _seed_repository_findings(db, repo_asset_key=repo_asset_key)
        db.commit()

        # Make sure all newly seeded findings have computed risk fields immediately.
        finding_rows = (
            db.execute(
                text(
                    """
                    SELECT f.finding_id
                    FROM findings f
                    JOIN assets a ON a.asset_id = f.asset_id
                    WHERE a.asset_key = :repo_asset_key
                    """
                ),
                {"repo_asset_key": repo_asset_key},
            )
            .mappings()
            .all()
        )
        for row in finding_rows:
            recompute_finding_risk(db, int(row["finding_id"]))
        db.commit()

        summary = {
            "seeded": True,
            "seed_version": seed_version,
            "asset_key": asset_key,
            "repo_asset_key": repo_asset_key,
            "ioc_source": ioc_source,
            "ioc_count": ioc_count,
            "ioc_asset_matches": ioc_asset_matches,
            "telemetry": telemetry_totals,
            "custom_telemetry": custom_summary,
            "anomaly_job_id": anomaly_job_id,
            "attack_lab_job_id": attack_lab_demo["job_id"],
            "attack_lab_run_id": attack_lab_demo["run_id"],
            "attack_lab_incident_id": attack_lab_demo["incident_id"],
            "detection_rule_id": int(rule_row["rule_id"]),
            "detection_matches": int(detection_result.get("matches") or 0),
            "repository_findings_seeded": seeded_findings,
        }
        _write_seed_marker(
            db,
            seed_version=seed_version,
            asset_key=asset_key,
            repo_asset_key=repo_asset_key,
            details=summary,
        )
        return summary
    finally:
        db.close()
        tenant_id_ctx.reset(tenant_token)


def maybe_seed_cyberlab_demo() -> dict[str, Any]:
    if not bool(getattr(settings, "CYBERLAB_AUTO_SEED_DEMO", False)):
        return {"seeded": False, "reason": "disabled"}
    force = bool(getattr(settings, "CYBERLAB_AUTO_SEED_FORCE", False))
    try:
        summary = run_cyberlab_auto_seed(force=force)
        logger.info("cyberlab_auto_seed result=%s", summary)
        return summary
    except Exception as exc:
        logger.exception("cyberlab_auto_seed failed: %s", exc)
        return {"seeded": False, "reason": "failed", "error": str(exc)}


def _demo_seed_context() -> dict[str, str]:
    seed_version = str(settings.CYBERLAB_AUTO_SEED_ONCE_VERSION or "v1").strip() or "v1"
    asset_key = str(settings.CYBERLAB_DEMO_ASSET_KEY or "cyberlab-demo-asset").strip()
    repo_asset_key = str(settings.CYBERLAB_DEMO_REPO_ASSET_KEY or "cyberlab-demo-repo").strip()
    ioc_source = str(settings.CYBERLAB_DEMO_IOC_SOURCE or "cyberlab-demo").strip().lower()
    rule_name = f"cyberlab-demo-cowrie-login-failed-{seed_version}"
    return {
        "seed_version": seed_version,
        "asset_key": asset_key,
        "repo_asset_key": repo_asset_key,
        "ioc_source": ioc_source,
        "rule_name": rule_name,
    }


def get_cyberlab_demo_status(db) -> dict[str, Any]:
    ctx = _demo_seed_context()
    asset_keys = [ctx["asset_key"], ctx["repo_asset_key"]]
    asset_rows = (
        db.execute(
            text(
                """
                SELECT asset_key, name, environment, criticality, verified
                FROM assets
                WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                ORDER BY asset_key
                """
            ),
            {"asset_keys": asset_keys},
        )
        .mappings()
        .all()
    )
    telemetry_events = int(
        db.execute(
            text(
                """
                SELECT COUNT(*)
                FROM security_events
                WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                """
            ),
            {"asset_keys": asset_keys},
        ).scalar()
        or 0
    )
    alert_count = int(
        db.execute(
            text(
                """
                SELECT COUNT(*)
                FROM security_alerts
                WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                """
            ),
            {"asset_keys": asset_keys},
        ).scalar()
        or 0
    )
    incident_count = int(
        db.execute(
            text(
                """
                SELECT COUNT(DISTINCT incident_id)
                FROM incident_alerts
                WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                """
            ),
            {"asset_keys": asset_keys},
        ).scalar()
        or 0
    )
    finding_count = int(
        db.execute(
            text(
                """
                SELECT COUNT(*)
                FROM findings f
                LEFT JOIN assets a ON a.asset_id = f.asset_id
                WHERE a.asset_key = :repo_asset_key
                   OR f.finding_key LIKE :finding_prefix
                """
            ),
            {
                "repo_asset_key": ctx["repo_asset_key"],
                "finding_prefix": f"{ctx['repo_asset_key']}:%",
            },
        ).scalar()
        or 0
    )
    attack_lab_runs = int(
        db.execute(
            text(
                """
                SELECT COUNT(*)
                FROM attack_lab_runs
                WHERE target_asset_key = :asset_key
                   OR requested_by = :requested_by
                """
            ),
            {"asset_key": ctx["asset_key"], "requested_by": SEED_ACTOR},
        ).scalar()
        or 0
    )
    latest_seed = (
        db.execute(
            text(
                """
                SELECT created_at, details
                FROM audit_events
                WHERE action = :action
                  AND details ->> 'seed_version' = :seed_version
                ORDER BY created_at DESC
                LIMIT 1
                """
            ),
            {"action": SEED_ACTION, "seed_version": ctx["seed_version"]},
        )
        .mappings()
        .first()
    )
    detection_rule = (
        db.execute(
            text(
                """
                SELECT rule_id, name, enabled, last_tested_at, last_test_matches
                FROM detection_rules
                WHERE name = :rule_name
                """
            ),
            {"rule_name": ctx["rule_name"]},
        )
        .mappings()
        .first()
    )
    return {
        **ctx,
        "seeded": bool(latest_seed),
        "assets_present": len(asset_rows),
        "assets": [dict(row) for row in asset_rows],
        "telemetry_events": telemetry_events,
        "alerts": alert_count,
        "incidents": incident_count,
        "repository_findings": finding_count,
        "attack_lab_runs": attack_lab_runs,
        "detection_rule": dict(detection_rule) if detection_rule else None,
        "latest_seed_at": (
            latest_seed["created_at"].isoformat()
            if latest_seed and hasattr(latest_seed.get("created_at"), "isoformat")
            else None
        ),
        "latest_seed_details": dict(latest_seed.get("details") or {}) if latest_seed else None,
    }


def reset_cyberlab_demo(*, tenant_id: str | None = None) -> dict[str, Any]:
    ctx = _demo_seed_context()
    asset_keys = [ctx["asset_key"], ctx["repo_asset_key"]]
    effective_tenant_id = _current_tenant_id(tenant_id)
    tenant_token = tenant_id_ctx.set(effective_tenant_id)
    db = SessionLocal()
    try:
        _pin_session_tenant(db, effective_tenant_id)
        cleanup = _cleanup_curated_site_noise(db, preserve_asset_keys=asset_keys)
        asset_rows = (
            db.execute(
                text(
                    """
                    SELECT asset_id, asset_key
                    FROM assets
                    WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                    """
                ),
                {"asset_keys": asset_keys},
            )
            .mappings()
            .all()
        )
        asset_ids = [int(row["asset_id"]) for row in asset_rows if row.get("asset_id") is not None]
        incident_ids = [
            int(row["incident_id"])
            for row in (
                db.execute(
                    text(
                        """
                        SELECT DISTINCT incident_id
                        FROM incident_alerts
                        WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                        """
                    ),
                    {"asset_keys": asset_keys},
                )
                .mappings()
                .all()
            )
            if row.get("incident_id") is not None
        ]

        _merge_cleanup_count(
            cleanup,
            "incidents",
            db.execute(
                text(
                    """
                    DELETE FROM incidents
                    WHERE id = ANY(CAST(:incident_ids AS integer[]))
                    """
                ),
                {"incident_ids": incident_ids or [0]},
            ).rowcount,
        )
        _merge_cleanup_count(
            cleanup,
            "alert_ai_guidance",
            db.execute(
                text(
                    """
                    DELETE FROM alert_ai_guidance
                    WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                    """
                ),
                {"asset_keys": asset_keys},
            ).rowcount,
        )
        _merge_cleanup_count(
            cleanup,
            "asset_ai_diagnoses",
            db.execute(
                text(
                    """
                    DELETE FROM asset_ai_diagnoses
                    WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                    """
                ),
                {"asset_keys": asset_keys},
            ).rowcount,
        )
        _merge_cleanup_count(
            cleanup,
            "threat_ioc_sightings",
            db.execute(
                text(
                    """
                    DELETE FROM threat_ioc_sightings
                    WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                    """
                ),
                {"asset_keys": asset_keys},
            ).rowcount,
        )
        _merge_cleanup_count(
            cleanup,
            "asset_anomaly_scores",
            db.execute(
                text(
                    """
                    DELETE FROM asset_anomaly_scores
                    WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                    """
                ),
                {"asset_keys": asset_keys},
            ).rowcount,
        )
        _merge_cleanup_count(
            cleanup,
            "security_alerts",
            db.execute(
                text(
                    """
                    DELETE FROM security_alerts
                    WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                    """
                ),
                {"asset_keys": asset_keys},
            ).rowcount,
        )
        _merge_cleanup_count(
            cleanup,
            "security_events",
            db.execute(
                text(
                    """
                    DELETE FROM security_events
                    WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                    """
                ),
                {"asset_keys": asset_keys},
            ).rowcount,
        )
        _merge_cleanup_count(
            cleanup,
            "attack_lab_runs",
            db.execute(
                text(
                    """
                    DELETE FROM attack_lab_runs
                    WHERE target_asset_key = ANY(CAST(:asset_keys AS text[]))
                       OR requested_by = :requested_by
                    """
                ),
                {"asset_keys": asset_keys, "requested_by": SEED_ACTOR},
            ).rowcount,
        )
        _merge_cleanup_count(
            cleanup,
            "scan_jobs",
            db.execute(
                text(
                    """
                    DELETE FROM scan_jobs
                    WHERE requested_by = :requested_by
                       OR target_asset_id = ANY(CAST(:asset_ids AS integer[]))
                    """
                ),
                {"requested_by": SEED_ACTOR, "asset_ids": asset_ids or [0]},
            ).rowcount,
        )
        _merge_cleanup_count(
            cleanup,
            "scan_jobs",
            db.execute(
                text(
                    """
                    DELETE FROM scan_jobs
                    WHERE job_type = 'threat_intel_refresh'
                    """
                )
            ).rowcount,
        )
        _merge_cleanup_count(
            cleanup,
            "detection_rules",
            db.execute(
                text(
                    """
                    DELETE FROM detection_rules
                    WHERE name = :rule_name
                       OR (created_by = :created_by AND rule_key LIKE 'cyberlab-demo-%')
                    """
                ),
                {"rule_name": ctx["rule_name"], "created_by": SEED_ACTOR},
            ).rowcount,
        )
        _merge_cleanup_count(
            cleanup,
            "findings",
            db.execute(
                text(
                    """
                    DELETE FROM findings
                    WHERE asset_id = ANY(CAST(:asset_ids AS integer[]))
                       OR finding_key LIKE :finding_prefix
                    """
                ),
                {"asset_ids": asset_ids or [0], "finding_prefix": f"{ctx['repo_asset_key']}:%"},
            ).rowcount,
        )
        _merge_cleanup_count(
            cleanup,
            "threat_iocs",
            db.execute(
                text(
                    """
                    DELETE FROM threat_iocs
                    WHERE source = :source
                    """
                ),
                {"source": ctx["ioc_source"]},
            ).rowcount,
        )
        _merge_cleanup_count(
            cleanup,
            "risk_entity_snapshots",
            db.execute(
                text(
                    """
                    DELETE FROM risk_entity_snapshots
                    WHERE entity_key = ANY(CAST(:entity_keys AS text[]))
                    """
                ),
                {"entity_keys": asset_keys},
            ).rowcount,
        )
        _merge_cleanup_count(
            cleanup,
            "posture_anomalies",
            db.execute(text("DELETE FROM posture_anomalies")).rowcount,
        )
        _merge_cleanup_count(
            cleanup,
            "posture_report_snapshots",
            db.execute(text("DELETE FROM posture_report_snapshots")).rowcount,
        )
        _merge_cleanup_count(
            cleanup,
            "audit_events",
            db.execute(
                text(
                    """
                    DELETE FROM audit_events
                    WHERE action = :seed_action
                       OR (user_name = :seed_actor AND asset_key = ANY(CAST(:asset_keys AS text[])))
                    """
                ),
                {
                    "seed_action": SEED_ACTION,
                    "seed_actor": SEED_ACTOR,
                    "asset_keys": asset_keys,
                },
            ).rowcount,
        )
        _merge_cleanup_count(
            cleanup,
            "assets",
            db.execute(
                text(
                    """
                    DELETE FROM assets
                    WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                    """
                ),
                {"asset_keys": asset_keys},
            ).rowcount,
        )
        db.commit()
    finally:
        db.close()
        tenant_id_ctx.reset(tenant_token)

    seeded = run_cyberlab_auto_seed(force=True)
    search_sync: dict[str, Any] | None = None
    search_sync_error: str | None = None
    sync_db = SessionLocal()
    try:
        _pin_session_tenant(sync_db, effective_tenant_id)
        search_sync = _sync_curated_site_opensearch_assets(sync_db)
    except Exception as exc:
        logger.exception("curated_site_opensearch_sync_failed: %s", exc)
        search_sync_error = str(exc)
    finally:
        sync_db.close()
    result = {"reset": True, "cleanup": cleanup, "seed": seeded}
    if search_sync is not None:
        result["search_sync"] = search_sync
    if search_sync_error:
        result["search_sync_error"] = search_sync_error
    return result
