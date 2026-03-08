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

from sqlalchemy import text

from .attack_lab import run_attack_lab_job
from .db import SessionLocal
from .detections import run_detection_rule
from .risk_scoring import recompute_finding_risk
from .routers.findings import FindingUpsertBody, upsert_finding_record
from .settings import settings
from .telemetry import _read_events_from_file, ingest_telemetry_events, run_network_anomaly_job
from .threat_intel import _rebuild_asset_matches

logger = logging.getLogger("secplat.demo_seed")

SEED_ACTION = "cyberlab_demo_seed"
SEED_ACTOR = "system-cyberlab-seed"


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
                    metadata = CAST(:metadata AS jsonb)
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
            },
        )
        db.commit()
        return asset_id

    created = (
        db.execute(
            text(
                """
                INSERT INTO assets(
                  asset_key, type, name, address, owner, environment, criticality,
                  asset_type, tags, metadata, verified
                )
                VALUES(
                  :asset_key, :type_name, :name, :address, :owner, :environment, :criticality,
                  :asset_type, CAST(:tags AS text[]), CAST(:metadata AS jsonb), TRUE
                )
                RETURNING asset_id
                """
            ),
            {
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
    row = (
        db.execute(
            text(
                """
                INSERT INTO scan_jobs(job_type, requested_by, status, job_params_json)
                VALUES (:job_type, :requested_by, 'queued', CAST(:job_params_json AS jsonb))
                RETURNING job_id
                """
            ),
            {
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


def run_cyberlab_auto_seed(*, force: bool = False) -> dict[str, Any]:
    seed_version = str(settings.CYBERLAB_AUTO_SEED_ONCE_VERSION or "v1").strip() or "v1"
    asset_key = str(settings.CYBERLAB_DEMO_ASSET_KEY or "cyberlab-demo-asset").strip()
    repo_asset_key = str(settings.CYBERLAB_DEMO_REPO_ASSET_KEY or "cyberlab-demo-repo").strip()
    if not asset_key:
        raise RuntimeError("CYBERLAB_DEMO_ASSET_KEY must not be empty")
    if not repo_asset_key:
        raise RuntimeError("CYBERLAB_DEMO_REPO_ASSET_KEY must not be empty")

    db = SessionLocal()
    try:
        if not force and _seed_marker_exists(db, seed_version=seed_version):
            return {"seeded": False, "reason": "already_seeded", "seed_version": seed_version}

        _ensure_asset(
            db,
            asset_key=asset_key,
            type_name="external_web",
            name=f"{asset_key}.lab.local",
            address="172.20.0.15",
            owner="soc-lab",
            environment="prod",
            criticality="high",
            asset_type="external_web",
            tags=["cyberlab", "telemetry", "demo"],
            metadata={"seeded": True, "seed_version": seed_version},
        )
        _ensure_asset(
            db,
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
        ioc_asset_matches = _rebuild_asset_matches(db)

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

        attack_job_id = _create_job(
            db,
            job_type="attack_lab_run",
            params={"task_type": "port_scan", "target": "opensearch", "asset_key": asset_key},
        )
        run_attack_lab_job(attack_job_id)

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
            "attack_lab_job_id": attack_job_id,
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
