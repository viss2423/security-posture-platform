"""Attack surface discovery, drift, and exposure scoring services."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import UTC, datetime, timedelta
from threading import Thread
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import text

from .db import SessionLocal

DEFAULT_CERT_SALT = "stable"
MANAGEMENT_PORTS = {22, 3389, 5432, 3306, 6379, 9200, 27017}
PORT_TO_SERVICE = {
    22: "ssh",
    80: "http",
    443: "https",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    9200: "opensearch",
}


def _safe_json(value: Any, *, default: Any) -> Any:
    if isinstance(value, type(default)):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return default
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return default
        if isinstance(parsed, type(default)):
            return parsed
    return default


def _normalize_host(address: str | None, fallback: str) -> str:
    raw = str(address or "").strip()
    if not raw:
        return fallback
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        return str(parsed.hostname or fallback).strip() or fallback
    if "://" in raw:
        parsed = urlparse(raw)
        if parsed.hostname:
            return str(parsed.hostname).strip()
    if ":" in raw and raw.count(":") == 1:
        host, _, _port = raw.partition(":")
        if host.strip():
            return host.strip()
    return raw


def _guess_port(address: str | None, explicit_port: Any) -> int | None:
    if explicit_port is not None:
        try:
            value = int(explicit_port)
        except (TypeError, ValueError):
            value = 0
        if 1 <= value <= 65535:
            return value
    raw = str(address or "").strip()
    if not raw:
        return None
    if raw.startswith("https://"):
        parsed = urlparse(raw)
        return int(parsed.port or 443)
    if raw.startswith("http://"):
        parsed = urlparse(raw)
        return int(parsed.port or 80)
    if "://" in raw:
        parsed = urlparse(raw)
        if parsed.port:
            return int(parsed.port)
    if ":" in raw and raw.count(":") == 1:
        _host, _sep, maybe_port = raw.partition(":")
        try:
            value = int(maybe_port.strip())
        except (TypeError, ValueError):
            value = 0
        if 1 <= value <= 65535:
            return value
    return None


def _is_internet_exposed(host: str) -> bool:
    candidate = str(host or "").strip().lower()
    if not candidate:
        return False
    if candidate in {"localhost", "127.0.0.1"} or candidate.endswith(".local"):
        return False
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return True
    return not (ip.is_private or ip.is_loopback or ip.is_link_local)


def _serialize_datetimes(payload: dict[str, Any], keys: list[str]) -> dict[str, Any]:
    out = dict(payload)
    for key in keys:
        value = out.get(key)
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
    return out


def _insert_drift_event(
    db: Any,
    *,
    run_id: int,
    event_type: str,
    severity: str,
    asset_key: str | None = None,
    hostname: str | None = None,
    domain: str | None = None,
    port: int | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    db.execute(
        text(
            """
            INSERT INTO attack_surface_drift_events (
              run_id,
              event_type,
              severity,
              asset_key,
              hostname,
              domain,
              port,
              details_json
            )
            VALUES (
              :run_id,
              :event_type,
              :severity,
              :asset_key,
              :hostname,
              :domain,
              :port,
              CAST(:details_json AS jsonb)
            )
            """
        ),
        {
            "run_id": int(run_id),
            "event_type": event_type,
            "severity": severity,
            "asset_key": asset_key,
            "hostname": hostname,
            "domain": domain,
            "port": port,
            "details_json": json.dumps(details or {}),
        },
    )


def _exposure_level(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _upsert_exposure(
    db: Any,
    *,
    run_id: int,
    asset_key: str,
    internet_exposed: bool,
    ports: list[int],
) -> dict[str, Any]:
    port_set = sorted({int(item) for item in ports if 1 <= int(item) <= 65535})
    management = sorted([item for item in port_set if item in MANAGEMENT_PORTS])
    service_risk = min(45, len(port_set) * 5)
    management_risk = min(36, len(management) * 12)
    exposure_score = min(100, (35 if internet_exposed else 5) + service_risk + management_risk)
    level = _exposure_level(exposure_score)
    details = {
        "open_ports": port_set,
        "management_ports": management,
    }
    row = (
        db.execute(
            text(
                """
                INSERT INTO attack_surface_exposures (
                  asset_key,
                  run_id,
                  internet_exposed,
                  open_port_count,
                  open_management_ports,
                  service_risk,
                  exposure_score,
                  exposure_level,
                  details_json,
                  updated_at
                )
                VALUES (
                  :asset_key,
                  :run_id,
                  :internet_exposed,
                  :open_port_count,
                  CAST(:open_management_ports AS text[]),
                  :service_risk,
                  :exposure_score,
                  :exposure_level,
                  CAST(:details_json AS jsonb),
                  NOW()
                )
                ON CONFLICT (asset_key) DO UPDATE
                SET
                  run_id = EXCLUDED.run_id,
                  internet_exposed = EXCLUDED.internet_exposed,
                  open_port_count = EXCLUDED.open_port_count,
                  open_management_ports = EXCLUDED.open_management_ports,
                  service_risk = EXCLUDED.service_risk,
                  exposure_score = EXCLUDED.exposure_score,
                  exposure_level = EXCLUDED.exposure_level,
                  details_json = EXCLUDED.details_json,
                  updated_at = NOW()
                RETURNING
                  asset_key,
                  run_id,
                  internet_exposed,
                  open_port_count,
                  open_management_ports,
                  service_risk,
                  exposure_score,
                  exposure_level,
                  updated_at
                """
            ),
            {
                "asset_key": asset_key,
                "run_id": int(run_id),
                "internet_exposed": bool(internet_exposed),
                "open_port_count": len(port_set),
                "open_management_ports": [str(item) for item in management],
                "service_risk": int(service_risk),
                "exposure_score": int(exposure_score),
                "exposure_level": level,
                "details_json": json.dumps(details),
            },
        )
        .mappings()
        .first()
    )
    return _serialize_datetimes(dict(row or {}), ["updated_at"])


def run_attack_surface_discovery(
    db: Any,
    *,
    requested_by: str,
    source_job_id: int | None = None,
    domains: list[str] | None = None,
    cert_salt: str | None = None,
) -> dict[str, Any]:
    run_row = (
        db.execute(
            text(
                """
                INSERT INTO attack_surface_discovery_runs (
                  status,
                  requested_by,
                  source_job_id,
                  metadata_json
                )
                VALUES (
                  'running',
                  :requested_by,
                  :source_job_id,
                  CAST(:metadata_json AS jsonb)
                )
                RETURNING run_id, status, requested_by, source_job_id, started_at, metadata_json
                """
            ),
            {
                "requested_by": requested_by,
                "source_job_id": source_job_id,
                "metadata_json": json.dumps({"domains": domains or [], "cert_salt": cert_salt or ""}),
            },
        )
        .mappings()
        .first()
    )
    if not run_row:
        raise RuntimeError("attack_surface_run_create_failed")
    run_id = int(run_row["run_id"])

    previous_run = (
        db.execute(
            text(
                """
                SELECT run_id, metadata_json
                FROM attack_surface_discovery_runs
                WHERE status = 'done' AND run_id <> :run_id
                ORDER BY run_id DESC
                LIMIT 1
                """
            ),
            {"run_id": run_id},
        )
        .mappings()
        .first()
    )
    previous_run_id = int(previous_run["run_id"]) if previous_run else None
    previous_domains = set(
        _safe_json((previous_run or {}).get("metadata_json"), default={}).get("domains") or []
    )

    assets = (
        db.execute(
            text(
                """
                SELECT asset_key, address, port, metadata
                FROM assets
                WHERE COALESCE(is_active, TRUE) = TRUE
                ORDER BY asset_id ASC
                """
            )
        )
        .mappings()
        .all()
    )

    host_rows: list[dict[str, Any]] = []
    host_ports: dict[str, set[int]] = {}
    cert_seed = (cert_salt or DEFAULT_CERT_SALT).strip() or DEFAULT_CERT_SALT

    for asset in assets:
        asset_key = str(asset.get("asset_key") or "").strip()
        if not asset_key:
            continue
        address = str(asset.get("address") or "").strip()
        host = _normalize_host(address, asset_key)
        internet_exposed = _is_internet_exposed(host)
        metadata = _safe_json(asset.get("metadata"), default={})

        host_row = (
            db.execute(
                text(
                    """
                    INSERT INTO attack_surface_hosts (
                      run_id,
                      asset_key,
                      hostname,
                      ip_address,
                      internet_exposed,
                      source
                    )
                    VALUES (
                      :run_id,
                      :asset_key,
                      :hostname,
                      :ip_address,
                      :internet_exposed,
                      :source
                    )
                    RETURNING host_id, run_id, asset_key, hostname, ip_address, internet_exposed, source, discovered_at
                    """
                ),
                {
                    "run_id": run_id,
                    "asset_key": asset_key,
                    "hostname": host,
                    "ip_address": host if host.replace(".", "").isdigit() else None,
                    "internet_exposed": internet_exposed,
                    "source": "asset_inventory",
                },
            )
            .mappings()
            .first()
        )
        if not host_row:
            continue
        host_data = _serialize_datetimes(dict(host_row), ["discovered_at"])
        host_rows.append(host_data)

        ports = set()
        guessed = _guess_port(address, asset.get("port"))
        if guessed is not None:
            ports.add(int(guessed))
        metadata_ports = metadata.get("open_ports")
        if isinstance(metadata_ports, list):
            for entry in metadata_ports:
                try:
                    port = int(entry)
                except (TypeError, ValueError):
                    continue
                if 1 <= port <= 65535:
                    ports.add(port)
        if not ports:
            ports.add(443 if str(address).startswith("https://") else 80)
        host_ports[asset_key] = set(ports)

        for port in sorted(ports):
            db.execute(
                text(
                    """
                    INSERT INTO attack_surface_services (
                      run_id,
                      host_id,
                      asset_key,
                      hostname,
                      port,
                      protocol,
                      service_name,
                      service_version
                    )
                    VALUES (
                      :run_id,
                      :host_id,
                      :asset_key,
                      :hostname,
                      :port,
                      'tcp',
                      :service_name,
                      :service_version
                    )
                    """
                ),
                {
                    "run_id": run_id,
                    "host_id": int(host_data["host_id"]),
                    "asset_key": asset_key,
                    "hostname": host,
                    "port": int(port),
                    "service_name": PORT_TO_SERVICE.get(port, "unknown"),
                    "service_version": str(metadata.get("service_version") or "").strip() or None,
                },
            )

        if 443 in ports or str(address).startswith("https://"):
            fingerprint = hashlib.sha256(f"{host}|{cert_seed}".encode("utf-8")).hexdigest()
            now = datetime.now(UTC)
            db.execute(
                text(
                    """
                    INSERT INTO attack_surface_certificates (
                      run_id,
                      host_id,
                      asset_key,
                      hostname,
                      common_name,
                      issuer,
                      serial_number,
                      fingerprint_sha256,
                      not_before,
                      not_after
                    )
                    VALUES (
                      :run_id,
                      :host_id,
                      :asset_key,
                      :hostname,
                      :common_name,
                      :issuer,
                      :serial_number,
                      :fingerprint_sha256,
                      :not_before,
                      :not_after
                    )
                    """
                ),
                {
                    "run_id": run_id,
                    "host_id": int(host_data["host_id"]),
                    "asset_key": asset_key,
                    "hostname": host,
                    "common_name": host,
                    "issuer": "SecPlat Lab CA",
                    "serial_number": hashlib.md5(host.encode("utf-8")).hexdigest()[:16],
                    "fingerprint_sha256": fingerprint,
                    "not_before": now - timedelta(days=1),
                    "not_after": now + timedelta(days=90),
                },
            )

    current_hostnames = {str(row.get("hostname") or "") for row in host_rows}
    current_ports = {
        (str(row.get("hostname") or ""), int(port))
        for row in host_rows
        for port in sorted(host_ports.get(str(row.get("asset_key") or ""), set()))
    }

    previous_hosts: set[str] = set()
    previous_ports: set[tuple[str, int]] = set()
    previous_certs: dict[str, str] = {}

    if previous_run_id:
        prev_host_rows = (
            db.execute(
                text(
                    """
                    SELECT hostname
                    FROM attack_surface_hosts
                    WHERE run_id = :run_id
                    """
                ),
                {"run_id": previous_run_id},
            )
            .mappings()
            .all()
        )
        previous_hosts = {str(row.get("hostname") or "") for row in prev_host_rows}
        prev_port_rows = (
            db.execute(
                text(
                    """
                    SELECT hostname, port
                    FROM attack_surface_services
                    WHERE run_id = :run_id
                    """
                ),
                {"run_id": previous_run_id},
            )
            .mappings()
            .all()
        )
        previous_ports = {
            (str(row.get("hostname") or ""), int(row.get("port") or 0))
            for row in prev_port_rows
            if int(row.get("port") or 0) > 0
        }
        prev_cert_rows = (
            db.execute(
                text(
                    """
                    SELECT hostname, fingerprint_sha256
                    FROM attack_surface_certificates
                    WHERE run_id = :run_id
                    """
                ),
                {"run_id": previous_run_id},
            )
            .mappings()
            .all()
        )
        previous_certs = {
            str(row.get("hostname") or ""): str(row.get("fingerprint_sha256") or "")
            for row in prev_cert_rows
        }

    for row in host_rows:
        hostname = str(row.get("hostname") or "")
        if hostname and hostname not in previous_hosts:
            _insert_drift_event(
                db,
                run_id=run_id,
                event_type="new_host",
                severity="medium",
                asset_key=str(row.get("asset_key") or "") or None,
                hostname=hostname,
                details={"internet_exposed": bool(row.get("internet_exposed"))},
            )

    for hostname, port in sorted(current_ports):
        if (hostname, port) not in previous_ports:
            _insert_drift_event(
                db,
                run_id=run_id,
                event_type="new_port",
                severity="high" if port in MANAGEMENT_PORTS else "medium",
                hostname=hostname,
                port=port,
                details={"management_port": bool(port in MANAGEMENT_PORTS)},
            )

    domain_items = [str(item).strip().lower() for item in (domains or []) if str(item).strip()]
    current_domains = set(domain_items)
    for domain in sorted(current_domains):
        if domain not in previous_domains:
            _insert_drift_event(
                db,
                run_id=run_id,
                event_type="new_subdomain",
                severity="medium",
                domain=domain,
            )

    cert_rows = (
        db.execute(
            text(
                """
                SELECT hostname, asset_key, fingerprint_sha256
                FROM attack_surface_certificates
                WHERE run_id = :run_id
                """
            ),
            {"run_id": run_id},
        )
        .mappings()
        .all()
    )
    for row in cert_rows:
        hostname = str(row.get("hostname") or "")
        fingerprint = str(row.get("fingerprint_sha256") or "")
        if hostname and previous_certs.get(hostname) and previous_certs.get(hostname) != fingerprint:
            _insert_drift_event(
                db,
                run_id=run_id,
                event_type="unexpected_cert_change",
                severity="high",
                asset_key=str(row.get("asset_key") or "") or None,
                hostname=hostname,
                details={"previous_fingerprint": previous_certs.get(hostname), "fingerprint": fingerprint},
            )

    exposures: list[dict[str, Any]] = []
    for row in host_rows:
        asset_key = str(row.get("asset_key") or "").strip()
        if not asset_key:
            continue
        exposure = _upsert_exposure(
            db,
            run_id=run_id,
            asset_key=asset_key,
            internet_exposed=bool(row.get("internet_exposed")),
            ports=sorted(host_ports.get(asset_key, set())),
        )
        if exposure:
            exposures.append(exposure)

    summary = {
        "hosts_discovered": len(host_rows),
        "services_discovered": int(
            db.execute(
                text("SELECT COUNT(*) FROM attack_surface_services WHERE run_id = :run_id"),
                {"run_id": run_id},
            ).scalar_one()
        ),
        "certificates_discovered": int(
            db.execute(
                text("SELECT COUNT(*) FROM attack_surface_certificates WHERE run_id = :run_id"),
                {"run_id": run_id},
            ).scalar_one()
        ),
        "drift_events": int(
            db.execute(
                text("SELECT COUNT(*) FROM attack_surface_drift_events WHERE run_id = :run_id"),
                {"run_id": run_id},
            ).scalar_one()
        ),
        "assets_scored": len(exposures),
    }
    db.execute(
        text(
            """
            UPDATE attack_surface_discovery_runs
            SET
              status = 'done',
              finished_at = NOW(),
              summary_json = CAST(:summary_json AS jsonb),
              metadata_json = CAST(:metadata_json AS jsonb)
            WHERE run_id = :run_id
            """
        ),
        {
            "run_id": run_id,
            "summary_json": json.dumps(summary),
            "metadata_json": json.dumps({"domains": domain_items, "cert_salt": cert_seed}),
        },
    )
    return {
        "run_id": run_id,
        "status": "done",
        "requested_by": requested_by,
        "source_job_id": source_job_id,
        "summary": summary,
    }


def run_attack_surface_discovery_job(job_id: int) -> None:
    db = SessionLocal()
    try:
        db.execute(
            text(
                """
                UPDATE scan_jobs
                SET status = 'running', started_at = NOW(), finished_at = NULL, error = NULL
                WHERE job_id = :job_id
                """
            ),
            {"job_id": int(job_id)},
        )
        db.commit()

        row = (
            db.execute(
                text(
                    """
                    SELECT requested_by, job_params_json
                    FROM scan_jobs
                    WHERE job_id = :job_id
                    """
                ),
                {"job_id": int(job_id)},
            )
            .mappings()
            .first()
        )
        if not row:
            raise RuntimeError("attack_surface_job_not_found")
        params = _safe_json(row.get("job_params_json"), default={})
        domains = params.get("domains")
        cert_salt = params.get("cert_salt")
        if not isinstance(domains, list):
            domains = []
        result = run_attack_surface_discovery(
            db,
            requested_by=str(row.get("requested_by") or "system"),
            source_job_id=int(job_id),
            domains=[str(item) for item in domains if str(item).strip()],
            cert_salt=str(cert_salt or "").strip() or None,
        )
        db.execute(
            text(
                """
                UPDATE scan_jobs
                SET
                  status = 'done',
                  finished_at = NOW(),
                  log_output = COALESCE(log_output, '') || :summary || E'\n',
                  error = NULL
                WHERE job_id = :job_id
                """
            ),
            {
                "job_id": int(job_id),
                "summary": (
                    f"attack_surface_discovery run_id={result.get('run_id')} "
                    f"hosts={result.get('summary', {}).get('hosts_discovered', 0)} "
                    f"services={result.get('summary', {}).get('services_discovered', 0)} "
                    f"drift={result.get('summary', {}).get('drift_events', 0)}"
                ),
            },
        )
        db.commit()
    except Exception as exc:
        db.execute(
            text(
                """
                UPDATE scan_jobs
                SET
                  status = 'failed',
                  finished_at = NOW(),
                  error = :error,
                  log_output = COALESCE(log_output, '') || :summary || E'\n'
                WHERE job_id = :job_id
                """
            ),
            {
                "job_id": int(job_id),
                "error": str(exc),
                "summary": f"attack_surface_discovery failed: {exc}",
            },
        )
        db.commit()
    finally:
        db.close()


def launch_attack_surface_discovery_job(job_id: int) -> None:
    thread = Thread(target=run_attack_surface_discovery_job, args=(int(job_id),), daemon=True)
    thread.start()

