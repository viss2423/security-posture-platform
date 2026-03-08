"""Repository scan execution for OSV and Trivy jobs launched from the API."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text

from .db import SessionLocal
from .queue import publish_scan_job
from .risk_scoring import recompute_finding_risk
from .routers.findings import FindingUpsertBody, upsert_finding_record
from .settings import settings

logger = logging.getLogger("secplat.repository_scan")

OSV_SOURCE = "osv_scanner"
TRIVY_SOURCE = "trivy_fs"


def _finding_key(*parts: str) -> str:
    raw = ":".join(part.strip() for part in parts if part and part.strip())
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _normalized_severity(value: Any, *, default: str = "medium") -> str:
    normalized = str(value or "").strip().lower()
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "negligible": "low",
        "info": "info",
        "unknown": default,
    }
    return mapping.get(normalized, default)


def _trim_references(values: list[Any] | None, *, limit: int = 12) -> list[str]:
    out: list[str] = []
    for item in values or []:
        normalized = str(item or "").strip()
        if normalized and normalized not in out:
            out.append(normalized)
        if len(out) >= limit:
            break
    return out


def _job_log_line(message: str) -> str:
    return f"[{datetime.now(UTC).isoformat().replace('+00:00', 'Z')}] {message}"


def _osv_no_package_sources(stderr: str) -> bool:
    return "no package sources found" in stderr.strip().lower()


def _append_job_log(db, job_id: int, message: str) -> None:
    db.execute(
        text(
            """
            UPDATE scan_jobs
               SET log_output = COALESCE(log_output, '') || :line || E'\n'
             WHERE job_id = :job_id
            """
        ),
        {"job_id": job_id, "line": _job_log_line(message)},
    )
    db.commit()


def _set_job_running(db, job_id: int) -> None:
    db.execute(
        text(
            """
            UPDATE scan_jobs
               SET status = 'running',
                   started_at = NOW(),
                   finished_at = NULL,
                   error = NULL
             WHERE job_id = :job_id
            """
        ),
        {"job_id": job_id},
    )
    db.commit()


def _finish_job(
    db, job_id: int, *, ok: bool, error: str | None = None, message: str | None = None
) -> None:
    if message:
        _append_job_log(db, job_id, message)
    db.execute(
        text(
            """
            UPDATE scan_jobs
               SET status = :status,
                   finished_at = NOW(),
                   error = :error
             WHERE job_id = :job_id
            """
        ),
        {"job_id": job_id, "status": "done" if ok else "failed", "error": error},
    )
    db.commit()


def _ensure_repository_asset(
    db,
    *,
    asset_key: str,
    asset_name: str,
    scan_path: str,
    environment: str,
    criticality: str,
) -> None:
    existing = (
        db.execute(
            text("SELECT asset_id FROM assets WHERE asset_key = :asset_key"),
            {"asset_key": asset_key},
        )
        .mappings()
        .first()
    )
    if existing:
        return
    db.execute(
        text(
            """
            INSERT INTO assets(
              asset_key, type, name, asset_type, environment, criticality, tags, metadata
            )
            VALUES (
              :asset_key, 'app', :name, 'repository', :environment, :criticality,
              CAST(:tags AS text[]), CAST(:metadata AS jsonb)
            )
            """
        ),
        {
            "asset_key": asset_key,
            "name": asset_name,
            "environment": environment,
            "criticality": criticality,
            "tags": ["repository", "dependency-scan", "trivy-scan"],
            "metadata": json.dumps(
                {
                    "repository_scan": True,
                    "scan_path": scan_path,
                }
            ),
        },
    )
    db.commit()


def _reconcile_findings_for_source(
    db, *, asset_key: str, source: str, current_keys: set[str]
) -> int:
    rows = (
        db.execute(
            text(
                """
                SELECT f.finding_id, f.finding_key, COALESCE(f.status, 'open') AS status
                FROM findings f
                JOIN assets a ON a.asset_id = f.asset_id
                WHERE a.asset_key = :asset_key AND f.source = :source
                """
            ),
            {"asset_key": asset_key, "source": source},
        )
        .mappings()
        .all()
    )
    resolved = 0
    for row in rows:
        finding_key = str(row.get("finding_key") or "").strip()
        if not finding_key or finding_key in current_keys:
            continue
        if str(row.get("status") or "open").strip().lower() == "remediated":
            continue
        finding_id = int(row["finding_id"])
        db.execute(
            text("UPDATE findings SET status = 'remediated' WHERE finding_id = :finding_id"),
            {"finding_id": finding_id},
        )
        recompute_finding_risk(db, finding_id)
        resolved += 1
    db.commit()
    return resolved


def _group_index(groups: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for group in groups:
        for vuln_id in group.get("ids") or []:
            normalized = str(vuln_id or "").strip()
            if normalized:
                out[normalized] = group
    return out


def _matching_affected(
    vulnerability: dict[str, Any], *, package_name: str, package_ecosystem: str
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    normalized_ecosystem = package_ecosystem.strip().lower()
    for affected in vulnerability.get("affected") or []:
        package = affected.get("package") or {}
        affected_name = str(package.get("name") or "").strip()
        affected_ecosystem = str(package.get("ecosystem") or "").strip().lower()
        if affected_name != package_name:
            continue
        if (
            normalized_ecosystem
            and affected_ecosystem
            and affected_ecosystem != normalized_ecosystem
        ):
            continue
        matches.append(affected)
    return matches


def _affected_ranges(
    vulnerability: dict[str, Any], *, package_name: str, package_ecosystem: str
) -> list[dict[str, Any]]:
    ranges_out: list[dict[str, Any]] = []
    for affected in _matching_affected(
        vulnerability,
        package_name=package_name,
        package_ecosystem=package_ecosystem,
    ):
        for range_item in affected.get("ranges") or []:
            events_out = []
            for event in range_item.get("events") or []:
                normalized_event = {}
                for key in ("introduced", "fixed", "last_affected"):
                    value = event.get(key)
                    if value:
                        normalized_event[key] = str(value)
                if normalized_event:
                    events_out.append(normalized_event)
            if events_out:
                ranges_out.append(
                    {
                        "type": str(range_item.get("type") or "unknown"),
                        "events": events_out,
                    }
                )
    return ranges_out


def _fixed_version(affected_ranges: list[dict[str, Any]]) -> str | None:
    for range_item in affected_ranges:
        for event in range_item.get("events") or []:
            fixed = event.get("fixed")
            if fixed:
                return str(fixed)
    return None


def _aliases(vulnerability: dict[str, Any], group: dict[str, Any]) -> list[str]:
    values = []
    for item in [
        vulnerability.get("id"),
        *(vulnerability.get("aliases") or []),
        *(group.get("aliases") or []),
    ]:
        normalized = str(item or "").strip()
        if normalized and normalized not in values:
            values.append(normalized)
    return values


def _severity_from_score(value: float) -> str:
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    return "low"


def _severity_for_osv(vulnerability: dict[str, Any], group: dict[str, Any]) -> str:
    max_severity = group.get("max_severity")
    try:
        if max_severity is not None:
            return _severity_from_score(float(max_severity))
    except (TypeError, ValueError):
        pass
    return _normalized_severity((vulnerability.get("database_specific") or {}).get("severity"))


def parse_osv_report(report: dict[str, Any], *, asset_key: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in report.get("results") or []:
        source = result.get("source") or {}
        source_path = str(source.get("path") or "").strip()
        source_type = str(source.get("type") or "").strip()
        for package_entry in result.get("packages") or []:
            package = package_entry.get("package") or {}
            package_name = str(package.get("name") or "").strip()
            package_version = str(package.get("version") or "").strip()
            package_ecosystem = str(package.get("ecosystem") or "").strip()
            if not package_name or not package_version:
                continue
            groups = _group_index(package_entry.get("groups") or [])
            for vulnerability in package_entry.get("vulnerabilities") or []:
                vulnerability_id = str(vulnerability.get("id") or "").strip()
                group = groups.get(vulnerability_id) or {}
                aliases = _aliases(vulnerability, group)
                if not vulnerability_id and aliases:
                    vulnerability_id = aliases[0]
                if not vulnerability_id:
                    continue
                affected_ranges = _affected_ranges(
                    vulnerability,
                    package_name=package_name,
                    package_ecosystem=package_ecosystem,
                )
                fixed_version = _fixed_version(affected_ranges)
                summary = str(vulnerability.get("summary") or "").strip()
                title = summary or f"{vulnerability_id} in {package_name}"
                evidence_lines = [title]
                if source_path:
                    evidence_lines.append(f"Source: {source_path}")
                if aliases:
                    evidence_lines.append(f"Aliases: {', '.join(aliases[:4])}")
                findings.append(
                    {
                        "finding_key": _finding_key(
                            asset_key,
                            source_path,
                            package_name,
                            package_version,
                            vulnerability_id,
                            OSV_SOURCE,
                        ),
                        "category": "dependency_vulnerability",
                        "title": title,
                        "severity": _severity_for_osv(vulnerability, group),
                        "confidence": "high",
                        "evidence": "\n".join(evidence_lines),
                        "remediation": (
                            f"Upgrade {package_name} from {package_version} to {fixed_version} or later."
                            if fixed_version
                            else f"Review {package_name} and update to a non-affected release."
                        ),
                        "source": OSV_SOURCE,
                        "vulnerability_id": vulnerability_id,
                        "package_ecosystem": package_ecosystem or None,
                        "package_name": package_name,
                        "package_version": package_version,
                        "fixed_version": fixed_version,
                        "scanner_metadata_json": {
                            "source_path": source_path,
                            "source_type": source_type,
                            "aliases": aliases,
                            "max_severity": group.get("max_severity"),
                            "database_specific_severity": (
                                vulnerability.get("database_specific") or {}
                            ).get("severity"),
                            "published": vulnerability.get("published"),
                            "modified": vulnerability.get("modified"),
                            "references": [
                                ref.get("url")
                                for ref in (vulnerability.get("references") or [])
                                if ref.get("url")
                            ][:12],
                            "affected_ranges": affected_ranges,
                            "summary": summary or None,
                            "details_excerpt": str(vulnerability.get("details") or "").strip()[
                                :2000
                            ]
                            or None,
                        },
                    }
                )
    return findings


def _package_index(packages: list[dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for package in packages or []:
        package_id = str(package.get("ID") or "").strip()
        if package_id:
            out[package_id] = package
    return out


def _location_ranges(package_entry: dict[str, Any] | None) -> list[dict[str, int]]:
    ranges: list[dict[str, int]] = []
    for location in (package_entry or {}).get("Locations") or []:
        start_line = location.get("StartLine")
        end_line = location.get("EndLine")
        if isinstance(start_line, int) or isinstance(end_line, int):
            item: dict[str, int] = {}
            if isinstance(start_line, int):
                item["start_line"] = start_line
            if isinstance(end_line, int):
                item["end_line"] = end_line
            if item:
                ranges.append(item)
    return ranges


def _cause_lines(cause: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in ((cause.get("Code") or {}).get("Lines") or [])[:8]:
        entry: dict[str, Any] = {}
        number = line.get("Number")
        content = str(line.get("Content") or "").rstrip()
        if isinstance(number, int):
            entry["number"] = number
        if content:
            entry["content"] = content
        if "IsCause" in line:
            entry["is_cause"] = bool(line.get("IsCause"))
        if entry:
            out.append(entry)
    return out


def parse_trivy_report(report: dict[str, Any], *, asset_key: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in report.get("Results") or []:
        target = str(result.get("Target") or "").strip()
        class_name = str(result.get("Class") or "").strip()
        target_type = str(result.get("Type") or "").strip()
        packages = _package_index(result.get("Packages") or [])

        for vulnerability in result.get("Vulnerabilities") or []:
            vulnerability_id = str(vulnerability.get("VulnerabilityID") or "").strip()
            package_name = str(vulnerability.get("PkgName") or "").strip()
            package_version = str(vulnerability.get("InstalledVersion") or "").strip()
            fixed_version = str(vulnerability.get("FixedVersion") or "").strip() or None
            if not vulnerability_id or not package_name:
                continue
            package_entry = packages.get(str(vulnerability.get("PkgID") or "").strip()) or {}
            title = (
                str(vulnerability.get("Title") or "").strip()
                or f"{vulnerability_id} in {package_name}"
            )
            aliases = _trim_references(vulnerability.get("VendorIDs") or [], limit=8)
            evidence_lines = [title]
            if target:
                evidence_lines.append(f"Target: {target}")
            evidence_lines.append(
                f"Package: {package_name}@{package_version}"
                if package_version
                else f"Package: {package_name}"
            )
            relationship = str(package_entry.get("Relationship") or "").strip()
            if relationship:
                evidence_lines.append(f"Relationship: {relationship}")
            if aliases:
                evidence_lines.append(f"Aliases: {', '.join(aliases)}")
            findings.append(
                {
                    "finding_key": _finding_key(
                        asset_key,
                        TRIVY_SOURCE,
                        "vulnerability",
                        target,
                        package_name,
                        package_version,
                        vulnerability_id,
                    ),
                    "category": "dependency_vulnerability",
                    "title": title,
                    "severity": _normalized_severity(vulnerability.get("Severity")),
                    "confidence": "high",
                    "evidence": "\n".join(evidence_lines),
                    "remediation": (
                        f"Upgrade {package_name} from {package_version} to {fixed_version} or later."
                        if fixed_version
                        else f"Review {package_name}; Trivy did not report a fixed version."
                    ),
                    "source": TRIVY_SOURCE,
                    "vulnerability_id": vulnerability_id,
                    "package_ecosystem": target_type or None,
                    "package_name": package_name,
                    "package_version": package_version or None,
                    "fixed_version": fixed_version,
                    "scanner_metadata_json": {
                        "target": target or None,
                        "class": class_name or None,
                        "type": target_type or None,
                        "aliases": aliases,
                        "status": str(vulnerability.get("Status") or "").strip() or None,
                        "primary_url": str(vulnerability.get("PrimaryURL") or "").strip() or None,
                        "severity_source": (
                            str(vulnerability.get("SeveritySource") or "").strip() or None
                        ),
                        "data_source": vulnerability.get("DataSource") or None,
                        "published": vulnerability.get("PublishedDate"),
                        "modified": vulnerability.get("LastModifiedDate"),
                        "references": _trim_references(vulnerability.get("References") or []),
                        "cvss": vulnerability.get("CVSS") or None,
                        "description": str(vulnerability.get("Description") or "").strip()[:2000]
                        or None,
                        "package_purl": (
                            (vulnerability.get("PkgIdentifier") or {}).get("PURL")
                            or (package_entry.get("Identifier") or {}).get("PURL")
                            or None
                        ),
                        "locations": _location_ranges(package_entry),
                        "fingerprint": str(vulnerability.get("Fingerprint") or "").strip() or None,
                    },
                }
            )

        for misconfiguration in result.get("Misconfigurations") or []:
            check_id = str(misconfiguration.get("ID") or "").strip()
            namespace = str(misconfiguration.get("Namespace") or "").strip()
            title = (
                str(misconfiguration.get("Title") or "").strip()
                or str(misconfiguration.get("Message") or "").strip()
                or check_id
                or "Trivy misconfiguration"
            )
            message = str(misconfiguration.get("Message") or "").strip()
            cause = misconfiguration.get("CauseMetadata") or {}
            start_line = cause.get("StartLine")
            end_line = cause.get("EndLine")
            evidence_lines = [title]
            if target:
                evidence_lines.append(f"Target: {target}")
            if message:
                evidence_lines.append(f"Message: {message}")
            if isinstance(start_line, int):
                evidence_lines.append(
                    f"Location: lines {start_line}-{end_line}"
                    if isinstance(end_line, int) and end_line != start_line
                    else f"Location: line {start_line}"
                )
            findings.append(
                {
                    "finding_key": _finding_key(
                        asset_key,
                        TRIVY_SOURCE,
                        "misconfiguration",
                        target,
                        check_id or namespace or title,
                        str(start_line or ""),
                    ),
                    "category": "misconfiguration",
                    "title": title,
                    "severity": _normalized_severity(misconfiguration.get("Severity")),
                    "confidence": "high",
                    "evidence": "\n".join(evidence_lines),
                    "remediation": (
                        str(misconfiguration.get("Resolution") or "").strip()
                        or "Review the configuration and align it with the reported control."
                    ),
                    "source": TRIVY_SOURCE,
                    "vulnerability_id": None,
                    "package_ecosystem": None,
                    "package_name": None,
                    "package_version": None,
                    "fixed_version": None,
                    "scanner_metadata_json": {
                        "target": target or None,
                        "class": class_name or None,
                        "type": target_type or None,
                        "check_id": check_id or None,
                        "namespace": namespace or None,
                        "query": str(misconfiguration.get("Query") or "").strip() or None,
                        "primary_url": str(misconfiguration.get("PrimaryURL") or "").strip()
                        or None,
                        "references": _trim_references(misconfiguration.get("References") or []),
                        "status": str(misconfiguration.get("Status") or "").strip() or None,
                        "message": message or None,
                        "description": str(misconfiguration.get("Description") or "").strip()[:2000]
                        or None,
                        "cause": {
                            "provider": str(cause.get("Provider") or "").strip() or None,
                            "service": str(cause.get("Service") or "").strip() or None,
                            "start_line": start_line if isinstance(start_line, int) else None,
                            "end_line": end_line if isinstance(end_line, int) else None,
                            "code_lines": _cause_lines(cause),
                        },
                    },
                }
            )
    return findings


def _run_osv_scan(scan_path: str, *, asset_key: str) -> dict[str, Any]:
    command = [
        settings.OSV_SCANNER_BIN,
        "scan",
        "source",
        "-r",
        scan_path,
        "--format",
        "json",
    ]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=settings.OSV_SCANNER_TIMEOUT_SECONDS,
        check=False,
    )
    stderr = (completed.stderr or "").strip()
    stdout = (completed.stdout or "").strip()
    if not stdout:
        if _osv_no_package_sources(stderr):
            return {
                "exit_code": completed.returncode,
                "stderr": stderr,
                "findings": [],
            }
        raise ValueError("osv_scanner_empty_output")
    report = json.loads(stdout)
    if completed.returncode not in (0, 1):
        if _osv_no_package_sources(stderr):
            return {
                "exit_code": completed.returncode,
                "stderr": stderr,
                "findings": [],
            }
        raise RuntimeError(f"osv_scanner_exit_{completed.returncode}: {stderr[:300]}")
    return {
        "exit_code": completed.returncode,
        "stderr": stderr,
        "findings": parse_osv_report(report, asset_key=asset_key),
    }


def _run_trivy_scan(scan_path: str, *, asset_key: str, scanners: str) -> dict[str, Any]:
    command = [
        settings.TRIVY_BIN,
        "fs",
        "--format",
        "json",
        "--quiet",
        "--timeout",
        f"{max(int(settings.TRIVY_TIMEOUT_SECONDS), 1)}s",
        "--scanners",
        scanners,
        scan_path,
    ]
    env = os.environ.copy()
    env.setdefault("TRIVY_DISABLE_VEX_NOTICE", "true")
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=settings.TRIVY_TIMEOUT_SECONDS,
        check=False,
        env=env,
    )
    if completed.returncode != 0:
        stderr_excerpt = (completed.stderr or "").strip()
        raise RuntimeError(f"trivy_exit_{completed.returncode}: {stderr_excerpt[:300]}")
    stdout = (completed.stdout or "").strip()
    if not stdout:
        raise ValueError("trivy_empty_output")
    report = json.loads(stdout)
    return {
        "exit_code": completed.returncode,
        "stderr": (completed.stderr or "").strip(),
        "findings": parse_trivy_report(report, asset_key=asset_key),
    }


def _to_bool(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def run_repository_scan_job(job_id: int) -> None:
    db = SessionLocal()
    try:
        row = (
            db.execute(
                text(
                    """
                    SELECT job_id, requested_by, COALESCE(job_params_json, '{}'::jsonb) AS job_params_json
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
            return
        params = row.get("job_params_json") or {}
        if isinstance(params, str):
            try:
                params = json.loads(params)
            except json.JSONDecodeError:
                params = {}

        _set_job_running(db, job_id)
        scan_path = str(params.get("path") or settings.REPOSITORY_SCAN_DEFAULT_PATH).strip()
        asset_key = str(
            params.get("asset_key") or settings.REPOSITORY_SCAN_DEFAULT_ASSET_KEY
        ).strip()
        asset_name = str(
            params.get("asset_name") or settings.REPOSITORY_SCAN_DEFAULT_ASSET_NAME
        ).strip()
        environment = str(
            params.get("environment") or settings.REPOSITORY_SCAN_DEFAULT_ENVIRONMENT
        ).strip()
        criticality = str(
            params.get("criticality") or settings.REPOSITORY_SCAN_DEFAULT_CRITICALITY
        ).strip()
        trivy_scanners = str(params.get("trivy_scanners") or settings.TRIVY_SCANNERS).strip()
        enable_osv = _to_bool(params.get("enable_osv"), default=True)
        enable_trivy = _to_bool(params.get("enable_trivy"), default=True)

        if not scan_path:
            raise ValueError("repository_scan_path_missing")
        if not asset_key:
            raise ValueError("repository_scan_asset_key_missing")
        if not enable_osv and not enable_trivy:
            raise ValueError("enable_osv_or_trivy_required")

        _append_job_log(db, job_id, f"Repository scan started for {asset_key} at {scan_path}")
        _ensure_repository_asset(
            db,
            asset_key=asset_key,
            asset_name=asset_name or asset_key,
            scan_path=scan_path,
            environment=environment or "dev",
            criticality=criticality or "medium",
        )

        summary_parts: list[str] = []
        if enable_osv:
            result = _run_osv_scan(scan_path, asset_key=asset_key)
            current_keys: set[str] = set()
            for finding in result["findings"]:
                upsert_finding_record(
                    db,
                    FindingUpsertBody(
                        finding_key=finding["finding_key"],
                        asset_key=asset_key,
                        category=finding.get("category"),
                        title=finding["title"],
                        severity=finding.get("severity", "medium"),
                        confidence=finding.get("confidence", "high"),
                        evidence=finding.get("evidence"),
                        remediation=finding.get("remediation"),
                        source=finding.get("source"),
                        vulnerability_id=finding.get("vulnerability_id"),
                        package_ecosystem=finding.get("package_ecosystem"),
                        package_name=finding.get("package_name"),
                        package_version=finding.get("package_version"),
                        fixed_version=finding.get("fixed_version"),
                        scanner_metadata_json=finding.get("scanner_metadata_json"),
                    ),
                )
                current_keys.add(str(finding.get("finding_key") or ""))
            resolved = _reconcile_findings_for_source(
                db,
                asset_key=asset_key,
                source=OSV_SOURCE,
                current_keys=current_keys,
            )
            summary_parts.append(f"OSV detected {len(result['findings'])}, resolved {resolved}")
            _append_job_log(db, job_id, summary_parts[-1])

        if enable_trivy:
            result = _run_trivy_scan(scan_path, asset_key=asset_key, scanners=trivy_scanners)
            current_keys = set()
            for finding in result["findings"]:
                upsert_finding_record(
                    db,
                    FindingUpsertBody(
                        finding_key=finding["finding_key"],
                        asset_key=asset_key,
                        category=finding.get("category"),
                        title=finding["title"],
                        severity=finding.get("severity", "medium"),
                        confidence=finding.get("confidence", "high"),
                        evidence=finding.get("evidence"),
                        remediation=finding.get("remediation"),
                        source=finding.get("source"),
                        vulnerability_id=finding.get("vulnerability_id"),
                        package_ecosystem=finding.get("package_ecosystem"),
                        package_name=finding.get("package_name"),
                        package_version=finding.get("package_version"),
                        fixed_version=finding.get("fixed_version"),
                        scanner_metadata_json=finding.get("scanner_metadata_json"),
                    ),
                )
                current_keys.add(str(finding.get("finding_key") or ""))
            resolved = _reconcile_findings_for_source(
                db,
                asset_key=asset_key,
                source=TRIVY_SOURCE,
                current_keys=current_keys,
            )
            summary_parts.append(f"Trivy detected {len(result['findings'])}, resolved {resolved}")
            _append_job_log(db, job_id, summary_parts[-1])

        _finish_job(
            db,
            job_id,
            ok=True,
            message="Repository scan completed. " + "; ".join(summary_parts),
        )
    except Exception as exc:
        logger.exception("repository_scan_failed job_id=%s", job_id)
        _finish_job(
            db,
            job_id,
            ok=False,
            error=str(exc),
            message=f"Repository scan failed: {exc}",
        )
    finally:
        db.close()


def launch_repository_scan_job(job_id: int) -> None:
    db = SessionLocal()
    try:
        row = (
            db.execute(
                text(
                    """
                    SELECT target_asset_id, requested_by
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
            logger.warning("repository_scan_enqueue_missing_job job_id=%s", job_id)
            return
        requested_by = str((row or {}).get("requested_by") or "system")
        target_asset_id = (row or {}).get("target_asset_id")
    finally:
        db.close()
    published = publish_scan_job(
        int(job_id),
        "repository_scan",
        int(target_asset_id) if target_asset_id is not None else None,
        requested_by,
    )
    if not published:
        logger.warning("repository_scan_enqueue_failed job_id=%s", job_id)
