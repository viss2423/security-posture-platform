"""OSV dependency scanning helpers."""

from __future__ import annotations

import hashlib
import json
import subprocess
from typing import Any

OSV_SOURCE = "osv_scanner"
OSV_CATEGORY = "dependency_vulnerability"


def _finding_key(
    asset_key: str,
    source_path: str,
    package_name: str,
    package_version: str,
    vulnerability_id: str,
) -> str:
    raw = f"{asset_key}:{source_path}:{package_name}:{package_version}:{vulnerability_id}:{OSV_SOURCE}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _severity_from_score(value: float) -> str:
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    return "low"


def _severity_from_database(value: Any) -> str | None:
    normalized = str(value or "").strip().lower()
    mapping = {
        "critical": "critical",
        "high": "high",
        "moderate": "medium",
        "medium": "medium",
        "low": "low",
    }
    return mapping.get(normalized)


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


def _severity_for_vulnerability(vulnerability: dict[str, Any], group: dict[str, Any]) -> str:
    max_severity = group.get("max_severity")
    try:
        if max_severity is not None:
            return _severity_from_score(float(max_severity))
    except (TypeError, ValueError):
        pass
    db_severity = _severity_from_database(
        (vulnerability.get("database_specific") or {}).get("severity")
    )
    return db_severity or "medium"


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
                severity = _severity_for_vulnerability(vulnerability, group)

                evidence_lines = [title]
                if source_path:
                    evidence_lines.append(f"Source: {source_path}")
                if aliases:
                    evidence_lines.append(f"Aliases: {', '.join(aliases[:4])}")
                evidence = "\n".join(evidence_lines)

                if fixed_version:
                    remediation = f"Upgrade {package_name} from {package_version} to {fixed_version} or later."
                else:
                    remediation = f"Review {package_name} and update to a non-affected release."

                metadata = {
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
                    "details_excerpt": str(vulnerability.get("details") or "").strip()[:2000]
                    or None,
                }

                findings.append(
                    {
                        "finding_key": _finding_key(
                            asset_key,
                            source_path,
                            package_name,
                            package_version,
                            vulnerability_id,
                        ),
                        "category": OSV_CATEGORY,
                        "title": title,
                        "severity": severity,
                        "confidence": "high",
                        "evidence": evidence,
                        "remediation": remediation,
                        "source": OSV_SOURCE,
                        "vulnerability_id": vulnerability_id,
                        "package_ecosystem": package_ecosystem or None,
                        "package_name": package_name,
                        "package_version": package_version,
                        "fixed_version": fixed_version,
                        "scanner_metadata_json": metadata,
                    }
                )
    return findings


def run_osv_scan(
    scan_path: str,
    *,
    asset_key: str,
    osv_scanner_bin: str = "osv-scanner",
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    command = [osv_scanner_bin, "scan", "source", "-r", scan_path, "--format", "json"]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    stderr = (completed.stderr or "").strip()
    stdout = (completed.stdout or "").strip()
    if not stdout:
        if "no package sources found" in stderr.lower():
            return {
                "command": command,
                "exit_code": completed.returncode,
                "stderr": stderr,
                "report": {"results": []},
                "findings": [],
            }
        raise ValueError("osv_scanner_empty_output")
    try:
        report = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("osv_scanner_invalid_json") from exc

    if completed.returncode not in (0, 1):
        if "no package sources found" in stderr.lower():
            return {
                "command": command,
                "exit_code": completed.returncode,
                "stderr": stderr,
                "report": {"results": []},
                "findings": [],
            }
        stderr_excerpt = stderr
        raise RuntimeError(f"osv_scanner_exit_{completed.returncode}: {stderr_excerpt[:300]}")

    return {
        "command": command,
        "exit_code": completed.returncode,
        "stderr": stderr,
        "report": report,
        "findings": parse_osv_report(report, asset_key=asset_key),
    }
