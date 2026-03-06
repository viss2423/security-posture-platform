"""Trivy filesystem scanning helpers."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from typing import Any

TRIVY_SOURCE = "trivy_fs"
TRIVY_VULNERABILITY_CATEGORY = "dependency_vulnerability"
TRIVY_MISCONFIGURATION_CATEGORY = "misconfiguration"


def _finding_key(*parts: str) -> str:
    raw = ":".join(part.strip() for part in parts if part and part.strip())
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _normalized_severity(value: Any, *, default: str = "medium") -> str:
    normalized = str(value or "").strip().lower()
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
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
            if package_version:
                evidence_lines.append(f"Package: {package_name}@{package_version}")
            else:
                evidence_lines.append(f"Package: {package_name}")
            relationship = str(package_entry.get("Relationship") or "").strip()
            if relationship:
                evidence_lines.append(f"Relationship: {relationship}")
            if aliases:
                evidence_lines.append(f"Aliases: {', '.join(aliases)}")
            evidence = "\n".join(evidence_lines)

            if fixed_version:
                remediation = (
                    f"Upgrade {package_name} from {package_version} to {fixed_version} or later."
                )
            else:
                remediation = f"Review {package_name}; Trivy did not report a fixed version."

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
                    "category": TRIVY_VULNERABILITY_CATEGORY,
                    "title": title,
                    "severity": _normalized_severity(vulnerability.get("Severity")),
                    "confidence": "high",
                    "evidence": evidence,
                    "remediation": remediation,
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
                if isinstance(end_line, int) and end_line != start_line:
                    evidence_lines.append(f"Location: lines {start_line}-{end_line}")
                else:
                    evidence_lines.append(f"Location: line {start_line}")
            if namespace:
                evidence_lines.append(f"Namespace: {namespace}")
            evidence = "\n".join(evidence_lines)

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
                    "category": TRIVY_MISCONFIGURATION_CATEGORY,
                    "title": title,
                    "severity": _normalized_severity(misconfiguration.get("Severity")),
                    "confidence": "high",
                    "evidence": evidence,
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


def run_trivy_scan(
    scan_path: str,
    *,
    asset_key: str,
    trivy_bin: str = "trivy",
    scanners: str = "vuln,misconfig",
    timeout_seconds: int = 1200,
) -> dict[str, Any]:
    command = [
        trivy_bin,
        "fs",
        "--format",
        "json",
        "--quiet",
        "--timeout",
        f"{max(int(timeout_seconds), 1)}s",
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
        timeout=timeout_seconds,
        check=False,
        env=env,
    )
    if completed.returncode != 0:
        stderr_excerpt = (completed.stderr or "").strip()
        raise RuntimeError(f"trivy_exit_{completed.returncode}: {stderr_excerpt[:300]}")

    stdout = (completed.stdout or "").strip()
    if not stdout:
        raise ValueError("trivy_empty_output")
    try:
        report = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("trivy_invalid_json") from exc

    return {
        "command": command,
        "exit_code": completed.returncode,
        "stderr": (completed.stderr or "").strip(),
        "report": report,
        "findings": parse_trivy_report(report, asset_key=asset_key),
    }
