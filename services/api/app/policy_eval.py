"""Phase B.2/Phase 4: evaluate policy bundle YAML rules with evidence output."""

from __future__ import annotations

from datetime import UTC, datetime
import re
from typing import Any

import yaml

OPEN_FINDING_STATUSES = {"open", "in_progress"}
HEADER_ALIASES = {
    "csp": "content-security-policy",
    "content-security-policy": "content-security-policy",
    "hsts": "strict-transport-security",
    "strict-transport-security": "strict-transport-security",
    "x-frame-options": "x-frame-options",
    "x-content-type-options": "x-content-type-options",
    "permissions-policy": "permissions-policy",
    "referrer-policy": "referrer-policy",
}


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _normalize_rule_params(rule: dict[str, Any]) -> dict[str, Any]:
    # Keep backward compatibility with existing {params: {...}} style,
    # and allow shorthand top-level keys in YAML.
    params = _as_dict(rule.get("params")).copy()
    for key in ("status", "min_score", "severity", "header", "min_version"):
        if key in rule and key not in params:
            params[key] = rule[key]
    return params


def parse_bundle_yaml(definition: str) -> list[dict[str, Any]]:
    """Parse YAML definition; return list of normalized rules."""
    try:
        data = yaml.safe_load(definition)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML: {e}") from e
    if not data or not isinstance(data, dict):
        raise ValueError("Definition must be a YAML object with a 'rules' list")
    rules = data.get("rules")
    if not isinstance(rules, list):
        raise ValueError("Definition must contain 'rules' as a list")
    out = []
    for i, raw_rule in enumerate(rules):
        if not isinstance(raw_rule, dict):
            raise ValueError(f"Rule {i} must be an object")
        rule_id = raw_rule.get("id") or f"rule_{i}"
        name = raw_rule.get("name") or rule_id
        rule_type = raw_rule.get("type")
        if not rule_type:
            raise ValueError(f"Rule {rule_id}: missing 'type'")
        out.append(
            {
                "id": str(rule_id),
                "name": str(name),
                "type": str(rule_type).strip().lower(),
                "params": _normalize_rule_params(raw_rule),
            }
        )
    return out


def _asset_key(asset: dict[str, Any]) -> str:
    return str(asset.get("asset_key") or asset.get("asset_id") or "")


def _asset_timestamp(asset: dict[str, Any], fallback: str) -> str:
    return str(asset.get("last_seen") or fallback)


def _open_findings(findings_by_asset: dict[str, list[dict]], asset_key: str) -> list[dict]:
    findings = findings_by_asset.get(asset_key, [])
    return [
        f
        for f in findings
        if str(f.get("status") or "open").strip().lower() in OPEN_FINDING_STATUSES
    ]


def _severity_findings(findings: list[dict], severity: str) -> list[dict]:
    want = severity.strip().lower()
    return [f for f in findings if str(f.get("severity") or "").strip().lower() == want]


def _simplify_finding(f: dict[str, Any]) -> dict[str, Any]:
    return {
        "finding_id": f.get("finding_id"),
        "title": f.get("title"),
        "severity": f.get("severity"),
        "status": f.get("status"),
        "category": f.get("category"),
        "source": f.get("source"),
        "first_seen": f.get("first_seen"),
        "last_seen": f.get("last_seen"),
    }


def _header_token(header: str) -> str:
    normalized = HEADER_ALIASES.get(header.strip().lower(), header.strip().lower())
    return normalized


def _finding_matches_missing_header(finding: dict[str, Any], required_header: str) -> bool:
    token = _header_token(required_header)
    title = str(finding.get("title") or "").strip().lower()
    evidence = str(finding.get("evidence") or "").strip().lower()
    category = str(finding.get("category") or "").strip().lower()
    if "security_headers" not in category and "header" not in title and "header" not in evidence:
        return False
    return token in title or token in evidence or token.split("-")[0] in title


def _parse_tls_version(text: str) -> tuple[int, int] | None:
    # Accept formats like TLS1.2, TLSv1.3, 1.2
    m = re.search(r"(?:tlsv?|version)\s*([0-9]+)\.([0-9]+)", text, flags=re.IGNORECASE)
    if not m:
        m = re.search(r"\b([0-9]+)\.([0-9]+)\b", text)
    if not m:
        return None
    try:
        return int(m.group(1)), int(m.group(2))
    except Exception:
        return None


def _version_lt(actual: tuple[int, int], minimum: tuple[int, int]) -> bool:
    return actual[0] < minimum[0] or (actual[0] == minimum[0] and actual[1] < minimum[1])


def _rule_result(
    rule: dict[str, Any],
    passed: int,
    failed: int,
    violations: list[dict[str, Any]],
) -> dict[str, Any]:
    total = passed + failed
    pass_pct = round(100.0 * passed / total, 1) if total else 0.0
    return {
        "id": rule["id"],
        "name": rule["name"],
        "type": rule["type"],
        "passed": passed,
        "failed": failed,
        "total": total,
        "pass_pct": pass_pct,
        "violations": violations,
    }


def evaluate_rules(
    rules: list[dict[str, Any]],
    assets: list[dict[str, Any]],
    findings_by_asset: dict[str, list[dict]],
    *,
    evaluated_at: str | None = None,
    bundle_approved_by: str | None = None,
) -> dict[str, Any]:
    """
    Evaluate rules against posture + findings.

    Returns:
      {
        "score": 0-100,
        "evaluated_at": "...Z",
        "bundle_approved_by": "...",
        "rules": [... per-rule pass/fail plus violations ...],
        "violations": [... flattened violations ...]
      }
    """
    evaluated_at_iso = evaluated_at or _now_iso()
    if not assets:
        empty_rules = [_rule_result(r, 0, 0, []) for r in rules]
        return {
            "score": 0.0,
            "evaluated_at": evaluated_at_iso,
            "bundle_approved_by": bundle_approved_by,
            "rules": empty_rules,
            "violations": [],
        }

    all_violations: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    for rule in rules:
        rtype = str(rule["type"]).strip().lower()
        params = _as_dict(rule.get("params"))
        passed = 0
        failed = 0
        violations: list[dict[str, Any]] = []

        for asset in assets:
            asset_key = _asset_key(asset)
            if not asset_key:
                continue
            asset_ts = _asset_timestamp(asset, evaluated_at_iso)
            open_findings = _open_findings(findings_by_asset, asset_key)

            failed_evidence: dict[str, Any] | None = None

            if rtype == "asset_status":
                want = str(params.get("status") or "green").strip().lower()
                actual = str(asset.get("status") or "").strip().lower()
                if actual != want:
                    failed_evidence = {
                        "expected_status": want,
                        "actual_status": actual,
                        "posture_score": asset.get("posture_score"),
                        "reason": asset.get("reason"),
                        "last_seen": asset.get("last_seen"),
                    }

            elif rtype == "posture_score_min":
                min_score = _as_float(params.get("min_score"), 0.0)
                actual_score = asset.get("posture_score")
                if actual_score is None or _as_float(actual_score, -1.0) < min_score:
                    failed_evidence = {
                        "required_min_score": min_score,
                        "actual_posture_score": actual_score,
                        "status": asset.get("status"),
                        "last_seen": asset.get("last_seen"),
                    }

            elif rtype in {"no_open_findings", "no_critical_findings"}:
                severity = (
                    "critical"
                    if rtype == "no_critical_findings"
                    else str(params.get("severity") or "critical").strip().lower()
                )
                matching = _severity_findings(open_findings, severity)
                if matching:
                    failed_evidence = {
                        "severity": severity,
                        "open_findings": [_simplify_finding(f) for f in matching],
                    }

            elif rtype == "require_header":
                required_header = str(params.get("header") or "content-security-policy").strip()
                missing = [f for f in open_findings if _finding_matches_missing_header(f, required_header)]
                if missing:
                    failed_evidence = {
                        "required_header": _header_token(required_header),
                        "open_findings": [_simplify_finding(f) for f in missing],
                    }

            elif rtype == "tls_min_version":
                min_version_raw = str(params.get("min_version") or "1.2").strip()
                minimum = _parse_tls_version(min_version_raw) or (1, 2)
                tls_open = [
                    f for f in open_findings if str(f.get("category") or "").strip().lower() == "tls"
                ]
                for finding in tls_open:
                    text_blob = (
                        f"{finding.get('title') or ''} {finding.get('evidence') or ''} "
                        f"{finding.get('remediation') or ''}"
                    )
                    parsed = _parse_tls_version(text_blob)
                    title = str(finding.get("title") or "").lower()
                    if parsed and _version_lt(parsed, minimum):
                        failed_evidence = {
                            "required_min_version": f"{minimum[0]}.{minimum[1]}",
                            "actual_version": f"{parsed[0]}.{parsed[1]}",
                            "finding": _simplify_finding(finding),
                        }
                        break
                    if any(x in title for x in ("no https", "tls connection failed", "certificate")):
                        failed_evidence = {
                            "required_min_version": f"{minimum[0]}.{minimum[1]}",
                            "actual_version": None,
                            "finding": _simplify_finding(finding),
                        }
                        break

            else:
                failed_evidence = {"error": f"Unknown rule type: {rtype}"}

            if failed_evidence is None:
                passed += 1
            else:
                failed += 1
                violation = {
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "rule_type": rtype,
                    "asset_key": asset_key,
                    "timestamp": asset_ts,
                    "bundle_approved_by": bundle_approved_by,
                    "evidence": failed_evidence,
                }
                violations.append(violation)
                all_violations.append(violation)

        results.append(_rule_result(rule, passed, failed, violations))

    avg_score = sum(r["pass_pct"] for r in results) / len(results) if results else 0.0
    return {
        "score": round(avg_score, 1),
        "evaluated_at": evaluated_at_iso,
        "bundle_approved_by": bundle_approved_by,
        "rules": results,
        "violations": all_violations,
    }
