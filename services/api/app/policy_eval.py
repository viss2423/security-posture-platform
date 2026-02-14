"""Phase B.2: Evaluate policy bundle YAML rules against posture + findings."""
from __future__ import annotations

import yaml
from typing import Any


def parse_bundle_yaml(definition: str) -> list[dict[str, Any]]:
    """Parse YAML definition; return list of rules. Each rule: id, name, type, params (dict)."""
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
    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            raise ValueError(f"Rule {i} must be an object")
        rule_id = r.get("id") or f"rule_{i}"
        name = r.get("name") or rule_id
        rule_type = r.get("type")
        if not rule_type:
            raise ValueError(f"Rule {rule_id}: missing 'type'")
        out.append({
            "id": rule_id,
            "name": name,
            "type": rule_type,
            "params": r.get("params") or {},
        })
    return out


def evaluate_rules(
    rules: list[dict[str, Any]],
    assets: list[dict[str, Any]],
    findings_by_asset: dict[str, list[dict]],
) -> dict[str, Any]:
    """
    Evaluate each rule against assets. assets: list of dicts with asset_id, status, posture_score, etc.
    findings_by_asset: asset_key -> list of finding dicts (with status, severity).
    Returns: { "score": 0-100, "rules": [ { "id", "name", "type", "passed", "failed", "total", "pass_pct" } ] }
    """
    if not assets:
        return {
            "score": 0.0,
            "rules": [
                {
                    "id": r["id"],
                    "name": r["name"],
                    "type": r["type"],
                    "passed": 0,
                    "failed": 0,
                    "total": 0,
                    "pass_pct": 0.0,
                }
                for r in rules
            ],
        }

    results = []
    for rule in rules:
        rtype = rule["type"]
        params = rule.get("params") or {}
        passed = 0
        failed = 0
        if rtype == "asset_status":
            want = (params.get("status") or "green").strip().lower()
            for a in assets:
                s = (a.get("status") or "").strip().lower()
                if s == want:
                    passed += 1
                else:
                    failed += 1
        elif rtype == "posture_score_min":
            min_score = float(params.get("min_score", 0))
            for a in assets:
                sc = a.get("posture_score")
                if sc is not None and float(sc) >= min_score:
                    passed += 1
                else:
                    failed += 1
        elif rtype == "no_open_findings":
            severity = (params.get("severity") or "critical").strip().lower()
            for a in assets:
                key = a.get("asset_id") or a.get("asset_key") or ""
                findings = findings_by_asset.get(key, [])
                open_of_severity = [
                    f for f in findings
                    if (f.get("status") or "open").strip().lower() in ("open", "in_progress")
                    and (f.get("severity") or "").strip().lower() == severity
                ]
                if not open_of_severity:
                    passed += 1
                else:
                    failed += 1
        else:
            failed = len(assets)
            passed = 0
        total = passed + failed
        pass_pct = round(100.0 * passed / total, 1) if total else 0.0
        results.append({
            "id": rule["id"],
            "name": rule["name"],
            "type": rule["type"],
            "passed": passed,
            "failed": failed,
            "total": total,
            "pass_pct": pass_pct,
        })
    avg_score = sum(r["pass_pct"] for r in results) / len(results) if results else 0.0
    return {"score": round(avg_score, 1), "rules": results}
