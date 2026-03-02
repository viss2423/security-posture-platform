from app.policy_eval import evaluate_rules, parse_bundle_yaml


def test_parse_bundle_yaml_supports_shorthand_params():
    rules = parse_bundle_yaml(
        """
rules:
  - id: r1
    type: posture_score_min
    min_score: 80
  - id: r2
    type: require_header
    header: content-security-policy
"""
    )
    assert len(rules) == 2
    assert rules[0]["params"]["min_score"] == 80
    assert rules[1]["params"]["header"] == "content-security-policy"


def test_evaluate_rules_returns_compliance_evidence():
    rules = parse_bundle_yaml(
        """
rules:
  - id: no-critical
    type: no_critical_findings
  - id: csp-required
    type: require_header
    params:
      header: content-security-policy
  - id: min-score
    type: posture_score_min
    params:
      min_score: 80
"""
    )
    assets = [
        {
            "asset_id": "juice-shop",
            "asset_key": "juice-shop",
            "status": "red",
            "posture_score": 42,
            "last_seen": "2026-02-25T12:00:00Z",
            "reason": "health_check_failed",
        }
    ]
    findings_by_asset = {
        "juice-shop": [
            {
                "finding_id": 1,
                "status": "open",
                "severity": "critical",
                "category": "security_headers",
                "title": "Missing CSP",
                "source": "header_scan",
                "evidence": "Header Content-Security-Policy not present",
                "first_seen": "2026-02-25T11:00:00Z",
                "last_seen": "2026-02-25T12:00:00Z",
            }
        ]
    }
    result = evaluate_rules(
        rules,
        assets,
        findings_by_asset,
        evaluated_at="2026-02-25T12:30:00Z",
        bundle_approved_by="admin",
    )
    assert result["score"] < 100
    assert result["bundle_approved_by"] == "admin"
    assert len(result["violations"]) >= 2
    first = result["violations"][0]
    assert first["rule_id"]
    assert first["asset_key"] == "juice-shop"
    assert first["timestamp"]
    assert first["bundle_approved_by"] == "admin"
    assert isinstance(first["evidence"], dict)
