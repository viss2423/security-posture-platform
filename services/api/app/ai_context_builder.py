"""Build evidence-grounded AI context payloads and guarded summary rendering."""

from __future__ import annotations

import json
from typing import Any

SECTION_ORDER = ("facts", "inference", "recommendations")


def _safe_text(value: Any, *, fallback: str = "") -> str:
    text = str(value or "").strip()
    return text or fallback


def _extract_json_object(raw_text: str) -> dict[str, Any] | None:
    text = str(raw_text or "").strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        parsed = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _sanitize_section_items(
    value: Any,
    *,
    allowed_evidence: set[str],
    limit: int,
    statement_key: str,
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    out: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        statement = _safe_text(item.get(statement_key))
        if not statement:
            continue
        evidence_value = item.get("evidence")
        evidence_ids: list[str] = []
        if isinstance(evidence_value, list):
            for raw_id in evidence_value:
                candidate = str(raw_id or "").strip().upper()
                if candidate in allowed_evidence and candidate not in evidence_ids:
                    evidence_ids.append(candidate)
        if not evidence_ids:
            # Guardrail: deny statements with no verifiable evidence references.
            continue
        out.append({"statement": statement[:280], "evidence": evidence_ids[:4]})
        if len(out) >= limit:
            break
    return out


def build_incident_guardrail_bundle(context: dict[str, Any]) -> dict[str, Any]:
    incident = dict(context.get("incident") or {})
    alerts = [dict(item) for item in (context.get("alerts") or []) if isinstance(item, dict)]
    timeline = [dict(item) for item in (context.get("timeline") or []) if isinstance(item, dict)]

    evidence_catalog: list[dict[str, Any]] = []

    def add_evidence(kind: str, value: Any) -> str | None:
        if value in (None, "", [], {}):
            return None
        evidence_id = f"E{len(evidence_catalog) + 1}"
        evidence_catalog.append({"id": evidence_id, "kind": kind, "value": value})
        return evidence_id

    title_id = add_evidence("incident.title", incident.get("title"))
    severity_id = add_evidence("incident.severity", incident.get("severity"))
    status_id = add_evidence("incident.status", incident.get("status"))
    assignee_id = add_evidence("incident.assigned_to", incident.get("assigned_to"))
    alert_count_id = add_evidence("incident.alert_count", len(alerts))
    timeline_count_id = add_evidence("incident.timeline_count", len(timeline))
    asset_keys = sorted(
        {
            str(item.get("asset_key") or "").strip()
            for item in alerts
            if str(item.get("asset_key") or "").strip()
        }
    )
    assets_id = add_evidence("incident.affected_assets", asset_keys)

    timeline_latest = timeline[-1] if timeline else {}
    latest_type = str(timeline_latest.get("event_type") or "").strip()
    latest_author = str(timeline_latest.get("author") or "").strip()
    latest_body = str(timeline_latest.get("body") or "").strip()
    latest_parts = [p for p in [latest_type, latest_author, latest_body] if p]
    latest_evidence = add_evidence(
        "incident.latest_timeline_event",
        " | ".join(latest_parts) if latest_parts else None,
    )

    facts: list[dict[str, Any]] = []
    if title_id or severity_id or status_id:
        facts.append(
            {
                "statement": (
                    f"Incident '{_safe_text(incident.get('title'), fallback='Untitled incident')}' "
                    f"is currently {_safe_text(incident.get('severity'), fallback='unknown')} severity "
                    f"with status {_safe_text(incident.get('status'), fallback='unknown')}."
                ),
                "evidence": [eid for eid in [title_id, severity_id, status_id] if eid],
            }
        )
    if assets_id:
        facts.append(
            {
                "statement": (
                    "Affected assets: " + ", ".join(asset_keys[:6])
                    if asset_keys
                    else "No linked assets are currently recorded."
                ),
                "evidence": [assets_id],
            }
        )
    if assignee_id:
        facts.append(
            {
                "statement": f"Assigned analyst: {_safe_text(incident.get('assigned_to'))}.",
                "evidence": [assignee_id],
            }
        )
    if alert_count_id:
        facts.append(
            {
                "statement": f"Linked alert count: {len(alerts)}.",
                "evidence": [alert_count_id],
            }
        )

    inference: list[dict[str, Any]] = []
    severity = _safe_text(incident.get("severity")).lower()
    status = _safe_text(incident.get("status")).lower()
    if severity in {"critical", "high"}:
        inference.append(
            {
                "statement": "Potential business impact remains elevated until containment and validation are complete.",
                "evidence": [eid for eid in [severity_id, status_id, alert_count_id] if eid],
            }
        )
    if status in {"new", "triaged"}:
        inference.append(
            {
                "statement": "Investigation appears active and not yet at containment/resolution stages.",
                "evidence": [eid for eid in [status_id, timeline_count_id] if eid],
            }
        )
    if latest_evidence:
        inference.append(
            {
                "statement": "The most recent timeline activity should be validated as part of current triage context.",
                "evidence": [latest_evidence],
            }
        )

    recommendations: list[dict[str, Any]] = []
    recommendations.append(
        {
            "statement": "Confirm scope on all linked assets and validate whether containment is required now.",
            "evidence": [eid for eid in [assets_id, severity_id, status_id] if eid],
        }
    )
    recommendations.append(
        {
            "statement": "Assign explicit owner and next checkpoint in the incident timeline.",
            "evidence": [eid for eid in [assignee_id, timeline_count_id] if eid],
        }
    )
    if alert_count_id:
        recommendations.append(
            {
                "statement": "Review correlated alerts for duplication/noise before escalation to reduce false positives.",
                "evidence": [alert_count_id],
            }
        )

    return {
        "evidence_catalog": evidence_catalog,
        "sections": {
            "facts": [item for item in facts if item.get("evidence")],
            "inference": [item for item in inference if item.get("evidence")],
            "recommendations": [item for item in recommendations if item.get("evidence")],
        },
    }


def build_finding_guardrail_bundle(context: dict[str, Any]) -> dict[str, Any]:
    finding = dict(context.get("finding") or {})
    asset = dict(context.get("asset") or {})

    evidence_catalog: list[dict[str, Any]] = []

    def add_evidence(kind: str, value: Any) -> str | None:
        if value in (None, "", [], {}):
            return None
        evidence_id = f"E{len(evidence_catalog) + 1}"
        evidence_catalog.append({"id": evidence_id, "kind": kind, "value": value})
        return evidence_id

    title_id = add_evidence("finding.title", finding.get("title"))
    severity_id = add_evidence("finding.severity", finding.get("severity"))
    status_id = add_evidence("finding.status", finding.get("status"))
    confidence_id = add_evidence("finding.confidence", finding.get("confidence"))
    category_id = add_evidence("finding.category", finding.get("category"))
    risk_score_id = add_evidence("finding.risk_score", finding.get("risk_score"))
    risk_level_id = add_evidence("finding.risk_level", finding.get("risk_level"))
    source_id = add_evidence("finding.source", finding.get("source"))
    remediation_id = add_evidence("finding.remediation", finding.get("remediation"))
    evidence_text_id = add_evidence("finding.evidence", finding.get("evidence"))

    asset_key_id = add_evidence("asset.asset_key", asset.get("asset_key"))
    asset_env_id = add_evidence("asset.environment", asset.get("environment"))
    asset_criticality_id = add_evidence("asset.criticality", asset.get("criticality"))
    asset_owner_id = add_evidence("asset.owner", asset.get("owner"))

    facts: list[dict[str, Any]] = []
    facts.append(
        {
            "statement": (
                f"Finding '{_safe_text(finding.get('title'), fallback='Untitled finding')}' "
                f"is {_safe_text(finding.get('severity'), fallback='unknown')} severity and "
                f"currently {_safe_text(finding.get('status'), fallback='unknown')}."
            ),
            "evidence": [eid for eid in [title_id, severity_id, status_id] if eid],
        }
    )
    if asset_key_id:
        facts.append(
            {
                "statement": (
                    f"Affected asset: {_safe_text(asset.get('asset_key'))} "
                    f"({_safe_text(asset.get('environment'), fallback='unknown environment')})."
                ),
                "evidence": [eid for eid in [asset_key_id, asset_env_id] if eid],
            }
        )
    if confidence_id or source_id:
        facts.append(
            {
                "statement": (
                    f"Confidence {_safe_text(finding.get('confidence'), fallback='unknown')} "
                    f"from source {_safe_text(finding.get('source'), fallback='unknown')}."
                ),
                "evidence": [eid for eid in [confidence_id, source_id] if eid],
            }
        )
    if evidence_text_id:
        facts.append(
            {
                "statement": "Finding evidence text is present and should be validated by the analyst.",
                "evidence": [evidence_text_id],
            }
        )

    inference: list[dict[str, Any]] = []
    severity = _safe_text(finding.get("severity")).lower()
    criticality = _safe_text(asset.get("criticality")).lower()
    if severity in {"critical", "high"}:
        inference.append(
            {
                "statement": "Exploit impact is likely meaningful and should be prioritized for remediation.",
                "evidence": [
                    eid for eid in [severity_id, asset_criticality_id, risk_score_id] if eid
                ],
            }
        )
    if criticality in {"critical", "high"}:
        inference.append(
            {
                "statement": "Business impact may be amplified because the related asset has elevated criticality.",
                "evidence": [eid for eid in [asset_criticality_id, asset_env_id] if eid],
            }
        )
    if risk_level_id:
        inference.append(
            {
                "statement": "Current risk level should drive remediation urgency and validation depth.",
                "evidence": [eid for eid in [risk_level_id, risk_score_id] if eid],
            }
        )

    recommendations: list[dict[str, Any]] = []
    recommendations.append(
        {
            "statement": "Validate exploitability in this environment and confirm blast radius before closure.",
            "evidence": [eid for eid in [severity_id, asset_env_id, asset_key_id] if eid],
        }
    )
    if remediation_id:
        recommendations.append(
            {
                "statement": "Apply or schedule the documented remediation steps and track verification evidence.",
                "evidence": [remediation_id],
            }
        )
    recommendations.append(
        {
            "statement": "Record decision rationale if accepted risk is considered for this finding.",
            "evidence": [eid for eid in [status_id, asset_owner_id, risk_level_id] if eid],
        }
    )

    return {
        "evidence_catalog": evidence_catalog,
        "sections": {
            "facts": [item for item in facts if item.get("evidence")],
            "inference": [item for item in inference if item.get("evidence")],
            "recommendations": [item for item in recommendations if item.get("evidence")],
        },
    }


def build_alert_guardrail_bundle(context: dict[str, Any]) -> dict[str, Any]:
    alert = dict(context.get("alert") or {})
    asset = dict(context.get("asset") or {})
    maintenance = dict(context.get("maintenance") or {})
    suppression = dict(context.get("suppression") or {})
    finding_summary = dict(context.get("finding_summary") or {})
    timeline_signals = dict(context.get("timeline_signals") or {})
    decision_signals = dict(context.get("decision_signals") or {})

    evidence_catalog: list[dict[str, Any]] = []

    def add_evidence(kind: str, value: Any) -> str | None:
        if value in (None, "", [], {}):
            return None
        evidence_id = f"E{len(evidence_catalog) + 1}"
        evidence_catalog.append({"id": evidence_id, "kind": kind, "value": value})
        return evidence_id

    state_id = add_evidence("alert.current_state", alert.get("current_state"))
    assignee_id = add_evidence("alert.assigned_to", alert.get("assigned_to"))
    posture_id = add_evidence("asset.posture_status", asset.get("posture_status"))
    posture_score_id = add_evidence("asset.posture_score", asset.get("posture_score"))
    criticality_id = add_evidence("asset.criticality", asset.get("criticality"))
    environment_id = add_evidence("asset.environment", asset.get("environment"))
    maintenance_id = add_evidence("maintenance.active", maintenance.get("active"))
    suppression_id = add_evidence("suppression.active", suppression.get("active"))
    finding_count_id = add_evidence(
        "finding_summary.active_finding_count",
        finding_summary.get("active_finding_count"),
    )
    top_risk_id = add_evidence(
        "finding_summary.top_risk_score", finding_summary.get("top_risk_score")
    )
    unhealthy_events_id = add_evidence(
        "timeline_signals.unhealthy_events",
        timeline_signals.get("unhealthy_events"),
    )
    timeout_events_id = add_evidence(
        "timeline_signals.timeout_events",
        timeline_signals.get("timeout_events"),
    )
    open_incident_id = add_evidence(
        "decision_signals.has_open_incident",
        decision_signals.get("has_open_incident"),
    )
    response_bias_id = add_evidence(
        "decision_signals.response_bias", decision_signals.get("response_bias")
    )

    facts: list[dict[str, Any]] = []
    facts.append(
        {
            "statement": (
                f"Alert for asset '{_safe_text(asset.get('asset_key'), fallback='unknown')}' "
                f"is in state {_safe_text(alert.get('current_state'), fallback='unknown')} with "
                f"posture {_safe_text(asset.get('posture_status'), fallback='unknown')}."
            ),
            "evidence": [eid for eid in [state_id, posture_id] if eid],
        }
    )
    if finding_count_id:
        facts.append(
            {
                "statement": f"Active related findings: {int(finding_summary.get('active_finding_count') or 0)}.",
                "evidence": [finding_count_id],
            }
        )
    if assignee_id:
        facts.append(
            {
                "statement": f"Current assignee is {_safe_text(alert.get('assigned_to'))}.",
                "evidence": [assignee_id],
            }
        )
    if maintenance_id:
        facts.append(
            {
                "statement": "Maintenance window is currently active for this alert context.",
                "evidence": [maintenance_id],
            }
        )

    inference: list[dict[str, Any]] = []
    if decision_signals.get("has_open_incident"):
        inference.append(
            {
                "statement": "Response should stay aligned with the already-open incident workflow.",
                "evidence": [eid for eid in [open_incident_id, assignee_id, state_id] if eid],
            }
        )
    if asset.get("posture_status") == "red":
        inference.append(
            {
                "statement": "Service risk remains elevated while posture is degraded.",
                "evidence": [
                    eid for eid in [posture_id, posture_score_id, unhealthy_events_id] if eid
                ],
            }
        )
    if suppression.get("active") or maintenance.get("active"):
        inference.append(
            {
                "statement": "Alert noise control may be appropriate while maintenance/suppression is active.",
                "evidence": [
                    eid for eid in [maintenance_id, suppression_id, response_bias_id] if eid
                ],
            }
        )

    recommendations: list[dict[str, Any]] = []
    recommendations.append(
        {
            "statement": "Confirm owner, asset criticality, and current service status before closing or suppressing.",
            "evidence": [eid for eid in [assignee_id, criticality_id, posture_id, state_id] if eid],
        }
    )
    recommendations.append(
        {
            "statement": "Validate whether related findings and incidents indicate broader scope expansion.",
            "evidence": [eid for eid in [finding_count_id, top_risk_id, open_incident_id] if eid],
        }
    )
    recommendations.append(
        {
            "statement": "Track fresh telemetry signals to verify stabilization after response action.",
            "evidence": [
                eid for eid in [unhealthy_events_id, timeout_events_id, environment_id] if eid
            ],
        }
    )

    return {
        "evidence_catalog": evidence_catalog,
        "sections": {
            "facts": [item for item in facts if item.get("evidence")],
            "inference": [item for item in inference if item.get("evidence")],
            "recommendations": [item for item in recommendations if item.get("evidence")],
        },
    }


def build_policy_guardrail_bundle(context: dict[str, Any]) -> dict[str, Any]:
    evaluation = dict(context.get("evaluation") or {})
    failed_rules = [
        dict(item) for item in (context.get("failed_rules") or []) if isinstance(item, dict)
    ]
    top_assets = [
        dict(item) for item in (context.get("top_assets") or []) if isinstance(item, dict)
    ]
    violation_themes = [
        dict(item) for item in (context.get("violation_themes") or []) if isinstance(item, dict)
    ]
    remediation_priorities = [
        str(item).strip()
        for item in (context.get("remediation_priorities") or [])
        if str(item).strip()
    ]
    sample_violations = [
        dict(item) for item in (context.get("sample_violations") or []) if isinstance(item, dict)
    ]

    evidence_catalog: list[dict[str, Any]] = []

    def add_evidence(kind: str, value: Any) -> str | None:
        if value in (None, "", [], {}):
            return None
        evidence_id = f"E{len(evidence_catalog) + 1}"
        evidence_catalog.append({"id": evidence_id, "kind": kind, "value": value})
        return evidence_id

    bundle_id = add_evidence("evaluation.bundle_id", evaluation.get("bundle_id"))
    bundle_name = add_evidence("evaluation.bundle_name", evaluation.get("bundle_name"))
    score_id = add_evidence("evaluation.score", evaluation.get("score"))
    violations_id = add_evidence("evaluation.violations_count", evaluation.get("violations_count"))
    assets_id = add_evidence("evaluation.evaluated_assets", evaluation.get("evaluated_assets"))
    failed_count_id = add_evidence(
        "evaluation.failed_rules_count",
        evaluation.get("failed_rules_count"),
    )

    top_rule_names = [
        str(item.get("name") or "").strip()
        for item in failed_rules
        if str(item.get("name") or "").strip()
    ][:3]
    top_rule_types = [
        str(item.get("type") or "").strip()
        for item in failed_rules
        if str(item.get("type") or "").strip()
    ][:3]
    top_rule_id = add_evidence("failed_rules.top_names", top_rule_names)
    top_rule_types_id = add_evidence("failed_rules.top_types", top_rule_types)

    top_asset_keys = [
        str(item.get("asset_key") or "").strip()
        for item in top_assets
        if str(item.get("asset_key") or "").strip()
    ][:5]
    top_assets_id = add_evidence("top_assets.keys", top_asset_keys)

    top_theme_labels = [
        str(item.get("label") or "").strip()
        for item in violation_themes
        if str(item.get("label") or "").strip()
    ][:4]
    top_themes_id = add_evidence("violation_themes.labels", top_theme_labels)
    remediation_id = add_evidence(
        "remediation.priorities",
        remediation_priorities[:3],
    )

    sample_violation_id = add_evidence(
        "sample_violations.preview",
        [
            {
                "rule_name": item.get("rule_name"),
                "asset_key": item.get("asset_key"),
                "evidence_preview": item.get("evidence_preview"),
            }
            for item in sample_violations[:3]
        ],
    )

    facts: list[dict[str, Any]] = []
    facts.append(
        {
            "statement": (
                f"Policy bundle '{_safe_text(evaluation.get('bundle_name'), fallback='unknown')}' "
                f"scored {_safe_text(evaluation.get('score'), fallback='0')} with "
                f"{_safe_text(evaluation.get('violations_count'), fallback='0')} violations."
            ),
            "evidence": [eid for eid in [bundle_name, score_id, violations_id] if eid],
        }
    )
    if failed_count_id:
        facts.append(
            {
                "statement": f"Failed rules recorded: {_safe_text(evaluation.get('failed_rules_count'), fallback='0')}.",
                "evidence": [failed_count_id],
            }
        )
    if top_rule_id:
        facts.append(
            {
                "statement": f"Top failed rules include: {', '.join(top_rule_names[:3])}.",
                "evidence": [eid for eid in [top_rule_id, top_rule_types_id] if eid],
            }
        )
    if top_assets_id:
        facts.append(
            {
                "statement": f"Most impacted assets: {', '.join(top_asset_keys[:4])}.",
                "evidence": [top_assets_id],
            }
        )

    inference: list[dict[str, Any]] = []
    try:
        score_value = float(evaluation.get("score") or 0.0)
    except (TypeError, ValueError):
        score_value = 0.0
    if score_value < 70:
        inference.append(
            {
                "statement": "Current control effectiveness is below target and likely needs prioritized remediation.",
                "evidence": [eid for eid in [score_id, failed_count_id, violations_id] if eid],
            }
        )
    if top_themes_id:
        inference.append(
            {
                "statement": "Repeated violation themes suggest shared control weaknesses across assets.",
                "evidence": [eid for eid in [top_themes_id, top_assets_id] if eid],
            }
        )
    if sample_violation_id:
        inference.append(
            {
                "statement": "Sample violation evidence should be validated to confirm consistent remediation scope.",
                "evidence": [sample_violation_id],
            }
        )

    recommendations: list[dict[str, Any]] = []
    if remediation_priorities:
        for remediation_text in remediation_priorities[:3]:
            recommendations.append(
                {
                    "statement": remediation_text,
                    "evidence": [eid for eid in [remediation_id, top_themes_id] if eid],
                }
            )
    recommendations.append(
        {
            "statement": "Address the highest-failing controls on top impacted assets before broad rollout.",
            "evidence": [eid for eid in [top_rule_id, top_assets_id, assets_id, bundle_id] if eid],
        }
    )
    recommendations.append(
        {
            "statement": "Re-run policy evaluation after fixes to confirm score improvement and violation reduction.",
            "evidence": [eid for eid in [score_id, violations_id] if eid],
        }
    )

    return {
        "evidence_catalog": evidence_catalog,
        "sections": {
            "facts": [item for item in facts if item.get("evidence")],
            "inference": [item for item in inference if item.get("evidence")],
            "recommendations": [item for item in recommendations if item.get("evidence")],
        },
    }


def parse_alert_guarded_payload(
    raw_text: str,
    *,
    allowed_evidence: set[str],
    fallback_sections: dict[str, list[dict[str, Any]]],
    fallback_action: str,
    fallback_urgency: str,
) -> tuple[dict[str, list[dict[str, Any]]], bool, str, str] | None:
    payload = _extract_json_object(raw_text)
    if not payload:
        return None

    parsed_sections = {
        "facts": _sanitize_section_items(
            payload.get("facts"),
            allowed_evidence=allowed_evidence,
            limit=5,
            statement_key="statement",
        ),
        "inference": _sanitize_section_items(
            payload.get("inference"),
            allowed_evidence=allowed_evidence,
            limit=4,
            statement_key="statement",
        ),
        "recommendations": _sanitize_section_items(
            payload.get("recommendations"),
            allowed_evidence=allowed_evidence,
            limit=5,
            statement_key="statement",
        ),
    }

    used_fallback = False
    for section in SECTION_ORDER:
        if parsed_sections[section]:
            continue
        parsed_sections[section] = fallback_sections.get(section) or []
        used_fallback = True

    recommended_action = _safe_text(payload.get("recommended_action")).lower()
    urgency = _safe_text(payload.get("urgency")).lower()
    allowed_actions = {"ack", "suppress", "assign", "escalate", "resolve", "monitor"}
    allowed_urgency = {"critical", "high", "medium", "low"}
    if recommended_action not in allowed_actions:
        recommended_action = fallback_action
        used_fallback = True
    if urgency not in allowed_urgency:
        urgency = fallback_urgency
        used_fallback = True

    return parsed_sections, used_fallback, recommended_action, urgency


def parse_guarded_sections_payload(
    raw_text: str,
    *,
    allowed_evidence: set[str],
    fallback_sections: dict[str, list[dict[str, Any]]],
) -> tuple[dict[str, list[dict[str, Any]]], bool] | None:
    payload = _extract_json_object(raw_text)
    if not payload:
        return None

    parsed_sections = {
        "facts": _sanitize_section_items(
            payload.get("facts"),
            allowed_evidence=allowed_evidence,
            limit=5,
            statement_key="statement",
        ),
        "inference": _sanitize_section_items(
            payload.get("inference"),
            allowed_evidence=allowed_evidence,
            limit=4,
            statement_key="statement",
        ),
        "recommendations": _sanitize_section_items(
            payload.get("recommendations"),
            allowed_evidence=allowed_evidence,
            limit=5,
            statement_key="statement",
        ),
    }

    used_fallback = False
    for section in SECTION_ORDER:
        if parsed_sections[section]:
            continue
        parsed_sections[section] = fallback_sections.get(section) or []
        used_fallback = True
    return parsed_sections, used_fallback


def parse_incident_guarded_sections(
    raw_text: str,
    *,
    allowed_evidence: set[str],
    fallback_sections: dict[str, list[dict[str, Any]]],
) -> tuple[dict[str, list[dict[str, Any]]], bool]:
    parsed = parse_guarded_sections_payload(
        raw_text,
        allowed_evidence=allowed_evidence,
        fallback_sections=fallback_sections,
    )
    if parsed is None:
        return fallback_sections, True
    return parsed


def render_guarded_sections_text(
    sections: dict[str, list[dict[str, Any]]],
) -> str:
    lines: list[str] = []
    labels = {
        "facts": "Facts",
        "inference": "Inference",
        "recommendations": "Recommendations",
    }
    for section in SECTION_ORDER:
        lines.append(labels[section])
        items = sections.get(section) or []
        if not items:
            lines.append("- None")
            lines.append("")
            continue
        for item in items:
            statement = _safe_text(item.get("statement"))
            evidence_ids = [
                str(eid).strip().upper() for eid in (item.get("evidence") or []) if str(eid).strip()
            ]
            evidence_suffix = f" [{', '.join(evidence_ids)}]" if evidence_ids else ""
            lines.append(f"- {statement}{evidence_suffix}")
        lines.append("")
    return "\n".join(lines).strip()
