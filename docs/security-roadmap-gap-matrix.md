# Security Roadmap Gap Matrix (Portfolio Scope)

Scope for this matrix:
- Phase 0-5
- Phase 8
- Phase 9
- Phase 11
- Phase 12

Status legend:
- `done`: implemented and usable end-to-end
- `partial`: implemented baseline exists, but key roadmap outcomes are missing
- `missing`: little or no implementation present for roadmap objective

## Phase Status

| Phase | Status | Current Evidence | Primary Gaps |
| --- | --- | --- | --- |
| Phase 0 - Foundation Hardening | partial | RBAC + auth in `routers/auth.py`; standardized error envelope in `errors.py`; audit table + API exists; jobs + worker + retry basics exist | User lifecycle APIs and broad audit coverage are now in place; remaining hardening gaps are full endpoint-level audit completeness verification and deeper job reliability observability/analytics |
| Phase 1 - Real Security Telemetry | partial | `telemetry.py` ingests Suricata/Zeek/Auditd/Cowrie; telemetry routes + UI pages exist; IOC matching integrated | Host auth log breadth (ssh auth/sudo/su/cron/process from raw Linux logs) needs expansion; source lineage/traceability fields are not first-class in `security_events` |
| Phase 2 - Detection Engineering | partial | Detection rules CRUD + test runs in `routers/detections.py`; ATT&CK-like tags in telemetry payload; alerts from rule test exist | Rule versioning/stage lifecycle (`draft/canary/active`) missing; simulator endpoint missing; correlation rules and ATT&CK coverage APIs/dashboard incomplete |
| Phase 3 - Alert Enrichment | partial | Alert queue includes posture + findings + incidents + suppression/maintenance context in `routers/alerts.py`; AI guidance enrichment exists | Dedicated severity engine for effective severity is not separated; explicit dedupe windows + clustering APIs/views are missing |
| Phase 4 - Incident Response Maturity | partial | Incident CRUD/state/timeline/notes/linking in `routers/incidents.py`; Jira integration and AI summary present | Auto-creation rules for incident chains are limited; formal evidence model (typed links for alerts/findings/assets/jobs/tickets) incomplete; collaboration primitives (watchers/checklists/decision logs) missing |
| Phase 5 - Automation & Playbooks | missing | Jobs and service workers exist; integrations exist (Slack/Jira/Twilio) | No playbook model/engine, no trigger-condition-action framework, no approval/rollback orchestration, no automation dashboard |
| Phase 8 - Attack Surface Management | partial | Attack-lab scanning and asset metadata exist; asset CRUD and verification exist | Continuous discovery engine (hosts/services/subdomains/certs), exposure scoring, drift detection, and dedicated `/attack-surface` workspace are missing |
| Phase 9 - Risk Scoring & Posture Intelligence | partial | Finding-level heuristic + ML scoring in `risk_scoring.py` / `risk_training.py`; evaluation/snapshots endpoints exist | Asset/incident/environment aggregate risk engines, explicit score explanation APIs for those entities, and remediation prioritization queue are incomplete |
| Phase 11 - Investigation Timeline & Attack Graph | missing | Incident timeline exists (notes/state/link events) | Unified multi-source timeline materialization and attack graph model/UI are not implemented |
| Phase 12 - AI Security Analyst | partial | AI summaries/guidance/diagnosis/explanations exist across incidents/alerts/assets/findings/policy/jobs | Evidence-citation guardrail schema and fact-vs-recommendation contract are not enforced; analyst feedback loop and summary version compare workflows are missing |

## Wave Priorities (Implementation Order)

1. `M0.1-M0.5`: hardening and control-plane consistency.
2. `M1.1-M3.2`: telemetry depth + detection + triage quality.
3. `M4.1-M5.3`: analyst workflow and automation platform.
4. `M8.1-M9.2`: attack surface and explainable risk intelligence.
5. `M11.1-M12.2`: investigation graph and evidence-grounded AI workflow.

## Milestone-to-Phase Mapping

| Milestone | Primary Phase |
| --- | --- |
| M0.1-M0.5 | Phase 0 |
| M1.1-M1.2 | Phase 1 |
| M2.1-M2.4 | Phase 2 |
| M3.1-M3.2 | Phase 3 |
| M4.1-M4.2 | Phase 4 |
| M5.1-M5.3 | Phase 5 |
| M8.1-M8.3 | Phase 8 |
| M9.1-M9.2 | Phase 9 |
| M11.1-M11.2 | Phase 11 |
| M12.1-M12.2 | Phase 12 |
