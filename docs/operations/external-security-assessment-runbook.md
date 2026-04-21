# External Security Assessment Runbook

## Purpose

Use this runbook to hand a release candidate to an external assessor or penetration-testing partner without additional engineering discovery.

## Scope

- API, worker, correlator, notifier, and deriver services
- Kubernetes deployment manifests and signed release bundle
- Tenant isolation, authn/authz, queue processing, backup/restore, and recovery controls

## Environment Expectations

- Single-tenant Kubernetes deployment
- Helm-installed release candidate matching the digest-pinned release bundle
- Admin test account and worker service account available
- Non-production environment with realistic telemetry and seeded detections

## Assessor Inputs

- Release bundle: `artifacts/phase4/release-bundle`
- Local GA verification report: `artifacts/phase4/ga-local-report.json`
- Stability contract: `docs/contracts/stability-contract.md`
- Upgrade policy: `docs/contracts/upgrade-policy.md`
- Backup and restore verification: `docs/operations/backup-restore-verification.md`
- Vulnerability disclosure policy: `docs/security/vulnerability-disclosure.md`

## Required Validation Areas

1. Authentication, authorization, and tenant-boundary controls
2. Queue/job execution and stale-job recovery behavior
3. Kubernetes runtime posture and image verification policy
4. Backup, restore, and operator runbook correctness
5. Upgrade, rollback, and release artifact trust path

## Deliverables Required Back

- Final assessment report with severity ratings
- Repro steps for each finding
- Remediation recommendation for each finding
- Retest result for every blocking issue

## Exit Rule

Phase 4 cannot be marked fully complete until:

- all blocking findings are remediated or explicitly risk-accepted, and
- the final external report is attached to the release-candidate evidence pack
