# Phase 4 External Assessment Brief

## Scope

- Kubernetes-first single-tenant release candidate path
- Release artifact verification, runtime recovery, and operational readiness evidence

## Evidence Included

- `artifacts/phase4/ga-local-report.json`: present
- `artifacts/phase4/release-bundle/release-bundle.json`: present
- `docs/contracts/stability-contract.md`: present
- `docs/contracts/upgrade-policy.md`: present
- `docs/operations/backup-restore-verification.md`: present
- `docs/operations/design-partner-rollout-checklist.md`: present
- `docs/operations/design-partner-signoff-template.md`: present
- `docs/operations/external-security-assessment-runbook.md`: present
- `docs/operations/incident-severity-and-escalation.md`: present
- `docs/security/vulnerability-disclosure.md`: present
- `docs/support/support-sla.md`: present

## Validation Commands Already Supported

- `py services/api/scripts/verify_phase4_local_ga.py --namespace secplat-phase3 --api-service secplat-api --admin-password <admin-password>`
- `py services/api/scripts/render_release_bundle.py --image-map-json services/api/examples/release-images.example.json --out-dir artifacts/phase4/release-bundle --github-repository acme/security-posture-platform`
- `py services/api/scripts/verify_kyverno_admission.py --repo-root artifacts/phase4/release-bundle --policy-file infra/policy/kyverno/verify-secplat-images.yaml --require-real-attestors`
- `py services/api/scripts/build_readiness_evidence.py --out artifacts/phase4/readiness-manifest.json`

## Manual Closeout Required

- Attach the final external security assessment or pen-test report and remediation status.
- Record design-partner validation outcome against the signoff template and collect stakeholder approval.

