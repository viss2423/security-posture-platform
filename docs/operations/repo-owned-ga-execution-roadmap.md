# Repo-Owned GA Execution Roadmap

This roadmap is the repo execution order for closing customer-trust and maintenance-light gaps without relying on outside vendors or customer signoff.

## Workstreams

1. Reliability and release discipline
   - Keep `stability.py`, release-gate endpoints, and CI gate scripts aligned.
   - Verify with `py -3.13 -m pytest -q services/api/tests/test_platform_stability.py services/api/tests/test_run_upgrade_preflight_script.py`.
2. Customer-trust documentation and evidence
   - Keep the compliance register, readiness manifest, and disclosure metadata current.
   - Verify with `py services/api/scripts/build_readiness_evidence.py` and `py services/api/scripts/build_compliance_evidence_pack.py`.
3. Tenant-safe OpenSearch posture paths
   - Preserve `org_id` propagation through asset indexing, posture search, and status derivation.
   - Verify with `py -3.13 -m pytest -q services/api/tests/test_posture_tenant_filters.py services/api/tests/test_telemetry_opensearch_doc.py`.
4. AI operator safety
   - Require explicit operator acknowledgement before applying AI-recommended alert actions.
   - Verify with `npm test --prefix services/frontend` and `npm run build --prefix services/frontend`.
5. Recovery and upgrade automation
   - Keep backup/restore drills and upgrade preflight scripts runnable from the repo.
   - Verify with `py -3.13 -m pytest -q services/api/tests/test_verify_backup_restore_script.py services/api/tests/test_verify_phase5_maintenance_script.py`.

## Release Closeout Commands

Run these commands in order before declaring the repo-owned slice green:

```powershell
py services/api/scripts/build_readiness_evidence.py
py services/api/scripts/build_compliance_evidence_pack.py
py -3.13 -m pytest -q services/api/tests/test_security_program.py services/api/tests/test_posture_tenant_filters.py services/api/tests/test_telemetry_opensearch_doc.py
py -3.13 -m pytest -q services/api/tests/test_platform_stability.py services/api/tests/test_run_upgrade_preflight_script.py services/api/tests/test_verify_phase5_maintenance_script.py services/api/tests/test_verify_backup_restore_script.py
npm test --prefix services/frontend
npm run lint --prefix services/frontend
npm run build --prefix services/frontend
```

Anything outside this roadmap requires external execution rather than repo-only implementation: independent assessment, real customer signoff, and production-environment operations.
