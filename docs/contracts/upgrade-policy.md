# Upgrade Policy (Phase 4)

## Versioning

- API follows semantic versioning.
- Breaking API changes require a major version bump.
- Database migrations must remain forward-compatible across one minor release window.
- Worker/correlator/notifier binaries must stay compatible with the active API minor release.
- Migration CI guardrail (`services/api/scripts/check_upgrade_compatibility.py`) blocks destructive SQL patterns by default.
- Any intentionally breaking migration must include an explicit annotation (`-- secplat: allow-breaking-change`) and be executed only in an approved change window.

## Upgrade order

1. Apply database migrations.
2. Roll API instances.
3. Roll async workers.
4. Roll correlator/notifier services.
5. Run smoke checks (`/health`, `/ready`, `/platform/release-gate/current`).

## Rollback

- Same-window rollbacks are allowed for API/workers when schema remains compatible.
- Irreversible migrations are forward-fix only.
- If rollback is unsafe, switch to reliability/security fix mode until compatibility is restored.
