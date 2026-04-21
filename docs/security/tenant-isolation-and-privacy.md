# Tenant Isolation and Privacy Controls (Phase 5)

## Tenant Context

- `TENANCY_MODE`: `single` or `multi`
- `DEFAULT_TENANT_ID`: fallback tenant identifier
- `REQUIRE_TENANT_HEADER`: require `x-tenant-id` header in multi-tenant mode

Request processing now propagates tenant context through:

- request context (`tenant_id`)
- response headers (`x-tenant-id`)
- queue event envelope `org_id`

## Datastore Enforcement

Tenant isolation is now enforced in PostgreSQL, not only in middleware:

- Session tenant context is set through `set_config('secplat.tenant_id', ...)` on DB execution paths.
- Core tables include `org_id` with tenant-default expression:
  - `assets`, `findings`, `incidents`, `incident_alerts`, `incident_notes`
  - `scan_jobs`, `security_events`, `security_alerts`
- Row-level security (RLS) is enabled and forced with tenant policies on those tables.
- Query visibility and inserts/updates are constrained by `org_id = current_setting('secplat.tenant_id', true)`.
- Runtime role hardening:
  - `python services/api/scripts/provision_runtime_db_role.py` provisions a non-superuser, non-`BYPASSRLS` role.
  - `python services/api/scripts/check_db_runtime_role.py --require-dsn` verifies runtime role posture for deployment gates.

## Privacy Controls

- Data retention endpoint (`POST /retention/apply`) remains the primary automated control.
- DSAR export endpoint (`POST /privacy/dsar/export`) provides auditable subject-data inventory for supported sources.
- DSAR delete endpoint (`POST /privacy/dsar/delete`) supports dry-run and execution mode:
  - pseudonymizes username references across operational tables,
  - deletes refresh-token rows for the subject,
  - disables and pseudonymizes the user account record.
- Security and audit events include request/tenant context for investigation and evidence.
- Recovery contract exposes RPO/RTO targets via `GET /platform/recovery-contract`.
