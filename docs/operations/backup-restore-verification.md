# Backup and Restore Verification (Phase 5)

Run automated verification with:

```bash
cd services/api
python scripts/generate_backup_artifact.py --dsn "$MIGRATIONS_POSTGRES_DSN" --out ../recovery-drill-backup.sql
python scripts/verify_backup_restore.py --backup-file /path/to/backup.dump --max-age-hours 24 --dry-run
```

Real restore validation (non-dry-run) requires a disposable target database DSN:

```bash
cd services/api
python scripts/verify_backup_restore.py \
  --backup-file /path/to/backup.sql \
  --no-dry-run \
  --restore-target-dsn postgresql+psycopg://secplat_runtime:secplat_runtime@localhost:5433/secplat_restore_tmp \
  --expect-table assets \
  --expect-table findings
```

## What it validates

- Backup file exists.
- Backup file is non-empty.
- Backup file age is within configured RPO window.
- In non-dry-run mode, executes restore validation against a target DSN.
- Validates expected restored objects when `--expect-table` is provided.
- Generates machine-readable verification output for runbooks/audits.

## Recovery Contract

- API endpoint: `GET /platform/recovery-contract`
- Default targets:
  - `RPO`: 24 hours
  - `RTO`: 4 hours

## Scheduled drill automation

- GitHub workflow: `.github/workflows/recovery-drill.yml`
- Runs weekly (`0 3 * * 1`) and can also run manually.
- The workflow is self-contained:
  - starts disposable PostgreSQL
  - provisions the least-privilege runtime role
  - runs startup migrations
  - generates a fresh backup artifact
  - restores into `secplat_restore_tmp`
- Non-dry-run workflow stage validates restore target DB role posture (`not superuser`, `no BYPASSRLS`) before executing restore checks.
