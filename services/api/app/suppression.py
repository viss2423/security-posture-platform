"""Phase 3.2: Maintenance windows and suppression rules. Known maintenance doesn't produce incidents/alerts."""

from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.orm import Session


def is_asset_suppressed(db: Session, asset_key: str, at_time: datetime | None = None) -> bool:
    """True if asset is in a maintenance window or covered by an active suppression rule."""
    now = at_time or datetime.now(UTC)
    # Maintenance window: asset_key and now in [start_at, end_at]
    row = db.execute(
        text("""
            SELECT 1 FROM maintenance_windows
            WHERE asset_key = :ak AND :now >= start_at AND :now <= end_at
            LIMIT 1
        """),
        {"ak": asset_key, "now": now},
    ).scalar()
    if row:
        return True
    # Suppression rule: scope 'asset' + scope_value = asset_key, or scope 'all'
    row = db.execute(
        text("""
            SELECT 1 FROM suppression_rules
            WHERE ((scope = 'asset' AND scope_value = :ak) OR scope = 'all')
            AND :now >= starts_at AND :now <= ends_at
            LIMIT 1
        """),
        {"ak": asset_key, "now": now},
    ).scalar()
    return bool(row)


def is_finding_suppressed(db: Session, finding_key: str, at_time: datetime | None = None) -> bool:
    """True if finding is covered by an active suppression rule (scope 'finding' or 'all')."""
    now = at_time or datetime.now(UTC)
    row = db.execute(
        text("""
            SELECT 1 FROM suppression_rules
            WHERE ((scope = 'finding' AND scope_value = :fk) OR scope = 'all')
            AND :now >= starts_at AND :now <= ends_at
            LIMIT 1
        """),
        {"fk": finding_key, "now": now},
    ).scalar()
    return bool(row)
