"""Validate upgrade contract artifacts (migration numbering + policy file)."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

MIGRATION_RE = re.compile(r"^(\d{3})_.+\.sql$")
REQUIRED_POLICY_SECTIONS = ("Versioning", "Upgrade order", "Rollback")


def _validate_migrations(migrations_dir: Path) -> dict[str, Any]:
    errors: list[str] = []
    files = sorted(path.name for path in migrations_dir.glob("*.sql"))
    numbers: list[int] = []
    for name in files:
        match = MIGRATION_RE.match(name)
        if not match:
            errors.append(f"invalid migration name: {name}")
            continue
        numbers.append(int(match.group(1)))
    unique_numbers = sorted(set(numbers))
    if unique_numbers:
        expected = list(range(unique_numbers[0], unique_numbers[-1] + 1))
        if unique_numbers != expected:
            missing = sorted(set(expected) - set(unique_numbers))
            errors.append(f"missing migration numbers: {missing}")
    return {
        "count": len(files),
        "first": unique_numbers[0] if unique_numbers else None,
        "last": unique_numbers[-1] if unique_numbers else None,
        "errors": errors,
    }


def _validate_policy(policy_file: Path) -> dict[str, Any]:
    errors: list[str] = []
    if not policy_file.exists():
        errors.append(f"missing policy file: {policy_file}")
        return {"errors": errors}
    content = policy_file.read_text(encoding="utf-8")
    for section in REQUIRED_POLICY_SECTIONS:
        if section not in content:
            errors.append(f"policy missing section: {section}")
    return {"errors": errors}


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--migrations-dir",
        default=str(Path(__file__).resolve().parents[3] / "infra" / "postgres" / "migrations"),
    )
    parser.add_argument(
        "--policy-file",
        default=str(
            Path(__file__).resolve().parents[3] / "docs" / "contracts" / "upgrade-policy.md"
        ),
    )
    args = parser.parse_args(argv)
    migrations = _validate_migrations(Path(args.migrations_dir))
    policy = _validate_policy(Path(args.policy_file))
    errors = [*migrations["errors"], *policy["errors"]]
    out = {
        "ok": len(errors) == 0,
        "migrations": {
            "count": migrations["count"],
            "first": migrations["first"],
            "last": migrations["last"],
        },
        "errors": errors,
    }
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0 if out["ok"] else 2


if __name__ == "__main__":
    sys.exit(run())
