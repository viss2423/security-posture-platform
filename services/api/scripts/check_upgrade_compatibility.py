"""Validate migration compatibility guardrails for safe upgrades.

Blocks high-risk migration SQL patterns unless the migration explicitly includes:
  -- secplat: allow-breaking-change
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ALLOW_BREAKING_MARKER = "secplat: allow-breaking-change"
RISK_PATTERNS = (
    ("drop_table", re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE)),
    ("drop_column", re.compile(r"\bDROP\s+COLUMN\b", re.IGNORECASE)),
    ("truncate", re.compile(r"\bTRUNCATE\b", re.IGNORECASE)),
    ("delete_all_rows", re.compile(r"\bDELETE\s+FROM\s+\w+\s*;?", re.IGNORECASE)),
    (
        "alter_drop",
        re.compile(r"\bALTER\s+TABLE\b[^;]{0,300}?\bDROP\b", re.IGNORECASE),
    ),
)


def _line_number(blob: str, offset: int) -> int:
    return blob.count("\n", 0, offset) + 1


def _scan_file(path: Path) -> list[dict[str, Any]]:
    content = path.read_text(encoding="utf-8")
    allow_breaking = ALLOW_BREAKING_MARKER in content.lower()
    if allow_breaking:
        return []

    findings: list[dict[str, Any]] = []
    for pattern_name, pattern in RISK_PATTERNS:
        for match in pattern.finditer(content):
            snippet = " ".join(match.group(0).split())[:180]
            findings.append(
                {
                    "path": str(path),
                    "line": _line_number(content, match.start()),
                    "pattern": pattern_name,
                    "snippet": snippet,
                    "hint": f"add '-- {ALLOW_BREAKING_MARKER}' only with an approved change window",
                }
            )
    return findings


def _scan_migrations(migrations_dir: Path) -> dict[str, Any]:
    all_findings: list[dict[str, Any]] = []
    files = sorted(migrations_dir.glob("*.sql"))
    for path in files:
        all_findings.extend(_scan_file(path))
    return {
        "migration_count": len(files),
        "findings": all_findings,
    }


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--migrations-dir",
        default=str(Path(__file__).resolve().parents[3] / "infra" / "postgres" / "migrations"),
        help="Path to SQL migrations directory.",
    )
    args = parser.parse_args(argv)
    results = _scan_migrations(Path(args.migrations_dir))
    out = {
        "ok": len(results["findings"]) == 0,
        "migration_count": results["migration_count"],
        "findings": results["findings"],
    }
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0 if out["ok"] else 2


if __name__ == "__main__":
    sys.exit(run())
