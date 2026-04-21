"""Build a repo-owned compliance evidence manifest for customer-trust reviews."""

from __future__ import annotations

import argparse
import json
import sys

try:
    from datetime import UTC, datetime
except ImportError:  # pragma: no cover - Python <3.11 compatibility
    from datetime import datetime

    UTC = UTC
from pathlib import Path
from typing import Any

REQUIRED_FILES = (
    "docs/security/compliance-control-register.md",
    "docs/security/appsec-control-matrix.md",
    "docs/security/vulnerability-disclosure.md",
    "docs/security/tenant-isolation-and-privacy.md",
    "docs/contracts/stability-contract.md",
    "docs/contracts/upgrade-policy.md",
    "docs/observability/otel-semantic-conventions.md",
    ".github/workflows/supply-chain.yml",
    ".github/workflows/recovery-drill.yml",
    "services/api/scripts/build_readiness_evidence.py",
)


def _build_manifest(repo_root: Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    missing: list[str] = []
    for rel_path in REQUIRED_FILES:
        path = repo_root / rel_path
        exists = path.exists()
        if not exists:
            missing.append(rel_path)
        entries.append(
            {
                "path": rel_path,
                "exists": exists,
                "size_bytes": path.stat().st_size if exists else 0,
            }
        )
    return {
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "ok": len(missing) == 0,
        "missing": missing,
        "artifacts": entries,
    }


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parents[3]),
        help="Repository root used to resolve required evidence file paths.",
    )
    parser.add_argument(
        "--out",
        default="",
        help="Optional output path for manifest JSON.",
    )
    args = parser.parse_args(argv)
    manifest = _build_manifest(Path(args.repo_root))
    rendered = json.dumps(manifest, indent=2, sort_keys=True)
    print(rendered)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    return 0 if manifest["ok"] else 2


if __name__ == "__main__":
    sys.exit(run())
