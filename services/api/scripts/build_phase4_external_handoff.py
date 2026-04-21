"""Build a Phase 4 external handoff bundle for assessors and design partners."""

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
    "artifacts/phase4/ga-local-report.json",
    "artifacts/phase4/release-bundle/release-bundle.json",
    "docs/contracts/stability-contract.md",
    "docs/contracts/upgrade-policy.md",
    "docs/operations/backup-restore-verification.md",
    "docs/operations/design-partner-rollout-checklist.md",
    "docs/operations/design-partner-signoff-template.md",
    "docs/operations/external-security-assessment-runbook.md",
    "docs/operations/incident-severity-and-escalation.md",
    "docs/security/vulnerability-disclosure.md",
    "docs/support/support-sla.md",
)

ASSESSMENT_COMMANDS = (
    "py services/api/scripts/verify_phase4_local_ga.py --namespace secplat-phase3 --api-service secplat-api --admin-password <admin-password>",
    "py services/api/scripts/render_release_bundle.py --image-map-json services/api/examples/release-images.example.json --out-dir artifacts/phase4/release-bundle --github-repository acme/security-posture-platform",
    "py services/api/scripts/verify_kyverno_admission.py --repo-root artifacts/phase4/release-bundle --policy-file infra/policy/kyverno/verify-secplat-images.yaml --require-real-attestors",
    "py services/api/scripts/build_readiness_evidence.py --out artifacts/phase4/readiness-manifest.json",
)

MANUAL_CLOSEOUT_ITEMS = (
    "Attach the final external security assessment or pen-test report and remediation status.",
    "Record design-partner validation outcome against the signoff template and collect stakeholder approval.",
)


def _artifact_entry(repo_root: Path, rel_path: str) -> dict[str, Any]:
    path = repo_root / rel_path
    exists = path.exists()
    return {
        "path": rel_path,
        "exists": exists,
        "size_bytes": path.stat().st_size if exists else 0,
    }


def build_handoff_manifest(repo_root: Path) -> dict[str, Any]:
    artifacts = [_artifact_entry(repo_root, rel_path) for rel_path in REQUIRED_FILES]
    missing = [entry["path"] for entry in artifacts if not entry["exists"]]
    return {
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "ok": len(missing) == 0,
        "missing": missing,
        "artifacts": artifacts,
        "assessment_commands": list(ASSESSMENT_COMMANDS),
        "manual_closeout_items": list(MANUAL_CLOSEOUT_ITEMS),
        "target_audiences": [
            "external security assessor",
            "design partner",
            "release manager",
        ],
    }


def _render_assessor_brief(manifest: dict[str, Any]) -> str:
    lines = [
        "# Phase 4 External Assessment Brief",
        "",
        "## Scope",
        "",
        "- Kubernetes-first single-tenant release candidate path",
        "- Release artifact verification, runtime recovery, and operational readiness evidence",
        "",
        "## Evidence Included",
        "",
    ]
    for artifact in manifest["artifacts"]:
        status = "present" if artifact["exists"] else "missing"
        lines.append(f"- `{artifact['path']}`: {status}")
    lines.extend(
        [
            "",
            "## Validation Commands Already Supported",
            "",
        ]
    )
    for command in manifest["assessment_commands"]:
        lines.append(f"- `{command}`")
    lines.extend(
        [
            "",
            "## Manual Closeout Required",
            "",
        ]
    )
    for item in manifest["manual_closeout_items"]:
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def _render_design_partner_packet() -> str:
    return """# Design-Partner Signoff Packet

## Customer

- Organization:
- Environment:
- Primary technical contact:
- Go-live date:

## Validated Workflows

- Login and admin access:
- Telemetry onboarding:
- First alert and first incident:
- Queue and job recovery:
- Backup and restore expectations:
- Upgrade and rollback expectations:

## Operability Review

- Support escalation path reviewed:
- Known gaps reviewed:
- Blocking issues:
- Non-blocking follow-up items:

## Signoff

- Customer signoff owner:
- Customer signoff date:
- SecPlat release owner:
- Release recommendation: approve / reject
"""


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parents[3]),
        help="Repository root used to resolve input files.",
    )
    parser.add_argument(
        "--out-dir",
        default="artifacts/phase4/external-handoff",
        help="Directory where the handoff bundle is written.",
    )
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = repo_root / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest = build_handoff_manifest(repo_root)
    rendered = json.dumps(manifest, indent=2, sort_keys=True)
    (out_dir / "handoff-manifest.json").write_text(rendered + "\n", encoding="utf-8")
    (out_dir / "assessor-brief.md").write_text(
        _render_assessor_brief(manifest) + "\n", encoding="utf-8"
    )
    (out_dir / "design-partner-signoff.md").write_text(
        _render_design_partner_packet(), encoding="utf-8"
    )
    print(rendered)
    return 0 if manifest["ok"] else 2


if __name__ == "__main__":
    sys.exit(run())
