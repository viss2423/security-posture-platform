from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "build_phase4_external_handoff.py"
SPEC = importlib.util.spec_from_file_location("build_phase4_external_handoff", SCRIPT_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _write(repo_root: Path, rel_path: str, content: str) -> None:
    target = repo_root / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def test_build_handoff_manifest_reports_present_artifacts(tmp_path):
    required = {
        "artifacts/phase4/ga-local-report.json": "{}\n",
        "artifacts/phase4/release-bundle/release-bundle.json": "{}\n",
        "docs/contracts/stability-contract.md": "# stability\n",
        "docs/contracts/upgrade-policy.md": "# upgrade\n",
        "docs/operations/backup-restore-verification.md": "# backup\n",
        "docs/operations/design-partner-rollout-checklist.md": "# rollout\n",
        "docs/operations/design-partner-signoff-template.md": "# signoff\n",
        "docs/operations/external-security-assessment-runbook.md": "# assessor\n",
        "docs/operations/incident-severity-and-escalation.md": "# incident\n",
        "docs/security/vulnerability-disclosure.md": "# disclosure\n",
        "docs/support/support-sla.md": "# sla\n",
    }
    for rel_path, content in required.items():
        _write(tmp_path, rel_path, content)

    manifest = MODULE.build_handoff_manifest(tmp_path)
    assert manifest["ok"] is True
    assert manifest["missing"] == []
    assert len(manifest["artifacts"]) == len(required)


def test_script_run_writes_bundle_and_fails_when_artifacts_missing(tmp_path):
    out_dir = tmp_path / "out"
    exit_code = MODULE.run(
        [
            "--repo-root",
            str(tmp_path),
            "--out-dir",
            str(out_dir),
        ]
    )
    assert exit_code == 2
    manifest_path = out_dir / "handoff-manifest.json"
    assert manifest_path.exists()
    assert (out_dir / "assessor-brief.md").exists()
    assert (out_dir / "design-partner-signoff.md").exists()
