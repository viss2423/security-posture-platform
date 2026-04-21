"""Validate contract parity between docs, runtime assumptions, and CI wiring."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REQUIRED_EVENT_FIELDS = {"event_id", "event_type", "ts", "org_id"}
REQUIRED_RUNTIME_EVENT_TYPES = {
    "scan.requested",
    "notify.requested",
    "finding.created",
    "alert.triggered",
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _event_contract_check(repo_root: Path) -> tuple[bool, dict[str, Any]]:
    contract_path = repo_root / "docs" / "contracts" / "event-envelope.json"
    if not contract_path.exists():
        return False, {"check": "event_contract_exists", "ok": False, "detail": str(contract_path)}
    payload = json.loads(contract_path.read_text(encoding="utf-8"))
    required = set(payload.get("required") or [])
    event_types = set(payload.get("properties", {}).get("event_type", {}).get("enum") or [])
    missing_fields = sorted(REQUIRED_EVENT_FIELDS - required)
    missing_types = sorted(REQUIRED_RUNTIME_EVENT_TYPES - event_types)
    ok = len(missing_fields) == 0 and len(missing_types) == 0
    return ok, {
        "check": "event_contract_runtime_parity",
        "ok": ok,
        "missing_required_fields": missing_fields,
        "missing_runtime_event_types": missing_types,
    }


def _k8s_readiness_check(repo_root: Path) -> tuple[bool, dict[str, Any]]:
    path = repo_root / "infra" / "k8s" / "deployment-api.yaml"
    if not path.exists():
        return False, {"check": "k8s_api_deployment_exists", "ok": False, "detail": str(path)}
    content = path.read_text(encoding="utf-8")
    has_readiness = "readinessProbe:" in content
    has_ready_path = "path: /ready" in content
    ok = has_readiness and has_ready_path
    return ok, {
        "check": "k8s_readiness_probe_contract",
        "ok": ok,
        "has_readiness_probe": has_readiness,
        "uses_ready_endpoint": has_ready_path,
    }


def _workflow_gate_check(repo_root: Path) -> tuple[bool, dict[str, Any]]:
    path = repo_root / ".github" / "workflows" / "supply-chain.yml"
    if not path.exists():
        return False, {"check": "supply_chain_workflow_exists", "ok": False, "detail": str(path)}
    content = path.read_text(encoding="utf-8")
    invokes_gate = "check_release_gate.py" in content
    uses_env_source = (
        "SECPLAT_SLI_REPORT_JSON" in content
        or "SECPLAT_SLI_REPORT_PATH" in content
        or "--input-env-json" in content
        or "--input-env-path" in content
    )
    invokes_parity = "check_contract_parity.py" in content
    ok = invokes_gate and uses_env_source and invokes_parity
    return ok, {
        "check": "supply_chain_workflow_release_gate_wiring",
        "ok": ok,
        "invokes_release_gate": invokes_gate,
        "uses_environment_input": uses_env_source,
        "invokes_contract_parity": invokes_parity,
    }


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        default=str(_repo_root()),
        help="Repository root path.",
    )
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root)
    checks: list[dict[str, Any]] = []
    check_fns = (_event_contract_check, _k8s_readiness_check, _workflow_gate_check)
    ok = True
    for fn in check_fns:
        check_ok, details = fn(repo_root)
        checks.append(details)
        ok = ok and check_ok
    out = {"ok": ok, "checks": checks}
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(run())
