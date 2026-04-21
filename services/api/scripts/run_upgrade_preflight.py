"""Run self-serve upgrade preflight checks for a SecPlat deployment."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib import error, request

REPO_ROOT = Path(__file__).resolve().parents[3]
PLACEHOLDER_TOKENS = (
    "<",
    ">",
    "your-live-api.example.com",
    "your-db-host",
    "your_password",
    "your-admin-password",
)


def _looks_like_placeholder(value: str) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    return any(token in text for token in PLACEHOLDER_TOKENS)


def _run_json(cmd: list[str]) -> dict[str, Any]:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(proc.stdout + proc.stderr)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        raise RuntimeError(proc.stdout or proc.stderr) from exc


def _request_json(url: str, *, timeout: float = 30.0) -> tuple[int, Any]:
    req = request.Request(url, method="GET")
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(payload)
            except json.JSONDecodeError:
                return resp.status, payload
    except error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(payload)
        except json.JSONDecodeError:
            return exc.code, payload


def _http_check(
    *,
    name: str,
    url: str,
    expect_status: int = 200,
    predicate: Any | None = None,
) -> dict[str, Any]:
    status, payload = _request_json(url)
    ok = status == expect_status
    if ok and predicate is not None:
        ok = bool(predicate(payload))
    return {
        "check": name,
        "ok": ok,
        "status": status,
        "detail": payload,
    }


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        default=str(REPO_ROOT),
        help="Repository root used to resolve local contract scripts.",
    )
    parser.add_argument(
        "--api-base-url",
        default="",
        help="Optional live API base URL for readiness and release-gate checks.",
    )
    parser.add_argument(
        "--runtime-dsn",
        default="",
        help="Optional runtime DB DSN used for least-privilege posture validation.",
    )
    parser.add_argument(
        "--require-live",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Fail when live API inputs are not provided.",
    )
    parser.add_argument(
        "--report-out",
        default="",
        help="Optional JSON report output path.",
    )
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    api_base_url = str(args.api_base_url or "").rstrip("/")
    runtime_dsn = str(args.runtime_dsn or "").strip()
    checks: list[dict[str, Any]] = []

    if api_base_url and _looks_like_placeholder(api_base_url):
        checks.append(
            {
                "check": "live_api_placeholder",
                "ok": False,
                "detail": "replace --api-base-url with a real live API URL before using --require-live",
            }
        )
        api_base_url = ""
    if runtime_dsn and _looks_like_placeholder(runtime_dsn):
        checks.append(
            {
                "check": "runtime_dsn_placeholder",
                "ok": False,
                "detail": "replace --runtime-dsn with a real database DSN before using --require-live",
            }
        )
        runtime_dsn = ""

    try:
        checks.append(
            {
                "check": "upgrade_contract",
                "ok": True,
                "detail": _run_json(
                    [
                        sys.executable,
                        str(repo_root / "services/api/scripts/check_upgrade_contract.py"),
                    ]
                ),
            }
        )
        checks.append(
            {
                "check": "upgrade_compatibility",
                "ok": True,
                "detail": _run_json(
                    [
                        sys.executable,
                        str(repo_root / "services/api/scripts/check_upgrade_compatibility.py"),
                    ]
                ),
            }
        )
        if runtime_dsn:
            checks.append(
                {
                    "check": "runtime_role_posture",
                    "ok": True,
                    "detail": _run_json(
                        [
                            sys.executable,
                            str(repo_root / "services/api/scripts/check_db_runtime_role.py"),
                            "--dsn",
                            runtime_dsn,
                            "--require-dsn",
                        ]
                    ),
                }
            )
        if api_base_url:
            checks.extend(
                [
                    _http_check(
                        name="api_health",
                        url=f"{api_base_url}/health",
                        predicate=lambda payload: payload.get("status") == "ok",
                    ),
                    _http_check(
                        name="api_ready",
                        url=f"{api_base_url}/ready",
                        predicate=lambda payload: payload.get("status") == "ok",
                    ),
                    _http_check(
                        name="release_gate_current",
                        url=f"{api_base_url}/platform/release-gate/current?strict_missing=true",
                        predicate=lambda payload: payload.get("gate_passed") is True,
                    ),
                    _http_check(
                        name="readiness_contract",
                        url=f"{api_base_url}/platform/readiness-contract",
                        predicate=lambda payload: bool(payload.get("support_sla")),
                    ),
                ]
            )
        elif args.require_live:
            checks.append(
                {
                    "check": "live_inputs_present",
                    "ok": False,
                    "detail": "api_base_url required when --require-live is set",
                }
            )
    except Exception as exc:
        checks.append({"check": "upgrade_preflight", "ok": False, "detail": str(exc)})

    out = {
        "ok": all(bool(item.get("ok")) for item in checks),
        "api_base_url": api_base_url or None,
        "runtime_dsn_provided": bool(runtime_dsn),
        "checks": checks,
    }
    rendered = json.dumps(out, indent=2, sort_keys=True)
    print(rendered)
    if args.report_out:
        Path(args.report_out).write_text(rendered + "\n", encoding="utf-8")
    return 0 if out["ok"] else 2


if __name__ == "__main__":
    sys.exit(run())
