"""Smoke-test live OIDC discovery configuration."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-configured",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Fail when OIDC is not configured.",
    )
    args = parser.parse_args(argv)

    sys.path.insert(0, str(_repo_root() / "services" / "api"))
    from app.routers import auth  # pylint: disable=import-outside-toplevel

    if not auth._oidc_enabled():
        out = {
            "ok": not bool(args.require_configured),
            "skipped": True,
            "reason": "oidc_not_configured",
        }
        print(json.dumps(out, indent=2, sort_keys=True))
        return 0 if out["ok"] else 2

    try:
        auth._oidc_config = None
        config = auth._get_oidc_config(force_refresh=True)
        out: dict[str, Any] = {
            "ok": True,
            "skipped": False,
            "issuer": str(config.get("issuer") or ""),
            "authorization_endpoint": str(config.get("authorization_endpoint") or ""),
            "token_endpoint": str(config.get("token_endpoint") or ""),
            "jwks_uri": str(config.get("jwks_uri") or ""),
        }
    except Exception as exc:
        out = {
            "ok": False,
            "skipped": False,
            "errors": [str(exc)],
        }
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0 if out.get("ok") else 2


if __name__ == "__main__":
    sys.exit(run())
