"""Evaluate release readiness from measured SLI values."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app.stability import evaluate_release_gate

DEFAULT_INLINE_ENV = "SECPLAT_SLI_REPORT_JSON"
DEFAULT_PATH_ENV = "SECPLAT_SLI_REPORT_PATH"
DEFAULT_SAMPLE_INPUT = _ROOT / "examples" / "sli-report.json"


def _load_payload_text(text: str) -> dict[str, Any]:
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("Input file must be a JSON object")
    return payload


def _load_payload_file(path: str) -> dict[str, Any]:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Input file not found: {file_path}")
    return _load_payload_text(file_path.read_text(encoding="utf-8"))


def _load_payload_arg(raw_value: str) -> tuple[dict[str, Any], str]:
    candidate = str(raw_value or "").strip()
    if not candidate:
        raise ValueError("input path/json cannot be empty")
    if candidate.startswith("{"):
        return _load_payload_text(candidate), "inline_json"
    return _load_payload_file(candidate), f"file:{candidate}"


def _resolve_payload(
    *,
    input_arg: str,
    input_env_json: str,
    input_env_path: str,
    allow_sample_fallback: bool,
) -> tuple[dict[str, Any], str]:
    if input_arg:
        return _load_payload_arg(input_arg)

    env_json_name = str(input_env_json or "").strip()
    env_path_name = str(input_env_path or "").strip()
    if env_json_name:
        inline_json = str(os.getenv(env_json_name, "") or "").strip()
        if inline_json:
            payload, source = _load_payload_arg(inline_json)
            return payload, f"env:{env_json_name}:{source}"
    if env_path_name:
        path_value = str(os.getenv(env_path_name, "") or "").strip()
        if path_value:
            payload, source = _load_payload_arg(path_value)
            return payload, f"env:{env_path_name}:{source}"

    if allow_sample_fallback and DEFAULT_SAMPLE_INPUT.exists():
        return _load_payload_file(str(DEFAULT_SAMPLE_INPUT)), f"sample:{DEFAULT_SAMPLE_INPUT}"

    raise ValueError(
        "No SLI input provided. Set --input or env "
        f"{env_json_name or DEFAULT_INLINE_ENV}/{env_path_name or DEFAULT_PATH_ENV}."
    )


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        default="",
        help="Path to JSON file or inline JSON containing either raw measurements or {'measurements': {...}}.",
    )
    parser.add_argument(
        "--input-env-json",
        default=DEFAULT_INLINE_ENV,
        help=f"Environment variable containing inline JSON payload (default: {DEFAULT_INLINE_ENV}).",
    )
    parser.add_argument(
        "--input-env-path",
        default=DEFAULT_PATH_ENV,
        help=f"Environment variable containing path to JSON payload (default: {DEFAULT_PATH_ENV}).",
    )
    parser.add_argument(
        "--allow-sample-fallback",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Allow fallback to services/api/examples/sli-report.json when explicit input is missing.",
    )
    parser.add_argument(
        "--strict-missing",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Fail gate if any required SLO measurement is missing.",
    )
    args = parser.parse_args(argv)
    payload, source = _resolve_payload(
        input_arg=args.input,
        input_env_json=args.input_env_json,
        input_env_path=args.input_env_path,
        allow_sample_fallback=bool(args.allow_sample_fallback),
    )
    raw_measurements = payload.get("measurements", payload)
    if not isinstance(raw_measurements, dict):
        raise ValueError("measurements must be a JSON object")
    result = evaluate_release_gate(raw_measurements, strict_missing=args.strict_missing)
    result["input_source"] = source
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["gate_passed"] else 2


if __name__ == "__main__":
    sys.exit(run())
