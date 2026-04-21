"""Validate incident postmortem evidence artifacts."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

REQUIRED_HEADERS = (
    "## Summary",
    "## Impact",
    "## Timeline",
    "## Root Cause",
    "## Corrective Actions",
    "## Prevention Actions",
    "## Owner",
)

FILENAME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}-sev[12]-[a-z0-9-]+\.md$")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _validate_template(template_path: Path) -> list[str]:
    errors: list[str] = []
    if not template_path.exists():
        return [f"missing template file: {template_path}"]
    content = _read(template_path)
    for header in REQUIRED_HEADERS:
        if header not in content:
            errors.append(f"template missing header: {header}")
    return errors


def _validate_index(index_path: Path) -> list[str]:
    errors: list[str] = []
    if not index_path.exists():
        return [f"missing index file: {index_path}"]
    content = _read(index_path)
    if "Postmortem" not in content:
        errors.append("index missing postmortem description")
    if "sev1" not in content.lower() or "sev2" not in content.lower():
        errors.append("index should describe sev1/sev2 expectations")
    return errors


def _validate_postmortem_file(path: Path) -> list[str]:
    errors: list[str] = []
    content = _read(path)
    if not FILENAME_RE.match(path.name):
        errors.append(
            f"invalid filename format: {path.name} (expected YYYY-MM-DD-sev1|sev2-<slug>.md)"
        )
    for header in REQUIRED_HEADERS:
        if header not in content:
            errors.append(f"{path.name}: missing header: {header}")
    prevention_block = re.search(
        r"## Prevention Actions(?P<body>[\s\S]*?)(?:\n## |\Z)",
        content,
        flags=re.IGNORECASE,
    )
    if not prevention_block:
        errors.append(f"{path.name}: missing Prevention Actions section body")
    else:
        lines = [line.strip() for line in prevention_block.group("body").splitlines()]
        action_lines = [line for line in lines if line.startswith("- ") and len(line) > 2]
        if len(action_lines) < 1:
            errors.append(f"{path.name}: Prevention Actions must include at least one bullet")
    return errors


def _collect_postmortems(directory: Path) -> list[Path]:
    return sorted(
        path for path in directory.glob("*.md") if path.name not in {"README.md", "template.md"}
    )


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--postmortems-dir",
        default=str(Path(__file__).resolve().parents[3] / "docs" / "operations" / "postmortems"),
        help="Directory containing postmortem files, template.md, and README.md.",
    )
    args = parser.parse_args(argv)

    postmortems_dir = Path(args.postmortems_dir)
    template_path = postmortems_dir / "template.md"
    index_path = postmortems_dir / "README.md"
    files = _collect_postmortems(postmortems_dir) if postmortems_dir.exists() else []

    errors = [
        *_validate_template(template_path),
        *_validate_index(index_path),
    ]
    per_file: list[dict[str, Any]] = []
    for path in files:
        file_errors = _validate_postmortem_file(path)
        per_file.append({"path": str(path), "ok": len(file_errors) == 0, "errors": file_errors})
        errors.extend(file_errors)

    out = {
        "ok": len(errors) == 0,
        "postmortems_dir": str(postmortems_dir),
        "postmortem_count": len(files),
        "files": per_file,
        "errors": errors,
    }
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0 if out["ok"] else 2


if __name__ == "__main__":
    sys.exit(run())
