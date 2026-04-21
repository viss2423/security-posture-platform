"""Render a production release bundle from real digest-pinned image inputs."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys

try:
    from datetime import UTC, datetime
except ImportError:  # pragma: no cover - Python <3.11 compatibility
    from datetime import datetime

    UTC = UTC
from pathlib import Path
from typing import Any

COMPONENT_IMAGE_NAME = {
    "api": "secplat-api",
    "worker-web": "secplat-worker-web",
    "correlator": "secplat-correlator",
    "deriver": "secplat-deriver",
    "notifier": "secplat-notifier",
    "ingestion": "secplat-ingestion",
}


def _load_image_map(path: Path) -> dict[str, str]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("image map must be a JSON object")
    image_map = {str(key): str(value) for key, value in raw.items()}
    missing = sorted(set(COMPONENT_IMAGE_NAME) - set(image_map))
    if missing:
        raise ValueError(f"missing image mappings: {', '.join(missing)}")
    return image_map


def _registry_pattern(image_map: dict[str, str]) -> str:
    api_image = image_map["api"]
    image_without_digest = api_image.split("@", 1)[0]
    if not image_without_digest.endswith("secplat-api"):
        raise ValueError("api image must end with secplat-api")
    return image_without_digest[: -len("secplat-api")] + "secplat-*"


def _validate_image_ref(image_ref: str) -> None:
    if "@sha256:" not in image_ref:
        raise ValueError(f"image ref must be digest pinned: {image_ref}")
    if "your-org/" in image_ref:
        raise ValueError(f"image ref still contains placeholder org: {image_ref}")


def _rewrite_content(
    content: str, *, image_map: dict[str, str], github_repository: str, branch_ref: str
) -> str:
    for component, image_name in COMPONENT_IMAGE_NAME.items():
        _validate_image_ref(image_map[component])
        content = re.sub(
            rf"ghcr\.io/your-org/{re.escape(image_name)}@sha256:[0-9a-f]{{64}}",
            image_map[component],
            content,
        )
    content = content.replace("ghcr.io/your-org/secplat-*", _registry_pattern(image_map))
    content = content.replace(
        "https://github.com/your-org/security-posture-platform/.github/workflows/supply-chain.yml@refs/heads/main",
        f"https://github.com/{github_repository}/.github/workflows/supply-chain.yml@{branch_ref}",
    )
    return content


def render_bundle(
    *,
    repo_root: Path,
    out_dir: Path,
    image_map_path: Path,
    github_repository: str,
    branch_ref: str,
) -> dict[str, Any]:
    image_map = _load_image_map(image_map_path)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    (out_dir / "infra").mkdir(parents=True, exist_ok=True)
    for rel_dir in ("infra/k8s", "infra/policy"):
        source_dir = repo_root / rel_dir
        target_dir = out_dir / rel_dir
        for path in source_dir.rglob("*"):
            relative = path.relative_to(source_dir)
            target = target_dir / relative
            if path.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if path.suffix.lower() == ".yaml":
                target.write_text(
                    _rewrite_content(
                        path.read_text(encoding="utf-8"),
                        image_map=image_map,
                        github_repository=github_repository,
                        branch_ref=branch_ref,
                    ),
                    encoding="utf-8",
                )
            else:
                shutil.copy2(path, target)
    manifest = {
        "ok": True,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "out_dir": str(out_dir),
        "github_repository": github_repository,
        "branch_ref": branch_ref,
        "registry_pattern": _registry_pattern(image_map),
        "images": image_map,
    }
    (out_dir / "release-bundle.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parents[3]),
        help="Repository root path.",
    )
    parser.add_argument(
        "--image-map-json",
        default="services/api/examples/release-images.example.json",
        help="JSON file containing component -> image ref mappings.",
    )
    parser.add_argument(
        "--out-dir",
        default="artifacts/release-bundle",
        help="Directory where the rendered release bundle is written.",
    )
    parser.add_argument(
        "--github-repository",
        default="acme/security-posture-platform",
        help="GitHub repository slug used in keyless attestor subject.",
    )
    parser.add_argument(
        "--branch-ref",
        default="refs/heads/main",
        help="Git ref used in keyless attestor subject.",
    )
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    image_map_path = Path(args.image_map_json)
    if not image_map_path.is_absolute():
        image_map_path = repo_root / image_map_path
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = repo_root / out_dir

    try:
        out = render_bundle(
            repo_root=repo_root,
            out_dir=out_dir,
            image_map_path=image_map_path,
            github_repository=str(args.github_repository or "").strip(),
            branch_ref=str(args.branch_ref or "").strip() or "refs/heads/main",
        )
    except Exception as exc:
        out = {"ok": False, "errors": [str(exc)]}

    print(json.dumps(out, indent=2, sort_keys=True))
    return 0 if out.get("ok") else 2


if __name__ == "__main__":
    sys.exit(run())
