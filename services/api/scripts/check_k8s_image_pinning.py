"""Validate Kubernetes image pinning and admission policy wiring."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

IMAGE_LINE_RE = re.compile(r"^\s*(?:-\s*)?image:\s*(?P<image>[^\s#]+)")
PLACEHOLDER_DIGEST_RE = re.compile(r"^([0-9a-f])\1{63}$", re.IGNORECASE)


def _is_placeholder_digest(image_ref: str) -> bool:
    lowered = image_ref.lower()
    if "your-org/" in lowered:
        return True
    if "@sha256:" not in lowered:
        return False
    digest = lowered.split("@sha256:", 1)[1].strip()
    return bool(PLACEHOLDER_DIGEST_RE.match(digest))


def _scan_images(k8s_dir: Path, *, require_real_digests: bool) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in sorted(k8s_dir.rglob("*.yaml")):
        content = path.read_text(encoding="utf-8")
        for lineno, raw_line in enumerate(content.splitlines(), start=1):
            match = IMAGE_LINE_RE.match(raw_line)
            if not match:
                continue
            image_ref = match.group("image").strip()
            if ":latest" in image_ref:
                findings.append(
                    {
                        "type": "mutable_tag",
                        "path": str(path),
                        "line": lineno,
                        "image": image_ref,
                    }
                )
                continue
            if "@sha256:" not in image_ref:
                findings.append(
                    {
                        "type": "missing_digest",
                        "path": str(path),
                        "line": lineno,
                        "image": image_ref,
                    }
                )
                continue
            if require_real_digests and _is_placeholder_digest(image_ref):
                findings.append(
                    {
                        "type": "placeholder_digest",
                        "path": str(path),
                        "line": lineno,
                        "image": image_ref,
                    }
                )
    return findings


def _policy_check(policy_path: Path) -> dict[str, Any]:
    if not policy_path.exists():
        return {
            "ok": False,
            "reason": "missing_policy",
            "path": str(policy_path),
        }
    content = policy_path.read_text(encoding="utf-8")
    has_verify_images = "verifyImages:" in content
    has_enforce = "validationFailureAction: Enforce" in content
    return {
        "ok": has_verify_images and has_enforce,
        "path": str(policy_path),
        "has_verify_images": has_verify_images,
        "has_enforce_mode": has_enforce,
    }


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parents[3]),
        help="Repository root path.",
    )
    parser.add_argument(
        "--k8s-dir",
        default="infra/k8s",
        help="Kubernetes manifests directory (relative to repo root unless absolute path).",
    )
    parser.add_argument(
        "--policy-file",
        default="infra/policy/kyverno/verify-secplat-images.yaml",
        help="Policy-as-code file path (relative to repo root unless absolute path).",
    )
    parser.add_argument(
        "--require-policy",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Fail when policy file is missing or does not include verifyImages + Enforce mode.",
    )
    parser.add_argument(
        "--require-real-digests",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Fail if digest-pinned images still use placeholder values.",
    )
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root)
    k8s_dir = Path(args.k8s_dir)
    if not k8s_dir.is_absolute():
        k8s_dir = repo_root / k8s_dir
    policy_file = Path(args.policy_file)
    if not policy_file.is_absolute():
        policy_file = repo_root / policy_file

    image_findings = _scan_images(k8s_dir, require_real_digests=bool(args.require_real_digests))
    policy = _policy_check(policy_file)
    ok = len(image_findings) == 0 and (policy["ok"] or not bool(args.require_policy))
    out = {
        "ok": ok,
        "k8s_dir": str(k8s_dir),
        "require_real_digests": bool(args.require_real_digests),
        "image_findings": image_findings,
        "policy": policy,
    }
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(run())
