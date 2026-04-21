"""Validate Kyverno image admission controls for release bundles."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

KYVERNO_IMAGE = "ghcr.io/kyverno/kyverno-cli:v1.13.4"


def _run_kyverno(
    *, repo_root: Path, policy_path: Path, resource_path: Path
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{repo_root.resolve()}:/work",
            KYVERNO_IMAGE,
            "apply",
            f"/work/{policy_path.relative_to(repo_root).as_posix()}",
            "--resource",
            f"/work/{resource_path.relative_to(repo_root).as_posix()}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _dynamic_digest_checks(repo_root: Path, policy_file: Path) -> dict[str, Any]:
    policy = yaml.safe_load(policy_file.read_text(encoding="utf-8"))
    rules = list((policy.get("spec") or {}).get("rules") or [])
    digest_rule = next(
        (
            rule
            for rule in rules
            if isinstance(rule, dict) and str(rule.get("name") or "") == "require-image-digests"
        ),
        None,
    )
    if digest_rule is None:
        return {
            "ok": False,
            "checks": [
                {
                    "check": "digest_rule_present",
                    "ok": False,
                    "detail": "missing require-image-digests rule",
                }
            ],
        }

    validate = dict(digest_rule.get("validate") or {})
    pattern = dict(validate.get("pattern") or {})
    spec = dict(pattern.get("spec") or {})
    container_patterns = list(spec.get("containers") or [])
    init_container_patterns = list(spec.get("=(initContainers)") or [])
    static_checks = [
        {
            "check": "digest_rule_container_pattern",
            "ok": bool(container_patterns and container_patterns[0].get("image") == "*@sha256:*"),
            "detail": container_patterns[0]
            if container_patterns
            else "missing containers image pattern",
        },
        {
            "check": "digest_rule_init_container_pattern",
            "ok": bool(
                init_container_patterns and init_container_patterns[0].get("image") == "*@sha256:*"
            ),
            "detail": init_container_patterns[0]
            if init_container_patterns
            else "missing initContainers image pattern",
        },
    ]

    with tempfile.TemporaryDirectory(dir=repo_root) as tmp_dir:
        tmp_path = Path(tmp_dir)
        policy_path = tmp_path / "digest-only.yaml"
        policy_path.write_text(
            yaml.safe_dump(
                {
                    "apiVersion": "kyverno.io/v1",
                    "kind": "ClusterPolicy",
                    "metadata": {"name": "secplat-digest-only"},
                    "spec": {
                        "validationFailureAction": "Enforce",
                        "background": True,
                        "rules": [digest_rule],
                    },
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        bad_resource = tmp_path / "bad-pod.yaml"
        bad_resource.write_text(
            yaml.safe_dump(
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "bad-image"},
                    "spec": {
                        "containers": [{"name": "api", "image": "ghcr.io/acme/secplat-api:latest"}]
                    },
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        good_resource = tmp_path / "good-pod.yaml"
        good_resource.write_text(
            yaml.safe_dump(
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "good-image"},
                    "spec": {
                        "containers": [
                            {
                                "name": "api",
                                "image": "ghcr.io/acme/secplat-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                            }
                        ]
                    },
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        bad = _run_kyverno(repo_root=repo_root, policy_path=policy_path, resource_path=bad_resource)
        good = _run_kyverno(
            repo_root=repo_root, policy_path=policy_path, resource_path=good_resource
        )

    kyverno_runtime_unavailable = (
        "failed to connect to the docker api"
        in (f"{bad.stdout}\n{bad.stderr}\n{good.stdout}\n{good.stderr}".lower())
        or "cannot find the file specified"
        in f"{bad.stdout}\n{bad.stderr}\n{good.stdout}\n{good.stderr}".lower()
    )
    if kyverno_runtime_unavailable:
        checks = static_checks + [
            {
                "check": "kyverno_runtime_unavailable",
                "ok": True,
                "detail": "Docker/Kyverno runtime unavailable; fell back to static digest policy validation",
            }
        ]
        return {
            "ok": all(item["ok"] for item in checks),
            "mode": "static_fallback",
            "checks": checks,
        }

    checks = [
        {
            "check": "digest_rule_rejects_mutable_tag",
            "ok": bad.returncode != 0 and "validation error" in (bad.stdout or ""),
            "detail": (bad.stdout or bad.stderr or "")[-1000:],
        },
        {
            "check": "digest_rule_accepts_digest_pin",
            "ok": good.returncode == 0 and "fail: 0" in (good.stdout or ""),
            "detail": (good.stdout or good.stderr or "")[-1000:],
        },
    ]
    return {"ok": all(item["ok"] for item in checks), "mode": "kyverno_cli", "checks": checks}


def _static_keyless_checks(policy_file: Path, *, require_real_attestors: bool) -> dict[str, Any]:
    policy = yaml.safe_load(policy_file.read_text(encoding="utf-8"))
    rules = list((policy.get("spec") or {}).get("rules") or [])
    verify_rule = next(
        (
            rule
            for rule in rules
            if isinstance(rule, dict)
            and str(rule.get("name") or "") == "verify-secplat-images-keyless"
        ),
        None,
    )
    if verify_rule is None:
        return {
            "ok": False,
            "checks": [
                {
                    "check": "keyless_verify_rule_present",
                    "ok": False,
                    "detail": "missing verify-secplat-images-keyless rule",
                }
            ],
        }

    verify_images = list(verify_rule.get("verifyImages") or [])
    first = verify_images[0] if verify_images else {}
    entries = list(((first.get("attestors") or [{}])[0]).get("entries") or [])
    keyless = entries[0].get("keyless") if entries else {}
    subject = str((keyless or {}).get("subject") or "").strip()
    pattern = ",".join(str(item) for item in (first.get("imageReferences") or []))
    checks = [
        {
            "check": "keyless_verify_rule_present",
            "ok": bool(verify_images),
            "detail": "verifyImages configured" if verify_images else "verifyImages missing",
        },
        {
            "check": "keyless_required_true",
            "ok": bool(first.get("required") is True),
            "detail": f"required={first.get('required')!r}",
        },
        {
            "check": "keyless_mutate_digest_disabled",
            "ok": bool(first.get("mutateDigest") is False),
            "detail": f"mutateDigest={first.get('mutateDigest')!r}",
        },
        {
            "check": "keyless_issuer_configured",
            "ok": bool(str((keyless or {}).get("issuer") or "").strip()),
            "detail": str((keyless or {}).get("issuer") or "").strip() or "missing issuer",
        },
        {
            "check": "keyless_subject_configured",
            "ok": bool(subject),
            "detail": subject or "missing subject",
        },
    ]
    if require_real_attestors:
        checks.append(
            {
                "check": "keyless_subject_not_placeholder",
                "ok": "your-org/" not in subject,
                "detail": subject,
            }
        )
        checks.append(
            {
                "check": "verify_images_pattern_not_placeholder",
                "ok": "your-org/" not in pattern,
                "detail": pattern or "missing imageReferences",
            }
        )
    return {"ok": all(item["ok"] for item in checks), "checks": checks}


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parents[3]),
        help="Repository root.",
    )
    parser.add_argument(
        "--policy-file",
        default="infra/policy/kyverno/verify-secplat-images.yaml",
        help="Path to the Kyverno verify-images policy.",
    )
    parser.add_argument(
        "--require-real-attestors",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Fail when keyless image references or subject still use placeholder org values.",
    )
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    policy_file = Path(args.policy_file)
    if not policy_file.is_absolute():
        policy_file = repo_root / policy_file

    if not policy_file.exists():
        out = {
            "ok": False,
            "policy_file": str(policy_file),
            "errors": [
                "policy file not found; render the release bundle first or point --repo-root/--policy-file at an existing bundle",
            ],
        }
        print(json.dumps(out, indent=2, sort_keys=True))
        return 2

    digest = _dynamic_digest_checks(repo_root, policy_file)
    keyless = _static_keyless_checks(
        policy_file,
        require_real_attestors=bool(args.require_real_attestors),
    )
    out = {
        "ok": bool(digest["ok"]) and bool(keyless["ok"]),
        "policy_file": str(policy_file),
        "digest_rule": digest,
        "keyless_rule": keyless,
    }
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0 if out["ok"] else 2


if __name__ == "__main__":
    sys.exit(run())
