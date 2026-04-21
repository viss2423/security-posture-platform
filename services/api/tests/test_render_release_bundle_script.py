from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _script_path() -> Path:
    return Path(__file__).resolve().parent.parent / "scripts" / "render_release_bundle.py"


def test_render_release_bundle_rewrites_placeholder_images_and_subject(tmp_path):
    repo_root = tmp_path / "repo"
    (repo_root / "infra" / "k8s").mkdir(parents=True, exist_ok=True)
    (repo_root / "infra" / "policy" / "kyverno").mkdir(parents=True, exist_ok=True)
    (repo_root / "infra" / "k8s" / "deployment.yaml").write_text(
        (
            "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n"
            "      containers:\n"
            "        - image: ghcr.io/your-org/secplat-api@sha256:1111111111111111111111111111111111111111111111111111111111111111\n"
        ),
        encoding="utf-8",
    )
    (repo_root / "infra" / "policy" / "kyverno" / "verify-secplat-images.yaml").write_text(
        (
            "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nspec:\n  rules:\n"
            "    - verifyImages:\n"
            "        - imageReferences:\n"
            "            - ghcr.io/your-org/secplat-*\n"
            "          attestors:\n"
            "            - entries:\n"
            "                - keyless:\n"
            "                    issuer: https://token.actions.githubusercontent.com\n"
            "                    subject: https://github.com/your-org/security-posture-platform/.github/workflows/supply-chain.yml@refs/heads/main\n"
        ),
        encoding="utf-8",
    )
    image_map = {
        "api": "ghcr.io/acme/secplat-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "worker-web": "ghcr.io/acme/secplat-worker-web@sha256:123456789abcdef00123456789abcdef00123456789abcdef00123456789abcde",
        "correlator": "ghcr.io/acme/secplat-correlator@sha256:23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
        "deriver": "ghcr.io/acme/secplat-deriver@sha256:3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012",
        "notifier": "ghcr.io/acme/secplat-notifier@sha256:456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123",
        "ingestion": "ghcr.io/acme/secplat-ingestion@sha256:56789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234",
    }
    image_map_path = repo_root / "image-map.json"
    image_map_path.write_text(json.dumps(image_map), encoding="utf-8")
    out_dir = repo_root / "out"
    proc = subprocess.run(
        [
            sys.executable,
            str(_script_path()),
            "--repo-root",
            str(repo_root),
            "--image-map-json",
            str(image_map_path),
            "--out-dir",
            str(out_dir),
            "--github-repository",
            "acme/security-posture-platform",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    deployment = (out_dir / "infra" / "k8s" / "deployment.yaml").read_text(encoding="utf-8")
    policy = (out_dir / "infra" / "policy" / "kyverno" / "verify-secplat-images.yaml").read_text(
        encoding="utf-8"
    )
    assert "ghcr.io/acme/secplat-api@" in deployment
    assert "ghcr.io/acme/secplat-*" in policy
    assert "github.com/acme/security-posture-platform" in policy
