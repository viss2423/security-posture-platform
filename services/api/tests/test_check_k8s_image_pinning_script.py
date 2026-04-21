from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _script_path() -> Path:
    return Path(__file__).resolve().parent.parent / "scripts" / "check_k8s_image_pinning.py"


def test_check_k8s_image_pinning_passes_for_repo_state():
    proc = subprocess.run(
        [sys.executable, str(_script_path())],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '"ok": true' in proc.stdout


def test_check_k8s_image_pinning_fails_for_mutable_tag(tmp_path):
    repo_root = tmp_path / "repo"
    k8s_dir = repo_root / "infra" / "k8s"
    policy_dir = repo_root / "infra" / "policy" / "kyverno"
    k8s_dir.mkdir(parents=True, exist_ok=True)
    policy_dir.mkdir(parents=True, exist_ok=True)
    (k8s_dir / "deployment.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - image: ghcr.io/acme/app:latest\n",
        encoding="utf-8",
    )
    (policy_dir / "verify-secplat-images.yaml").write_text(
        "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nspec:\n  validationFailureAction: Enforce\n  rules:\n    - verifyImages: []\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, str(_script_path()), "--repo-root", str(repo_root)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert '"type": "mutable_tag"' in proc.stdout


def test_check_k8s_image_pinning_strict_mode_fails_for_placeholder_digest(tmp_path):
    repo_root = tmp_path / "repo"
    k8s_dir = repo_root / "infra" / "k8s"
    policy_dir = repo_root / "infra" / "policy" / "kyverno"
    k8s_dir.mkdir(parents=True, exist_ok=True)
    policy_dir.mkdir(parents=True, exist_ok=True)
    (k8s_dir / "deployment.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - image: ghcr.io/your-org/secplat-api@sha256:1111111111111111111111111111111111111111111111111111111111111111\n",
        encoding="utf-8",
    )
    (policy_dir / "verify-secplat-images.yaml").write_text(
        "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nspec:\n  validationFailureAction: Enforce\n  rules:\n    - verifyImages: []\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [
            sys.executable,
            str(_script_path()),
            "--repo-root",
            str(repo_root),
            "--require-real-digests",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert '"type": "placeholder_digest"' in proc.stdout


def test_check_k8s_image_pinning_strict_mode_passes_for_real_digest(tmp_path):
    repo_root = tmp_path / "repo"
    k8s_dir = repo_root / "infra" / "k8s"
    policy_dir = repo_root / "infra" / "policy" / "kyverno"
    k8s_dir.mkdir(parents=True, exist_ok=True)
    policy_dir.mkdir(parents=True, exist_ok=True)
    (k8s_dir / "deployment.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - image: ghcr.io/acme/secplat-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
        encoding="utf-8",
    )
    (policy_dir / "verify-secplat-images.yaml").write_text(
        "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nspec:\n  validationFailureAction: Enforce\n  rules:\n    - verifyImages: []\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [
            sys.executable,
            str(_script_path()),
            "--repo-root",
            str(repo_root),
            "--require-real-digests",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '"ok": true' in proc.stdout
