from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_script_module():
    script_path = Path(__file__).resolve().parent.parent / "scripts" / "verify_kyverno_admission.py"
    spec = importlib.util.spec_from_file_location("verify_kyverno_admission", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_verify_kyverno_admission_static_checks_accept_policy_shape(tmp_path):
    mod = _load_script_module()
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        (
            "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nspec:\n  rules:\n"
            "    - name: require-image-digests\n"
            "      validate:\n        pattern:\n          spec:\n            containers:\n              - image: '*@sha256:*'\n"
            "    - name: verify-secplat-images-keyless\n"
            "      verifyImages:\n"
            "        - imageReferences:\n"
            "            - ghcr.io/acme/secplat-*\n"
            "          mutateDigest: false\n"
            "          required: true\n"
            "          attestors:\n"
            "            - entries:\n"
            "                - keyless:\n"
            "                    issuer: https://token.actions.githubusercontent.com\n"
            "                    subject: https://github.com/acme/security-posture-platform/.github/workflows/supply-chain.yml@refs/heads/main\n"
        ),
        encoding="utf-8",
    )
    out = mod._static_keyless_checks(policy_path, require_real_attestors=True)
    assert out["ok"] is True
