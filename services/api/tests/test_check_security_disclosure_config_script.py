from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_script_module():
    script_path = (
        Path(__file__).resolve().parent.parent / "scripts" / "check_security_disclosure_config.py"
    )
    spec = importlib.util.spec_from_file_location("check_security_disclosure_config", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_security_disclosure_check_accepts_real_values():
    mod = _load_script_module()
    out = mod.evaluate_security_disclosure(
        contact_email="security@acme-security.io",
        contact_url="https://acme-security.io/report",
        policy_url="https://acme-security.io/security",
        require_real=True,
    )
    assert out["ok"] is True
    assert out["errors"] == []


def test_security_disclosure_check_rejects_placeholder_values():
    mod = _load_script_module()
    out = mod.evaluate_security_disclosure(
        contact_email="security@secplat.local",
        contact_url="",
        policy_url="https://secplat.local/security",
        require_real=True,
    )
    assert out["ok"] is False
    assert any("placeholder" in item["detail"] for item in out["checks"] if not item["ok"])
