from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app


def test_platform_security_program_lists_core_frameworks():
    c = TestClient(app)
    r = c.get("/platform/security-program")
    assert r.status_code == 200
    body = r.json()
    names = {entry["name"] for entry in body["security_frameworks"]}
    assert "NIST SSDF (SP 800-218)" in names
    assert "OWASP SAMM" in names
    assert "OWASP ASVS" in names
    assert "configured" in body["vulnerability_disclosure"]
    assert body["vulnerability_disclosure"]["report_endpoint"] == "/security/report"


def test_security_txt_served_from_well_known_path():
    c = TestClient(app)
    r = c.get("/.well-known/security.txt")
    assert r.status_code == 200
    assert "Contact: mailto:" in r.text
    assert "Expires:" in r.text
    assert "Canonical: http://testserver/.well-known/security.txt" in r.text


def test_security_txt_shortcut_path_works():
    c = TestClient(app)
    r = c.get("/security.txt")
    assert r.status_code == 200
    assert "Policy:" in r.text


def test_public_security_report_endpoint_records_audit_event():
    c = TestClient(app)
    r = c.post(
        "/security/report",
        json={
            "reporter_email": "researcher@example.org",
            "title": "Stored XSS in evidence viewer",
            "details": "The evidence viewer renders attacker-controlled HTML from imported findings.",
            "severity": "high",
            "affected_component": "frontend-evidence",
            "reproduction_steps": "1. Import finding with HTML payload. 2. Open evidence viewer.",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "accepted"
    assert body["report_id"].startswith("sec-")
    assert body["intake_sla_hours"] == 24
