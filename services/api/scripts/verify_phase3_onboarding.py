from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from fastapi.testclient import TestClient

API_ROOT = Path(__file__).resolve().parents[1]
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))

from app.main import app  # noqa: E402


def _login(client: TestClient, username: str, password: str) -> str:
    response = client.post("/auth/login", data={"username": username, "password": password})
    response.raise_for_status()
    token = response.json().get("access_token")
    if not token:
        raise RuntimeError("access_token missing from login response")
    return token


def _assert_ok(response, context: str) -> dict:
    if response.status_code >= 400:
        raise RuntimeError(f"{context} failed: {response.status_code} {response.text}")
    return response.json()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify the Phase 3 onboarding and demo control flow."
    )
    parser.add_argument("--admin-username", default=os.getenv("ADMIN_USERNAME", "admin"))
    parser.add_argument("--admin-password", default=os.getenv("ADMIN_PASSWORD", "admin"))
    args = parser.parse_args()

    suffix = str(int(time.time()))
    asset_key = f"phase3-onboarding-{suffix}"
    rule_name = f"Phase 3 onboarding detector {suffix}"
    rule_key = f"phase3-onboarding-{suffix}"
    incident_key = f"phase3:{asset_key}"

    client = TestClient(app)

    unauth = client.get("/platform/demo/status")
    if unauth.status_code != 401:
        raise RuntimeError(f"demo status should require auth, got {unauth.status_code}")

    token = _login(client, args.admin_username, args.admin_password)
    headers = {"Authorization": f"Bearer {token}"}

    seed = _assert_ok(
        client.post("/platform/demo/seed", headers=headers, json={"force": True}),
        "demo seed",
    )
    if not seed.get("result", {}).get("seeded"):
        raise RuntimeError(f"demo seed did not report seeded=true: {seed}")

    asset = _assert_ok(
        client.post(
            "/assets/",
            headers=headers,
            json={
                "asset_key": asset_key,
                "type": "external_web",
                "name": "Phase 3 onboarding asset",
                "owner": "platform-security",
                "address": "https://gateway.phase3.example.test",
                "environment": "prod",
                "criticality": "high",
                "asset_type": "external_web",
            },
        ),
        "asset create",
    )
    if asset.get("asset_key") != asset_key:
        raise RuntimeError(f"asset create returned unexpected key: {asset}")

    telemetry = _assert_ok(
        client.post(
            "/telemetry/ingest",
            headers=headers,
            json={
                "source": "cowrie",
                "asset_key": asset_key,
                "create_alerts": True,
                "events": [
                    {
                        "eventid": "cowrie.login.failed",
                        "session": f"phase3-{asset_key}",
                        "src_ip": "203.0.113.90",
                        "username": "root",
                        "message": "Failed login attempt from phase3 verification",
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    }
                ],
            },
        ),
        "telemetry ingest",
    )
    if int(telemetry.get("processed_events") or 0) < 1:
        raise RuntimeError(f"telemetry ingest did not process events: {telemetry}")

    rule = _assert_ok(
        client.post(
            "/detections/rules",
            headers=headers,
            json={
                "name": rule_name,
                "rule_key": rule_key,
                "description": "Phase 3 onboarding verification detector",
                "source": "cowrie",
                "stage": "active",
                "severity": "high",
                "enabled": True,
                "definition_json": {
                    "condition_mode": "all",
                    "conditions": [
                        {"field": "event_type", "op": "eq", "value": "cowrie.login.failed"}
                    ],
                },
            },
        ),
        "detection create",
    )
    detection_run = _assert_ok(
        client.post(
            f"/detections/rules/{int(rule['rule_id'])}/test",
            headers=headers,
            json={"lookback_hours": 168, "create_alerts": True},
        ),
        "detection test",
    )
    if int(detection_run.get("matches") or 0) < 1:
        raise RuntimeError(f"detection test did not match seeded telemetry: {detection_run}")

    alerts = _assert_ok(client.get("/alerts", headers=headers), "alerts fetch")
    candidate_alerts = [
        *(alerts.get("firing") or []),
        *(alerts.get("acked") or []),
        *(alerts.get("suppressed") or []),
        *(alerts.get("resolved") or []),
    ]
    matched_alert = next(
        (item for item in candidate_alerts if item.get("asset_key") == asset_key), None
    )
    if not matched_alert:
        raise RuntimeError(f"expected an alert for {asset_key}, got {alerts}")

    incident = _assert_ok(
        client.post(
            "/incidents",
            headers=headers,
            json={
                "incident_key": incident_key,
                "title": f"Phase 3 incident for {asset_key}",
                "severity": "high",
                "asset_keys": [asset_key],
                "alert_ids": [matched_alert["alert_id"]] if matched_alert.get("alert_id") else [],
            },
        ),
        "incident create",
    )
    if int(incident.get("id") or 0) <= 0:
        raise RuntimeError(f"incident create returned invalid payload: {incident}")

    incident_list = _assert_ok(client.get("/incidents?limit=25", headers=headers), "incident list")
    if int(incident_list.get("total") or 0) < 1:
        raise RuntimeError(f"incident list did not include created incident: {incident_list}")

    demo_status = _assert_ok(client.get("/platform/demo/status", headers=headers), "demo status")
    if not demo_status.get("seeded"):
        raise RuntimeError(f"demo status did not report seeded state: {demo_status}")

    reset = _assert_ok(client.post("/platform/demo/reset", headers=headers), "demo reset")
    if not reset.get("reset"):
        raise RuntimeError(f"demo reset did not report reset=true: {reset}")

    print(
        {
            "asset_key": asset_key,
            "rule_id": rule["rule_id"],
            "alert_id": matched_alert.get("alert_id"),
            "incident_id": incident["id"],
            "demo_seeded": demo_status["seeded"],
            "demo_reset": reset["reset"],
        }
    )


if __name__ == "__main__":
    main()
