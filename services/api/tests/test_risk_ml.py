import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from app.main import app

pytestmark = pytest.mark.skipif(
    not os.getenv("POSTGRES_DSN"),
    reason="POSTGRES_DSN not set; risk-ml tests require Postgres",
)


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def _login(client: TestClient, username: str, password: str) -> dict:
    response = client.post("/auth/login", data={"username": username, "password": password})
    if response.status_code != 200:
        pytest.skip(f"Login failed for {username}: {response.status_code} {response.text}")
    token = response.json().get("access_token")
    assert token
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def admin_headers(client):
    return _login(
        client,
        os.getenv("ADMIN_USERNAME", "admin"),
        os.getenv("ADMIN_PASSWORD", "admin"),
    )


@pytest.fixture(scope="module")
def viewer_headers(client):
    return _login(client, "viewer", "viewer")


def test_risk_model_status_bootstrap_and_train(client, admin_headers, viewer_headers):
    status_before = client.get("/ai/risk-scoring/status", headers=viewer_headers)
    assert status_before.status_code == 200, status_before.text
    before_payload = status_before.json()
    before_labels = int(before_payload["readiness"]["summary"]["total_labels"])

    denied = client.post("/ai/risk-scoring/bootstrap-labels", headers=viewer_headers)
    assert denied.status_code == 403

    bootstrapped = client.post("/ai/risk-scoring/bootstrap-labels", headers=admin_headers)
    assert bootstrapped.status_code == 200, bootstrapped.text
    bootstrap_payload = bootstrapped.json()
    assert bootstrap_payload["summary"]["total_labels"] >= before_labels
    assert bootstrap_payload["summary"]["positive_labels"] >= 1
    assert bootstrap_payload["summary"]["negative_labels"] >= 1

    trained = client.post("/ai/risk-scoring/train", headers=admin_headers, json={})
    assert trained.status_code == 200, trained.text
    train_payload = trained.json()
    assert train_payload["artifact_exists"] is True
    assert train_payload["training_rows"] >= 10
    assert train_payload["metadata"]["algorithm"] == "logistic_regression"
    assert train_payload["metadata"]["calibration_method"] in {"sigmoid", "isotonic"}
    assert train_payload["metadata"]["recommended_threshold"] is not None
    assert train_payload["snapshot_id"] >= 1

    status_after = client.get("/ai/risk-scoring/status", headers=admin_headers)
    assert status_after.status_code == 200, status_after.text
    after_payload = status_after.json()
    assert after_payload["artifact_exists"] is True
    assert after_payload["model_metadata"] is not None
    assert after_payload["model_metadata"]["active_threshold"] is not None
    assert after_payload["latest_snapshot"] is not None

    evaluation = client.get("/ai/risk-scoring/evaluation", headers=viewer_headers)
    assert evaluation.status_code == 200, evaluation.text
    evaluation_payload = evaluation.json()
    assert evaluation_payload["labeled_evaluation"]["rows"] >= 10
    assert "confusion_matrix" in evaluation_payload["labeled_evaluation"]
    assert "brier_score" in evaluation_payload["labeled_evaluation"]
    assert isinstance(evaluation_payload["threshold_sweep"], list)
    assert evaluation_payload["calibration"]["method"] in {"sigmoid", "isotonic"}
    assert isinstance(evaluation_payload["calibration"]["bins"], list)
    assert evaluation_payload["training_baseline"]["label_counts"]
    assert evaluation_payload["training_baseline"]["label_source_counts"]
    assert "score_distribution_psi" in evaluation_payload["drift"]
    assert isinstance(evaluation_payload["review_queue"], list)
    if evaluation_payload["review_queue"]:
        first = evaluation_payload["review_queue"][0]
        assert 0.0 <= first["uncertainty"] <= 1.0
        assert "distance_from_threshold" in first
        if len(evaluation_payload["review_queue"]) > 1:
            second = evaluation_payload["review_queue"][1]
            assert first["uncertainty"] >= second["uncertainty"]

    threshold_out = client.post(
        "/ai/risk-scoring/threshold",
        headers=admin_headers,
        json={"threshold": 0.61, "source": "manual"},
    )
    assert threshold_out.status_code == 200, threshold_out.text
    threshold_payload = threshold_out.json()
    assert float(threshold_payload["active_threshold"]) == pytest.approx(0.61, rel=0, abs=1e-6)
    assert threshold_payload["threshold_source"] == "manual"

    evaluation_manual = client.get(
        "/ai/risk-scoring/evaluation",
        headers=viewer_headers,
    )
    assert evaluation_manual.status_code == 200, evaluation_manual.text
    assert float(evaluation_manual.json()["threshold"]) == pytest.approx(0.61, rel=0, abs=1e-6)

    snapshot_create = client.post(
        "/ai/risk-scoring/snapshots",
        headers=admin_headers,
        json={"threshold": 0.61},
    )
    assert snapshot_create.status_code == 200, snapshot_create.text
    snapshot_payload = snapshot_create.json()
    assert snapshot_payload["snapshot_id"] >= 1

    snapshot_list = client.get("/ai/risk-scoring/snapshots?limit=5", headers=viewer_headers)
    assert snapshot_list.status_code == 200, snapshot_list.text
    items = snapshot_list.json()["items"]
    assert items

    snapshot_detail = client.get(
        f"/ai/risk-scoring/snapshots/{snapshot_payload['snapshot_id']}",
        headers=viewer_headers,
    )
    assert snapshot_detail.status_code == 200, snapshot_detail.text
    detail_payload = snapshot_detail.json()
    assert detail_payload["summary_json"]["threshold"] == pytest.approx(0.61, rel=0, abs=1e-6)
