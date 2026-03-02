import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import joblib
import pytest
from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from app import risk_model
from app.risk_features import build_risk_feature_vector
from app.risk_scoring import compute_finding_risk


@pytest.fixture(autouse=True)
def disable_risk_model_by_default(monkeypatch):
    monkeypatch.setattr(risk_model.settings, "RISK_MODEL_ENABLED", False)
    risk_model.clear_risk_model_cache()
    yield
    risk_model.clear_risk_model_cache()


def test_high_risk_external_production_finding_scores_high():
    now = datetime(2026, 3, 1, tzinfo=UTC)
    out = compute_finding_risk(
        {
            "finding": {
                "finding_key": "finding-1",
                "severity": "high",
                "confidence": "high",
                "status": "open",
                "source": "tls_scan",
                "first_seen": now - timedelta(days=14),
            },
            "asset": {
                "asset_key": "edge-api",
                "type": "external_web",
                "asset_type": "service",
                "environment": "prod",
                "criticality": "high",
                "verified": True,
                "is_active": True,
                "tags": ["public"],
                "metadata": {"internet_facing": True},
            },
        },
        now=now,
    )
    assert out["risk_score"] >= 85
    assert out["risk_level"] == "critical"
    drivers = set(out["risk_factors_json"]["drivers"])
    assert "internet_facing" in drivers
    assert "prod_environment" in drivers
    assert "high_criticality" in drivers


def test_remediated_finding_scores_low():
    now = datetime(2026, 3, 1, tzinfo=UTC)
    out = compute_finding_risk(
        {
            "finding": {
                "finding_key": "finding-2",
                "severity": "critical",
                "confidence": "high",
                "status": "remediated",
                "source": "header_scan",
                "first_seen": now - timedelta(days=45),
            },
            "asset": {
                "asset_key": "internal-app",
                "type": "app",
                "asset_type": "service",
                "environment": "prod",
                "criticality": "high",
                "verified": False,
                "is_active": True,
                "tags": [],
                "metadata": {},
            },
        },
        now=now,
    )
    assert out["risk_score"] <= 20
    assert out["risk_level"] == "low"
    assert "remediated" in out["risk_factors_json"]["drivers"]


def test_accepted_risk_expired_scores_higher_than_active_acceptance():
    now = datetime(2026, 3, 1, tzinfo=UTC)
    base_context = {
        "finding": {
            "finding_key": "finding-3",
            "severity": "medium",
            "confidence": "medium",
            "status": "accepted_risk",
            "source": "pytest",
            "first_seen": now - timedelta(days=10),
        },
        "asset": {
            "asset_key": "svc-1",
            "type": "app",
            "asset_type": "service",
            "environment": "staging",
            "criticality": "medium",
            "verified": False,
            "is_active": True,
            "tags": [],
            "metadata": {},
        },
    }
    active = compute_finding_risk(
        {
            **base_context,
            "finding": {
                **base_context["finding"],
                "accepted_risk_reason": "Known issue",
                "accepted_risk_expires_at": now + timedelta(days=10),
            },
        },
        now=now,
    )
    expired = compute_finding_risk(
        {
            **base_context,
            "finding": {
                **base_context["finding"],
                "accepted_risk_reason": "Known issue",
                "accepted_risk_expires_at": now - timedelta(days=1),
            },
        },
        now=now,
    )
    assert expired["risk_score"] > active["risk_score"]
    assert "accepted_risk_expired" in expired["risk_factors_json"]["drivers"]


def test_ml_model_prediction_can_override_heuristic(monkeypatch, tmp_path):
    now = datetime(2026, 3, 1, tzinfo=UTC)
    high_context = {
        "finding": {
            "finding_key": "finding-ml-high",
            "severity": "critical",
            "confidence": "high",
            "status": "open",
            "source": "tls_scan",
            "first_seen": now - timedelta(days=21),
        },
        "asset": {
            "asset_key": "prod-edge-api",
            "type": "external_web",
            "asset_type": "service",
            "environment": "prod",
            "criticality": "high",
            "verified": True,
            "is_active": True,
            "tags": ["public"],
            "metadata": {"internet_facing": True},
        },
    }
    low_context = {
        "finding": {
            "finding_key": "finding-ml-low",
            "severity": "low",
            "confidence": "low",
            "status": "open",
            "source": "pytest",
            "first_seen": now - timedelta(days=1),
        },
        "asset": {
            "asset_key": "internal-dev-tool",
            "type": "app",
            "asset_type": "service",
            "environment": "dev",
            "criticality": "low",
            "verified": False,
            "is_active": True,
            "tags": ["internal"],
            "metadata": {},
        },
    }
    training_rows = [
        (high_context, 1),
        (
            {
                **high_context,
                "finding": {**high_context["finding"], "finding_key": "finding-ml-high-2"},
            },
            1,
        ),
        (
            {
                **high_context,
                "finding": {**high_context["finding"], "finding_key": "finding-ml-high-3"},
                "asset": {**high_context["asset"], "criticality": "medium"},
            },
            1,
        ),
        (low_context, 0),
        (
            {
                **low_context,
                "finding": {**low_context["finding"], "finding_key": "finding-ml-low-2"},
                "asset": {**low_context["asset"], "environment": "test"},
            },
            0,
        ),
        (
            {
                **low_context,
                "finding": {**low_context["finding"], "finding_key": "finding-ml-low-3"},
                "asset": {**low_context["asset"], "is_active": False},
            },
            0,
        ),
    ]
    vectorizer = DictVectorizer(sparse=True)
    matrix = vectorizer.fit_transform(
        [build_risk_feature_vector(context, now=now) for context, _ in training_rows]
    )
    model = LogisticRegression(max_iter=1000, random_state=42)
    model.fit(matrix, [target for _, target in training_rows])
    artifact_path = tmp_path / "finding-risk-model.joblib"
    joblib.dump(
        {
            "model": model,
            "explain_model": model,
            "vectorizer": vectorizer,
            "metadata": {
                "algorithm": "logistic_regression",
                "target_name": "incident_worthy",
                "positive_class": 1,
                "trained_at": now.isoformat(),
                "dataset_size": len(training_rows),
                "feature_count": len(vectorizer.get_feature_names_out()),
                "active_threshold": 0.61,
                "recommended_threshold": 0.58,
                "threshold_source": "manual",
                "calibration_method": "sigmoid",
            },
        },
        artifact_path,
    )

    monkeypatch.setattr(risk_model.settings, "RISK_MODEL_ENABLED", True)
    monkeypatch.setattr(risk_model.settings, "RISK_MODEL_ARTIFACT_PATH", str(artifact_path))
    risk_model.clear_risk_model_cache()
    out = compute_finding_risk(high_context, now=now)
    risk_model.clear_risk_model_cache()

    assert out["risk_factors_json"]["score_source"] == "ml"
    assert out["risk_factors_json"]["model"] is not None
    assert out["risk_factors_json"]["model"]["algorithm"] == "logistic_regression"
    assert out["risk_factors_json"]["model"]["active_threshold"] == 0.61
    assert out["risk_factors_json"]["model"]["predicted_positive"] is True
    assert out["risk_factors_json"]["scoring_signature"].startswith("v3:ml:")
    assert out["risk_score"] >= 50
