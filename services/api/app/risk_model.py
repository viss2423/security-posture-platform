"""Optional trainable ML model for contextual finding risk."""

from __future__ import annotations

import logging
import math
from functools import lru_cache
from pathlib import Path
from typing import Any

import joblib

from .risk_features import build_risk_feature_vector
from .settings import settings

logger = logging.getLogger("secplat")


def configured_risk_model_artifact_path() -> str | None:
    raw = str(settings.RISK_MODEL_ARTIFACT_PATH or "").strip()
    return raw or "/app/models/finding-risk-model.joblib"


def risk_model_enabled() -> bool:
    return bool(settings.RISK_MODEL_ENABLED and configured_risk_model_artifact_path())


def get_risk_model_signature() -> str | None:
    if not risk_model_enabled():
        return None
    artifact_path = configured_risk_model_artifact_path()
    if not artifact_path:
        return None
    candidate = Path(artifact_path)
    if not candidate.exists():
        return None
    stat = candidate.stat()
    return f"ml:{candidate.name}:{stat.st_mtime_ns}"


@lru_cache(maxsize=4)
def _load_risk_model_cached(artifact_path: str, mtime_ns: int) -> dict[str, Any]:
    artifact = joblib.load(artifact_path)
    if not isinstance(artifact, dict):
        raise ValueError("Risk model artifact must be a dict")
    for key in ("model", "vectorizer", "metadata"):
        if key not in artifact:
            raise ValueError(f"Risk model artifact missing key: {key}")
    return artifact


def clear_risk_model_cache() -> None:
    _load_risk_model_cached.cache_clear()


def load_risk_model() -> dict[str, Any] | None:
    signature = get_risk_model_signature()
    artifact_path = configured_risk_model_artifact_path()
    if not signature or not artifact_path:
        return None
    mtime_ns = int(signature.rsplit(":", 1)[-1])
    try:
        return _load_risk_model_cached(artifact_path, mtime_ns)
    except Exception as exc:
        logger.warning("risk_model_load_failed path=%s error=%s", artifact_path, exc)
        return None


def _safe_feature_names(vectorizer: Any) -> list[str]:
    if hasattr(vectorizer, "get_feature_names_out"):
        names = vectorizer.get_feature_names_out()
        return [str(name) for name in names]
    if hasattr(vectorizer, "feature_names_"):
        return [str(name) for name in vectorizer.feature_names_]
    return []


def _top_feature_contributors(
    artifact: dict[str, Any], matrix: Any
) -> dict[str, list[dict[str, float | str]]]:
    model = artifact.get("explain_model") or artifact["model"]
    if not hasattr(model, "coef_") or len(getattr(model, "coef_", [])) != 1:
        return {"positive": [], "negative": []}
    feature_names = _safe_feature_names(artifact["vectorizer"])
    if not feature_names:
        return {"positive": [], "negative": []}
    row = matrix[0]
    row_values = row.toarray()[0] if hasattr(row, "toarray") else row
    contributions = []
    for name, value, coefficient in zip(feature_names, row_values, model.coef_[0], strict=False):
        contribution = float(value) * float(coefficient)
        if contribution:
            contributions.append((name, contribution))
    positive = [
        {"feature": name, "contribution": round(value, 4)}
        for name, value in sorted(contributions, key=lambda item: item[1], reverse=True)
        if value > 0
    ][:5]
    negative = [
        {"feature": name, "contribution": round(value, 4)}
        for name, value in sorted(contributions, key=lambda item: item[1])
        if value < 0
    ][:5]
    return {"positive": positive, "negative": negative}


def predict_ml_risk(context: dict[str, Any], *, now: Any | None = None) -> dict[str, Any] | None:
    artifact = load_risk_model()
    artifact_path = configured_risk_model_artifact_path()
    if not artifact or not artifact_path:
        return None

    model = artifact["model"]
    vectorizer = artifact["vectorizer"]
    metadata = artifact.get("metadata") or {}
    features = build_risk_feature_vector(context, now=now)
    matrix = vectorizer.transform([features])

    probability = None
    if hasattr(model, "predict_proba"):
        classes = list(getattr(model, "classes_", []))
        positive_class = metadata.get("positive_class", 1)
        if positive_class in classes:
            positive_index = classes.index(positive_class)
        elif 1 in classes:
            positive_index = classes.index(1)
        else:
            positive_index = len(classes) - 1
        probability = float(model.predict_proba(matrix)[0][positive_index])
    elif hasattr(model, "decision_function"):
        decision = float(model.decision_function(matrix)[0])
        probability = 1.0 / (1.0 + math.exp(-decision))
    else:
        return None

    score = max(0, min(100, int(round(probability * 100))))
    active_threshold = float(
        metadata.get("active_threshold", metadata.get("recommended_threshold", 0.5))
    )
    return {
        "risk_score": score,
        "probability": probability,
        "score_source": "ml",
        "feature_vector": features,
        "top_contributors": _top_feature_contributors(artifact, matrix),
        "metadata": {
            "artifact_path": artifact_path,
            "artifact_signature": get_risk_model_signature(),
            "algorithm": metadata.get("algorithm", type(model).__name__),
            "base_algorithm": metadata.get("base_algorithm"),
            "calibration_method": metadata.get("calibration_method"),
            "trained_at": metadata.get("trained_at"),
            "target_name": metadata.get("target_name", "incident_worthy"),
            "dataset_size": metadata.get("dataset_size"),
            "feature_count": metadata.get("feature_count"),
            "train_auc": metadata.get("train_auc"),
            "test_auc": metadata.get("test_auc"),
            "active_threshold": round(active_threshold, 4),
            "recommended_threshold": metadata.get("recommended_threshold"),
            "threshold_source": metadata.get("threshold_source", "recommended"),
            "predicted_positive": bool(probability >= active_threshold),
        },
    }
