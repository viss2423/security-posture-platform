"""Training, status, and weak-supervision helpers for finding risk ML."""

from __future__ import annotations

import json
import math
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, roc_auc_score
from sklearn.model_selection import train_test_split
from sqlalchemy import text

from .risk_features import build_risk_feature_vector, extract_risk_primitives
from .risk_labels import POSITIVE_RISK_LABELS, label_to_target
from .risk_model import clear_risk_model_cache, get_risk_model_signature
from .settings import settings

DEFAULT_RISK_MODEL_ARTIFACT_PATH = "/app/models/finding-risk-model.joblib"
DEFAULT_BOOTSTRAP_ACTOR = "system-ml-bootstrap"
DEFAULT_DECISION_THRESHOLD = 0.5

READINESS_SQL = """
WITH label_counts AS (
  SELECT label, COUNT(*) AS count
  FROM finding_risk_labels
  GROUP BY label
),
source_counts AS (
  SELECT source, COUNT(*) AS count
  FROM finding_risk_labels
  GROUP BY source
)
SELECT
  (SELECT COUNT(*) FROM findings) AS total_findings,
  (SELECT COUNT(*) FROM incidents) AS total_incidents,
  (SELECT COUNT(*) FROM finding_risk_labels) AS total_labels,
  (SELECT COUNT(*) FROM finding_risk_labels WHERE label = 'incident_worthy') AS positive_labels,
  (SELECT COUNT(*) FROM finding_risk_labels WHERE label = 'benign') AS negative_labels,
  (SELECT COUNT(DISTINCT f.finding_id)
     FROM findings f
     JOIN assets a ON a.asset_id = f.asset_id
     JOIN incident_alerts ia ON ia.asset_key = a.asset_key
  ) AS incident_linked_findings,
  COALESCE((SELECT json_object_agg(label, count) FROM label_counts), '{}'::json) AS labels_by_name,
  COALESCE((SELECT json_object_agg(source, count) FROM source_counts), '{}'::json) AS labels_by_source
"""

LABELED_EXAMPLES_SQL = """
SELECT
  f.finding_id,
  f.finding_key,
  COALESCE(f.status, 'open') AS status,
  f.severity,
  f.confidence,
  f.source,
  f.first_seen,
  f.accepted_risk_reason,
  f.accepted_risk_expires_at,
  a.asset_id,
  a.asset_key,
  a.type,
  a.asset_type,
  a.environment,
  a.criticality,
  a.verified,
  a.is_active,
  a.tags,
  a.metadata,
  COALESCE(te.telemetry_events_24h, 0) AS telemetry_events_24h,
  COALESCE(te.ioc_hits_24h, 0) AS ioc_hits_24h,
  COALESCE(te.zeek_events_24h, 0) AS zeek_events_24h,
  COALESCE(te.cowrie_events_24h, 0) AS cowrie_events_24h,
  COALESCE(sa.suricata_high_alerts_24h, 0) AS suricata_high_alerts_24h,
  COALESCE(an.anomaly_score, 0) AS anomaly_score,
  lbl.label,
  lbl.source AS label_source,
  lbl.created_at AS label_created_at,
  lbl.created_by AS label_created_by,
  lbl.note AS label_note
FROM findings f
LEFT JOIN assets a ON a.asset_id = f.asset_id
LEFT JOIN LATERAL (
  SELECT
    COUNT(*) AS telemetry_events_24h,
    COUNT(*) FILTER (WHERE se.ti_match = TRUE) AS ioc_hits_24h,
    COUNT(*) FILTER (WHERE se.source = 'zeek') AS zeek_events_24h,
    COUNT(*) FILTER (WHERE se.source = 'cowrie') AS cowrie_events_24h
  FROM security_events se
  WHERE se.asset_key = a.asset_key
    AND se.event_time >= (NOW() - INTERVAL '24 hours')
) te ON TRUE
LEFT JOIN LATERAL (
  SELECT COUNT(*) AS suricata_high_alerts_24h
  FROM security_alerts sa
  WHERE sa.asset_key = a.asset_key
    AND sa.source = 'suricata'
    AND sa.severity IN ('critical', 'high')
    AND sa.last_seen_at >= (NOW() - INTERVAL '24 hours')
) sa ON TRUE
LEFT JOIN LATERAL (
  SELECT anomaly_score
  FROM asset_anomaly_scores an
  WHERE an.asset_key = a.asset_key
  ORDER BY an.computed_at DESC
  LIMIT 1
) an ON TRUE
JOIN LATERAL (
  SELECT label, source, created_at, created_by, note
  FROM finding_risk_labels frl
  WHERE frl.finding_id = f.finding_id
  ORDER BY
    CASE
      WHEN frl.source = 'analyst' THEN 0
      ELSE 1
    END,
    frl.created_at DESC,
    frl.id DESC
  LIMIT 1
) AS lbl ON TRUE
ORDER BY f.finding_id ASC
"""

CURRENT_FINDINGS_SQL = """
SELECT
  f.finding_id,
  f.finding_key,
  COALESCE(f.status, 'open') AS status,
  f.severity,
  f.confidence,
  f.source,
  f.first_seen,
  f.accepted_risk_reason,
  f.accepted_risk_expires_at,
  f.title,
  f.risk_score,
  f.risk_level,
  a.asset_id,
  a.asset_key,
  a.type,
  a.asset_type,
  a.environment,
  a.criticality,
  a.verified,
  a.is_active,
  a.tags,
  a.metadata,
  COALESCE(te.telemetry_events_24h, 0) AS telemetry_events_24h,
  COALESCE(te.ioc_hits_24h, 0) AS ioc_hits_24h,
  COALESCE(te.zeek_events_24h, 0) AS zeek_events_24h,
  COALESCE(te.cowrie_events_24h, 0) AS cowrie_events_24h,
  COALESCE(sa.suricata_high_alerts_24h, 0) AS suricata_high_alerts_24h,
  COALESCE(an.anomaly_score, 0) AS anomaly_score,
  lbl.label,
  lbl.source AS label_source,
  lbl.created_at AS label_created_at
FROM findings f
LEFT JOIN assets a ON a.asset_id = f.asset_id
LEFT JOIN LATERAL (
  SELECT
    COUNT(*) AS telemetry_events_24h,
    COUNT(*) FILTER (WHERE se.ti_match = TRUE) AS ioc_hits_24h,
    COUNT(*) FILTER (WHERE se.source = 'zeek') AS zeek_events_24h,
    COUNT(*) FILTER (WHERE se.source = 'cowrie') AS cowrie_events_24h
  FROM security_events se
  WHERE se.asset_key = a.asset_key
    AND se.event_time >= (NOW() - INTERVAL '24 hours')
) te ON TRUE
LEFT JOIN LATERAL (
  SELECT COUNT(*) AS suricata_high_alerts_24h
  FROM security_alerts sa
  WHERE sa.asset_key = a.asset_key
    AND sa.source = 'suricata'
    AND sa.severity IN ('critical', 'high')
    AND sa.last_seen_at >= (NOW() - INTERVAL '24 hours')
) sa ON TRUE
LEFT JOIN LATERAL (
  SELECT anomaly_score
  FROM asset_anomaly_scores an
  WHERE an.asset_key = a.asset_key
  ORDER BY an.computed_at DESC
  LIMIT 1
) an ON TRUE
LEFT JOIN LATERAL (
  SELECT label, source, created_at
  FROM finding_risk_labels frl
  WHERE frl.finding_id = f.finding_id
  ORDER BY
    CASE
      WHEN frl.source = 'analyst' THEN 0
      ELSE 1
    END,
    frl.created_at DESC,
    frl.id DESC
  LIMIT 1
) AS lbl ON TRUE
ORDER BY f.finding_id ASC
"""

SNAPSHOT_INSERT_SQL = """
INSERT INTO risk_model_snapshots (
  created_by,
  event_type,
  model_signature,
  artifact_path,
  threshold,
  recommended_threshold,
  dataset_size,
  positive_labels,
  negative_labels,
  accuracy,
  precision,
  recall,
  f1,
  auc,
  brier_score,
  test_auc,
  drift_psi,
  summary_json
)
VALUES (
  :created_by,
  :event_type,
  :model_signature,
  :artifact_path,
  :threshold,
  :recommended_threshold,
  :dataset_size,
  :positive_labels,
  :negative_labels,
  :accuracy,
  :precision,
  :recall,
  :f1,
  :auc,
  :brier_score,
  :test_auc,
  :drift_psi,
  CAST(:summary_json AS JSONB)
)
RETURNING id, created_at
"""

SNAPSHOT_LIST_SQL = """
SELECT
  id,
  created_at,
  created_by,
  event_type,
  model_signature,
  artifact_path,
  threshold,
  recommended_threshold,
  dataset_size,
  positive_labels,
  negative_labels,
  accuracy,
  precision,
  recall,
  f1,
  auc,
  brier_score,
  test_auc,
  drift_psi
FROM risk_model_snapshots
ORDER BY created_at DESC, id DESC
LIMIT :limit
"""

SNAPSHOT_DETAIL_SQL = """
SELECT
  id,
  created_at,
  created_by,
  event_type,
  model_signature,
  artifact_path,
  threshold,
  recommended_threshold,
  dataset_size,
  positive_labels,
  negative_labels,
  accuracy,
  precision,
  recall,
  f1,
  auc,
  brier_score,
  test_auc,
  drift_psi,
  summary_json
FROM risk_model_snapshots
WHERE id = :snapshot_id
"""


def risk_model_artifact_path() -> str:
    raw = str(settings.RISK_MODEL_ARTIFACT_PATH or "").strip()
    return raw or DEFAULT_RISK_MODEL_ARTIFACT_PATH


def _context_from_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "finding": {
            "finding_id": row.get("finding_id"),
            "finding_key": row.get("finding_key"),
            "status": row.get("status"),
            "severity": row.get("severity"),
            "confidence": row.get("confidence"),
            "source": row.get("source"),
            "first_seen": row.get("first_seen"),
            "accepted_risk_reason": row.get("accepted_risk_reason"),
            "accepted_risk_expires_at": row.get("accepted_risk_expires_at"),
            "telemetry_events_24h": row.get("telemetry_events_24h"),
            "ioc_hits_24h": row.get("ioc_hits_24h"),
            "suricata_high_alerts_24h": row.get("suricata_high_alerts_24h"),
            "zeek_events_24h": row.get("zeek_events_24h"),
            "cowrie_events_24h": row.get("cowrie_events_24h"),
            "anomaly_score": row.get("anomaly_score"),
        },
        "asset": {
            "asset_id": row.get("asset_id"),
            "asset_key": row.get("asset_key"),
            "type": row.get("type"),
            "asset_type": row.get("asset_type"),
            "environment": row.get("environment"),
            "criticality": row.get("criticality"),
            "verified": row.get("verified"),
            "is_active": row.get("is_active"),
            "tags": row.get("tags"),
            "metadata": row.get("metadata"),
            "telemetry_events_24h": row.get("telemetry_events_24h"),
            "ioc_hits_24h": row.get("ioc_hits_24h"),
            "suricata_high_alerts_24h": row.get("suricata_high_alerts_24h"),
            "zeek_events_24h": row.get("zeek_events_24h"),
            "cowrie_events_24h": row.get("cowrie_events_24h"),
            "anomaly_score": row.get("anomaly_score"),
        },
    }


def _clamp_threshold(value: Any, default: float = DEFAULT_DECISION_THRESHOLD) -> float:
    try:
        threshold = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.05, min(0.95, threshold))


def _enriched_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    payload = dict(metadata or {})
    recommended_threshold = _clamp_threshold(
        payload.get("recommended_threshold"),
        DEFAULT_DECISION_THRESHOLD,
    )
    active_threshold = _clamp_threshold(
        payload.get("active_threshold"),
        recommended_threshold,
    )
    payload["recommended_threshold"] = recommended_threshold
    payload["active_threshold"] = active_threshold
    payload["threshold_source"] = str(payload.get("threshold_source") or "recommended")
    return payload


def get_risk_label_summary(
    conn: Any,
    *,
    min_labels: int = 100,
    min_positive: int = 25,
    min_negative: int = 25,
) -> dict[str, Any]:
    row = conn.execute(text(READINESS_SQL)).mappings().first()
    if not row:
        return {
            "status": "not_ready",
            "summary": {
                "total_findings": 0,
                "total_incidents": 0,
                "incident_linked_findings": 0,
                "total_labels": 0,
                "positive_labels": 0,
                "negative_labels": 0,
                "positive_ratio": 0.0,
                "positive_label_names": sorted(POSITIVE_RISK_LABELS),
                "labels_by_name": {},
                "labels_by_source": {},
            },
            "checks": [],
        }

    total_labels = int(row["total_labels"] or 0)
    positive_labels = int(row["positive_labels"] or 0)
    negative_labels = int(row["negative_labels"] or 0)
    positive_ratio = round(positive_labels / total_labels, 4) if total_labels else 0.0
    checks = [
        {
            "name": "minimum_total_labels",
            "ok": total_labels >= min_labels,
            "current": total_labels,
            "required": min_labels,
        },
        {
            "name": "minimum_positive_labels",
            "ok": positive_labels >= min_positive,
            "current": positive_labels,
            "required": min_positive,
        },
        {
            "name": "minimum_negative_labels",
            "ok": negative_labels >= min_negative,
            "current": negative_labels,
            "required": min_negative,
        },
        {
            "name": "class_balance_reasonable",
            "ok": total_labels > 0 and 0.1 <= positive_ratio <= 0.9,
            "current": positive_ratio,
            "required": "between 0.1 and 0.9 positive ratio",
        },
    ]
    return {
        "status": "ready" if all(check["ok"] for check in checks) else "not_ready",
        "summary": {
            "total_findings": int(row["total_findings"] or 0),
            "total_incidents": int(row["total_incidents"] or 0),
            "incident_linked_findings": int(row["incident_linked_findings"] or 0),
            "total_labels": total_labels,
            "positive_labels": positive_labels,
            "negative_labels": negative_labels,
            "positive_ratio": positive_ratio,
            "positive_label_names": sorted(POSITIVE_RISK_LABELS),
            "labels_by_name": dict(row["labels_by_name"] or {}),
            "labels_by_source": dict(row["labels_by_source"] or {}),
        },
        "checks": checks,
    }


def bootstrap_risk_labels(conn: Any, *, actor: str = DEFAULT_BOOTSTRAP_ACTOR) -> dict[str, Any]:
    positive_rows = (
        conn.execute(
            text(
                """
            INSERT INTO finding_risk_labels (finding_id, label, source, note, created_by)
            SELECT DISTINCT
              f.finding_id,
              'incident_worthy',
              'incident_linked',
              'Bootstrapped from incident-linked asset correlation',
              :actor
            FROM findings f
            JOIN assets a ON a.asset_id = f.asset_id
            JOIN incident_alerts ia ON ia.asset_key = a.asset_key
            WHERE NOT EXISTS (
              SELECT 1
              FROM finding_risk_labels existing
              WHERE existing.finding_id = f.finding_id
                AND existing.source = 'analyst'
            )
              AND NOT EXISTS (
                SELECT 1
                FROM finding_risk_labels existing
                WHERE existing.finding_id = f.finding_id
                  AND existing.label = 'incident_worthy'
                  AND existing.source = 'incident_linked'
            )
            RETURNING finding_id
            """
            ),
            {"actor": actor},
        )
        .mappings()
        .all()
    )

    negative_rows = (
        conn.execute(
            text(
                """
            WITH incident_linked AS (
              SELECT DISTINCT f.finding_id
              FROM findings f
              JOIN assets a ON a.asset_id = f.asset_id
              JOIN incident_alerts ia ON ia.asset_key = a.asset_key
            )
            INSERT INTO finding_risk_labels (finding_id, label, source, note, created_by)
            SELECT
              f.finding_id,
              'benign',
              'imported',
              'Bootstrapped from non-incident-linked, non-production internal finding',
              :actor
            FROM findings f
            LEFT JOIN assets a ON a.asset_id = f.asset_id
            WHERE f.finding_id NOT IN (SELECT finding_id FROM incident_linked)
              AND COALESCE(a.environment, 'dev') NOT IN ('prod', 'production')
              AND COALESCE(a.verified, FALSE) = FALSE
              AND COALESCE(a.type, '') <> 'external_web'
              AND COALESCE(a.asset_type, '') NOT IN ('external', 'public', 'internet', 'edge', 'ingress')
              AND COALESCE(f.severity, 'medium') IN ('low', 'medium')
              AND NOT EXISTS (
                SELECT 1
                FROM finding_risk_labels existing
                WHERE existing.finding_id = f.finding_id
                  AND existing.source = 'analyst'
              )
              AND NOT EXISTS (
                SELECT 1
                FROM finding_risk_labels existing
                WHERE existing.finding_id = f.finding_id
                  AND existing.label = 'benign'
              )
            RETURNING finding_id
            """
            ),
            {"actor": actor},
        )
        .mappings()
        .all()
    )

    workflow_rows = (
        conn.execute(
            text(
                """
            WITH incident_linked AS (
              SELECT DISTINCT f.finding_id
              FROM findings f
              JOIN assets a ON a.asset_id = f.asset_id
              JOIN incident_alerts ia ON ia.asset_key = a.asset_key
            )
            INSERT INTO finding_risk_labels (finding_id, label, source, note, created_by)
            SELECT
              f.finding_id,
              'benign',
              'accepted_risk',
              'Bootstrapped from accepted-risk/remediated workflow state',
              :actor
            FROM findings f
            WHERE COALESCE(f.status, 'open') IN ('accepted_risk', 'remediated')
              AND f.finding_id NOT IN (SELECT finding_id FROM incident_linked)
              AND NOT EXISTS (
                SELECT 1
                FROM finding_risk_labels existing
                WHERE existing.finding_id = f.finding_id
                  AND existing.source = 'analyst'
              )
              AND NOT EXISTS (
                SELECT 1
                FROM finding_risk_labels existing
                WHERE existing.finding_id = f.finding_id
                  AND existing.label = 'benign'
              )
            RETURNING finding_id
            """
            ),
            {"actor": actor},
        )
        .mappings()
        .all()
    )

    def _effective_label_counts() -> dict[str, int]:
        rows = (
            conn.execute(
                text(
                    """
                WITH ranked AS (
                  SELECT
                    frl.finding_id,
                    frl.label,
                    ROW_NUMBER() OVER (
                      PARTITION BY frl.finding_id
                      ORDER BY
                        CASE WHEN frl.source = 'analyst' THEN 0 ELSE 1 END,
                        frl.created_at DESC,
                        frl.id DESC
                    ) AS rn
                  FROM finding_risk_labels frl
                )
                SELECT label, COUNT(*) AS count
                FROM ranked
                WHERE rn = 1
                GROUP BY label
                """
                )
            )
            .mappings()
            .all()
        )
        counts: dict[str, int] = {}
        for row in rows:
            counts[str(row.get("label") or "")] = int(row.get("count") or 0)
        return counts

    balanced_positive = 0
    balanced_negative = 0
    effective_counts = _effective_label_counts()

    if effective_counts.get("incident_worthy", 0) <= 0:
        balanced_positive_rows = (
            conn.execute(
                text(
                    """
                WITH candidates AS (
                  SELECT
                    f.finding_id,
                    CASE COALESCE(f.severity, 'medium')
                      WHEN 'critical' THEN 4
                      WHEN 'high' THEN 3
                      WHEN 'medium' THEN 2
                      WHEN 'low' THEN 1
                      ELSE 0
                    END AS severity_rank,
                    COALESCE(f.risk_score, 0) AS risk_score,
                    CASE
                      WHEN COALESCE(a.environment, 'dev') IN ('prod', 'production') THEN 2
                      ELSE 1
                    END AS env_rank
                  FROM findings f
                  LEFT JOIN assets a ON a.asset_id = f.asset_id
                  WHERE NOT EXISTS (
                    SELECT 1
                    FROM finding_risk_labels existing
                    WHERE existing.finding_id = f.finding_id
                      AND existing.source = 'analyst'
                  )
                    AND NOT EXISTS (
                      SELECT 1
                      FROM finding_risk_labels existing
                      WHERE existing.finding_id = f.finding_id
                        AND existing.label = 'incident_worthy'
                    )
                )
                INSERT INTO finding_risk_labels (finding_id, label, source, note, created_by)
                SELECT
                  c.finding_id,
                  'incident_worthy',
                  'bootstrap_balanced',
                  'Bootstrap balancing label to keep training classes available',
                  :actor
                FROM candidates c
                ORDER BY c.severity_rank DESC, c.env_rank DESC, c.risk_score DESC, c.finding_id ASC
                LIMIT 5
                RETURNING finding_id
                """
                ),
                {"actor": actor},
            )
            .mappings()
            .all()
        )
        balanced_positive = len(balanced_positive_rows)
        effective_counts = _effective_label_counts()

    if effective_counts.get("benign", 0) <= 0:
        balanced_negative_rows = (
            conn.execute(
                text(
                    """
                WITH candidates AS (
                  SELECT
                    f.finding_id,
                    CASE COALESCE(f.severity, 'medium')
                      WHEN 'critical' THEN 4
                      WHEN 'high' THEN 3
                      WHEN 'medium' THEN 2
                      WHEN 'low' THEN 1
                      ELSE 0
                    END AS severity_rank,
                    COALESCE(f.risk_score, 0) AS risk_score,
                    CASE
                      WHEN COALESCE(a.environment, 'dev') IN ('prod', 'production') THEN 2
                      ELSE 1
                    END AS env_rank
                  FROM findings f
                  LEFT JOIN assets a ON a.asset_id = f.asset_id
                  WHERE NOT EXISTS (
                    SELECT 1
                    FROM finding_risk_labels existing
                    WHERE existing.finding_id = f.finding_id
                      AND existing.source = 'analyst'
                  )
                    AND NOT EXISTS (
                      SELECT 1
                      FROM finding_risk_labels existing
                      WHERE existing.finding_id = f.finding_id
                        AND existing.label = 'benign'
                    )
                )
                INSERT INTO finding_risk_labels (finding_id, label, source, note, created_by)
                SELECT
                  c.finding_id,
                  'benign',
                  'bootstrap_balanced',
                  'Bootstrap balancing label to keep training classes available',
                  :actor
                FROM candidates c
                ORDER BY c.severity_rank ASC, c.env_rank ASC, c.risk_score ASC, c.finding_id ASC
                LIMIT 5
                RETURNING finding_id
                """
                ),
                {"actor": actor},
            )
            .mappings()
            .all()
        )
        balanced_negative = len(balanced_negative_rows)

    return {
        "inserted_positive": len(positive_rows) + balanced_positive,
        "inserted_negative": len(negative_rows) + len(workflow_rows) + balanced_negative,
        "inserted_total": len(positive_rows)
        + len(negative_rows)
        + len(workflow_rows)
        + balanced_positive
        + balanced_negative,
        "inserted_balanced_positive": balanced_positive,
        "inserted_balanced_negative": balanced_negative,
        "summary": get_risk_label_summary(conn)["summary"],
    }


def export_labeled_dataset_rows(conn: Any) -> list[dict[str, Any]]:
    rows = conn.execute(text(LABELED_EXAMPLES_SQL)).mappings().all()
    output: list[dict[str, Any]] = []
    exported_at = datetime.now(UTC).isoformat()
    for row in rows:
        row_dict = dict(row)
        context = _context_from_row(row_dict)
        output.append(
            {
                "exported_at": exported_at,
                "finding_id": int(row_dict["finding_id"]),
                "finding_key": row_dict.get("finding_key"),
                "asset_key": row_dict.get("asset_key"),
                "label": row_dict["label"],
                "target": label_to_target(str(row_dict["label"])),
                "label_source": row_dict.get("label_source"),
                "label_created_at": (
                    row_dict["label_created_at"].isoformat()
                    if hasattr(row_dict.get("label_created_at"), "isoformat")
                    else row_dict.get("label_created_at")
                ),
                "label_created_by": row_dict.get("label_created_by"),
                "label_note": row_dict.get("label_note"),
                "features": build_risk_feature_vector(context),
                "context": {
                    "severity": row_dict.get("severity"),
                    "confidence": row_dict.get("confidence"),
                    "status": row_dict.get("status"),
                    "source": row_dict.get("source"),
                    "environment": row_dict.get("environment"),
                    "criticality": row_dict.get("criticality"),
                },
            }
        )
    return output


def _safe_auc(y_true: list[int], y_score: list[float]) -> float | None:
    if len(set(y_true)) < 2:
        return None
    return float(roc_auc_score(y_true, y_score))


def _safe_brier(y_true: list[int], y_score: list[float]) -> float | None:
    if not y_true or len(y_true) != len(y_score):
        return None
    return float(brier_score_loss(y_true, y_score))


def _threshold_metrics(
    y_true: list[int], probabilities: list[float], threshold: float
) -> dict[str, Any]:
    threshold = _clamp_threshold(threshold)
    predictions = [1 if probability >= threshold else 0 for probability in probabilities]
    tp = sum(
        1
        for actual, predicted in zip(y_true, predictions, strict=False)
        if actual == 1 and predicted == 1
    )
    tn = sum(
        1
        for actual, predicted in zip(y_true, predictions, strict=False)
        if actual == 0 and predicted == 0
    )
    fp = sum(
        1
        for actual, predicted in zip(y_true, predictions, strict=False)
        if actual == 0 and predicted == 1
    )
    fn = sum(
        1
        for actual, predicted in zip(y_true, predictions, strict=False)
        if actual == 1 and predicted == 0
    )
    precision = round(tp / (tp + fp), 4) if (tp + fp) else None
    recall = round(tp / (tp + fn), 4) if (tp + fn) else None
    f1 = (
        round(2 * precision * recall / (precision + recall), 4)
        if precision is not None and recall is not None and (precision + recall)
        else None
    )
    accuracy = round((tp + tn) / len(y_true), 4) if y_true else None
    return {
        "threshold": round(threshold, 4),
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "positive_predictions": int(sum(predictions)),
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }


def _build_threshold_candidates(probabilities: list[float]) -> list[float]:
    fixed = [
        round(value, 2)
        for value in [
            0.1,
            0.15,
            0.2,
            0.25,
            0.3,
            0.35,
            0.4,
            0.45,
            0.5,
            0.55,
            0.6,
            0.65,
            0.7,
            0.75,
            0.8,
            0.85,
            0.9,
        ]
    ]
    dynamic = [round(float(probability), 4) for probability in probabilities]
    merged = sorted({_clamp_threshold(value) for value in fixed + dynamic})
    return [value for value in merged if 0.05 <= value <= 0.95]


def _threshold_sweep(y_true: list[int], probabilities: list[float]) -> list[dict[str, Any]]:
    return [
        _threshold_metrics(y_true, probabilities, threshold)
        for threshold in _build_threshold_candidates(probabilities)
    ]


def _recommended_threshold(
    y_true: list[int], probabilities: list[float]
) -> tuple[float, list[dict[str, Any]]]:
    sweep = _threshold_sweep(y_true, probabilities)
    if not sweep:
        return (DEFAULT_DECISION_THRESHOLD, [])
    best = max(
        sweep,
        key=lambda item: (
            item["f1"] if item["f1"] is not None else -1.0,
            item["recall"] if item["recall"] is not None else -1.0,
            item["precision"] if item["precision"] is not None else -1.0,
            -abs(float(item["threshold"]) - DEFAULT_DECISION_THRESHOLD),
        ),
    )
    return (float(best["threshold"]), sweep)


def _calibration_bins(
    y_true: list[int], probabilities: list[float], *, bins: int = 8
) -> list[dict[str, Any]]:
    if not y_true or not probabilities:
        return []
    bucket_size = 1.0 / bins
    grouped: list[list[tuple[int, float]]] = [[] for _ in range(bins)]
    for actual, probability in zip(y_true, probabilities, strict=False):
        bucket = min(bins - 1, max(0, int(float(probability) / bucket_size)))
        grouped[bucket].append((int(actual), float(probability)))
    output = []
    for index, rows in enumerate(grouped):
        lower = round(index * bucket_size, 4)
        upper = round((index + 1) * bucket_size, 4)
        if rows:
            observed = round(sum(actual for actual, _ in rows) / len(rows), 4)
            predicted = round(sum(probability for _, probability in rows) / len(rows), 4)
            count = len(rows)
        else:
            observed = None
            predicted = None
            count = 0
        output.append(
            {
                "bucket": f"{int(lower * 100)}-{int(upper * 100)}",
                "range_start": lower,
                "range_end": upper,
                "count": count,
                "observed_positive_rate": observed,
                "average_predicted_probability": predicted,
            }
        )
    return output


def _calibration_method_for_dataset(record_count: int, min_class_count: int) -> str:
    if record_count >= 200 and min_class_count >= 25:
        return "isotonic"
    return "sigmoid"


def _calibration_folds_for_targets(targets: list[int]) -> int:
    min_class = min(sum(targets), len(targets) - sum(targets))
    return max(2, min(5, int(min_class)))


def _load_artifact(path: str | None = None) -> dict[str, Any]:
    artifact_path = path or risk_model_artifact_path()
    artifact = joblib.load(artifact_path)
    if not isinstance(artifact, dict):
        raise ValueError("Risk model artifact must be a dict")
    artifact["metadata"] = _enriched_metadata(artifact.get("metadata"))
    return artifact


def _positive_class_index(artifact: dict[str, Any]) -> int:
    metadata = artifact.get("metadata") or {}
    model = artifact["model"]
    classes = list(getattr(model, "classes_", []))
    positive_class = metadata.get("positive_class", 1)
    if positive_class in classes:
        return classes.index(positive_class)
    if 1 in classes:
        return classes.index(1)
    return len(classes) - 1


def _predict_probabilities(
    artifact: dict[str, Any], feature_rows: list[dict[str, Any]]
) -> list[float]:
    if not feature_rows:
        return []
    model = artifact["model"]
    vectorizer = artifact["vectorizer"]
    matrix = vectorizer.transform(feature_rows)
    if hasattr(model, "predict_proba"):
        positive_index = _positive_class_index(artifact)
        values = model.predict_proba(matrix)[:, positive_index]
        return [float(value) for value in values]
    if hasattr(model, "decision_function"):
        scores = model.decision_function(matrix)
        return [1.0 / (1.0 + math.exp(-float(score))) for score in scores]
    raise ValueError("Model does not support probability prediction")


def _probability_bucket(probability: float) -> str:
    score = max(0, min(100, int(round(probability * 100))))
    if score < 20:
        return "0-19"
    if score < 40:
        return "20-39"
    if score < 60:
        return "40-59"
    if score < 80:
        return "60-79"
    return "80-100"


def _bucket_counts(probabilities: list[float]) -> dict[str, int]:
    counts = Counter(_probability_bucket(probability) for probability in probabilities)
    return {
        bucket: int(counts.get(bucket, 0))
        for bucket in ["0-19", "20-39", "40-59", "60-79", "80-100"]
    }


def _record_dimension_value(record: dict[str, Any], field: str) -> str:
    feature_value = (record.get("features") or {}).get(field)
    if feature_value not in (None, ""):
        return str(feature_value)
    return str((record.get("context") or {}).get(field) or "unknown")


def _context_distribution(records: list[dict[str, Any]], field: str) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for record in records:
        counts[_record_dimension_value(record, field)] += 1
    return dict(counts)


def _row_dimension_value(row: dict[str, Any], field: str) -> str:
    primitives = extract_risk_primitives(_context_from_row(row))
    return str(primitives.get(field) or "unknown")


def _row_distribution(rows: list[dict[str, Any]], field: str) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for row in rows:
        counts[_row_dimension_value(row, field)] += 1
    return dict(counts)


def _normalized_distribution(counts: dict[str, int]) -> dict[str, float]:
    total = float(sum(counts.values()) or 0)
    if total <= 0:
        return {}
    return {key: round(value / total, 4) for key, value in counts.items()}


def _psi(expected_counts: dict[str, int], actual_counts: dict[str, int]) -> float | None:
    expected_total = float(sum(expected_counts.values()) or 0)
    actual_total = float(sum(actual_counts.values()) or 0)
    if expected_total <= 0 or actual_total <= 0:
        return None
    epsilon = 1e-6
    psi = 0.0
    for key in sorted(set(expected_counts) | set(actual_counts)):
        expected_share = max(expected_counts.get(key, 0) / expected_total, epsilon)
        actual_share = max(actual_counts.get(key, 0) / actual_total, epsilon)
        psi += (actual_share - expected_share) * math.log(actual_share / expected_share)
    return round(float(psi), 4)


def _largest_distribution_shift(
    expected_counts: dict[str, int], actual_counts: dict[str, int]
) -> dict[str, Any] | None:
    expected_share = _normalized_distribution(expected_counts)
    actual_share = _normalized_distribution(actual_counts)
    if not expected_share and not actual_share:
        return None
    candidate = None
    for key in sorted(set(expected_share) | set(actual_share)):
        delta = abs(actual_share.get(key, 0.0) - expected_share.get(key, 0.0))
        if candidate is None or delta > candidate["delta"]:
            candidate = {
                "value": key,
                "delta": round(delta, 4),
                "training_share": round(expected_share.get(key, 0.0), 4),
                "current_share": round(actual_share.get(key, 0.0), 4),
            }
    return candidate


def train_risk_model_from_records(
    records: list[dict[str, Any]],
    *,
    output_path: str,
    random_state: int = 42,
    test_size: float = 0.25,
) -> dict[str, Any]:
    if len(records) < 10:
        raise ValueError("Need at least 10 labeled rows to train a baseline model.")
    features = [record["features"] for record in records]
    targets = [int(record["target"]) for record in records]
    if len(set(targets)) < 2:
        raise ValueError("Need both positive and negative labels to train a classifier.")
    positive_count = sum(targets)
    negative_count = len(targets) - positive_count
    if positive_count < 2 or negative_count < 2:
        raise ValueError("Need at least two examples in each class to split train/test data.")

    vectorizer = DictVectorizer(sparse=True)
    matrix = vectorizer.fit_transform(features)
    X_train, X_test, y_train, y_test = train_test_split(
        matrix,
        targets,
        test_size=test_size,
        random_state=random_state,
        stratify=targets,
    )
    calibration_method = _calibration_method_for_dataset(
        len(records),
        min(positive_count, negative_count),
    )
    eval_cv_folds = _calibration_folds_for_targets(list(y_train))
    eval_model = CalibratedClassifierCV(
        estimator=LogisticRegression(
            class_weight="balanced",
            max_iter=2000,
            random_state=random_state,
        ),
        method=calibration_method,
        cv=eval_cv_folds,
    )
    eval_model.fit(X_train, y_train)
    train_scores = [float(value) for value in eval_model.predict_proba(X_train)[:, 1]]
    test_scores = [float(value) for value in eval_model.predict_proba(X_test)[:, 1]]

    recommended_threshold, threshold_sweep = _recommended_threshold(list(y_test), list(test_scores))
    artifact_file = Path(output_path)
    previous_metadata = (
        load_artifact_metadata(str(artifact_file)) if artifact_file.exists() else None
    )
    active_threshold = recommended_threshold
    threshold_source = "recommended"
    if previous_metadata and previous_metadata.get("threshold_source") == "manual":
        active_threshold = _clamp_threshold(
            previous_metadata.get("active_threshold"),
            recommended_threshold,
        )
        threshold_source = "manual"

    train_metrics_at_half = _threshold_metrics(
        list(y_train), train_scores, DEFAULT_DECISION_THRESHOLD
    )
    test_metrics_at_half = _threshold_metrics(list(y_test), test_scores, DEFAULT_DECISION_THRESHOLD)
    train_metrics_at_active = _threshold_metrics(list(y_train), train_scores, active_threshold)
    test_metrics_at_active = _threshold_metrics(list(y_test), test_scores, active_threshold)
    all_label_counts = dict(Counter(str(record["label"]) for record in records))
    all_source_counts = dict(
        Counter(str(record.get("label_source") or "unknown") for record in records)
    )

    final_cv_folds = _calibration_folds_for_targets(targets)
    final_model = CalibratedClassifierCV(
        estimator=LogisticRegression(
            class_weight="balanced",
            max_iter=2000,
            random_state=random_state,
        ),
        method=calibration_method,
        cv=final_cv_folds,
    )
    final_model.fit(matrix, targets)
    explain_model = LogisticRegression(
        class_weight="balanced",
        max_iter=2000,
        random_state=random_state,
    )
    explain_model.fit(matrix, targets)
    all_probabilities = _predict_probabilities(
        {"model": final_model, "vectorizer": vectorizer, "metadata": {"positive_class": 1}},
        features,
    )

    metadata = {
        "algorithm": "logistic_regression",
        "base_algorithm": "logistic_regression",
        "calibration_method": calibration_method,
        "calibration_folds": final_cv_folds,
        "target_name": "incident_worthy",
        "positive_class": 1,
        "trained_at": datetime.now(UTC).isoformat(),
        "dataset_size": len(records),
        "feature_count": len(vectorizer.get_feature_names_out()),
        "train_auc": _safe_auc(list(y_train), list(train_scores)),
        "test_auc": _safe_auc(list(y_test), list(test_scores)),
        "train_accuracy": train_metrics_at_half["accuracy"],
        "test_accuracy": test_metrics_at_half["accuracy"],
        "train_accuracy_active_threshold": train_metrics_at_active["accuracy"],
        "test_accuracy_active_threshold": test_metrics_at_active["accuracy"],
        "brier_score": _safe_brier(list(y_test), list(test_scores)),
        "class_balance": {
            "positive": int(positive_count),
            "negative": int(negative_count),
        },
        "label_counts": all_label_counts,
        "label_source_counts": all_source_counts,
        "recommended_threshold": round(recommended_threshold, 4),
        "active_threshold": round(active_threshold, 4),
        "threshold_source": threshold_source,
        "threshold_metric": "f1",
        "threshold_sweep": threshold_sweep,
        "training_prediction_buckets": _bucket_counts(all_probabilities),
        "training_feature_distributions": {
            "severity": _context_distribution(records, "severity"),
            "source": _context_distribution(records, "source"),
            "environment": _context_distribution(records, "environment"),
            "criticality": _context_distribution(records, "criticality"),
        },
    }

    artifact = {
        "model": final_model,
        "explain_model": explain_model,
        "vectorizer": vectorizer,
        "metadata": metadata,
    }
    artifact_file.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, artifact_file)
    clear_risk_model_cache()
    return {
        "artifact_path": str(artifact_file),
        "artifact_exists": artifact_file.exists(),
        "metadata": _enriched_metadata(metadata),
    }


def train_risk_model_from_db(
    conn: Any,
    *,
    output_path: str | None = None,
    random_state: int = 42,
    test_size: float = 0.25,
) -> dict[str, Any]:
    records = export_labeled_dataset_rows(conn)
    result = train_risk_model_from_records(
        records,
        output_path=output_path or risk_model_artifact_path(),
        random_state=random_state,
        test_size=test_size,
    )
    result["training_rows"] = len(records)
    return result


def load_artifact_metadata(path: str | None = None) -> dict[str, Any] | None:
    artifact_path = path or risk_model_artifact_path()
    file_path = Path(artifact_path)
    if not file_path.exists():
        return None
    artifact = _load_artifact(str(file_path))
    if not isinstance(artifact, dict):
        return None
    metadata = artifact.get("metadata")
    return _enriched_metadata(metadata) if isinstance(metadata, dict) else None


def get_risk_model_status(conn: Any) -> dict[str, Any]:
    artifact_path = risk_model_artifact_path()
    artifact_exists = Path(artifact_path).exists()
    metadata = load_artifact_metadata(artifact_path) if artifact_exists else None
    summary = get_risk_label_summary(conn)
    enabled = bool(settings.RISK_MODEL_ENABLED)
    signature = get_risk_model_signature()
    latest_snapshot = next(iter(list_risk_model_snapshots(conn, limit=1)), None)
    return {
        "enabled": enabled,
        "artifact_path": artifact_path,
        "artifact_exists": artifact_exists,
        "artifact_loaded": bool(enabled and artifact_exists and signature),
        "current_scoring_mode": "ml" if enabled and artifact_exists and signature else "heuristic",
        "scoring_signature": signature or "heuristic",
        "readiness": summary,
        "model_metadata": metadata,
        "latest_snapshot": latest_snapshot,
    }


def set_risk_model_threshold(
    *,
    threshold: float,
    actor: str | None = None,
    source: str = "manual",
    path: str | None = None,
) -> dict[str, Any]:
    artifact_path = path or risk_model_artifact_path()
    artifact_file = Path(artifact_path)
    if not artifact_file.exists():
        raise ValueError("Risk model artifact not found")
    artifact = _load_artifact(str(artifact_file))
    metadata = _enriched_metadata(artifact.get("metadata"))
    metadata["active_threshold"] = _clamp_threshold(threshold, metadata["active_threshold"])
    metadata["threshold_source"] = source or "manual"
    metadata["threshold_updated_by"] = actor
    metadata["threshold_updated_at"] = datetime.now(UTC).isoformat()
    artifact["metadata"] = metadata
    joblib.dump(artifact, artifact_file)
    clear_risk_model_cache()
    return metadata


def list_risk_model_snapshots(conn: Any, *, limit: int = 20) -> list[dict[str, Any]]:
    rows = (
        conn.execute(
            text(SNAPSHOT_LIST_SQL),
            {"limit": max(1, min(int(limit), 100))},
        )
        .mappings()
        .all()
    )
    return [
        {
            **dict(row),
            "created_at": row["created_at"].isoformat()
            if hasattr(row.get("created_at"), "isoformat")
            else row.get("created_at"),
        }
        for row in rows
    ]


def get_risk_model_snapshot(conn: Any, snapshot_id: int) -> dict[str, Any] | None:
    row = (
        conn.execute(
            text(SNAPSHOT_DETAIL_SQL),
            {"snapshot_id": snapshot_id},
        )
        .mappings()
        .first()
    )
    if not row:
        return None
    payload = dict(row)
    if hasattr(payload.get("created_at"), "isoformat"):
        payload["created_at"] = payload["created_at"].isoformat()
    return payload


def evaluate_risk_model(
    conn: Any,
    *,
    threshold: float | None = None,
    review_limit: int = 12,
) -> dict[str, Any]:
    artifact_path = risk_model_artifact_path()
    artifact_file = Path(artifact_path)
    if not artifact_file.exists():
        raise ValueError("Risk model artifact not found")
    artifact = _load_artifact(str(artifact_file))
    metadata = _enriched_metadata(artifact.get("metadata"))
    active_threshold = _clamp_threshold(
        threshold,
        metadata.get(
            "active_threshold", metadata.get("recommended_threshold", DEFAULT_DECISION_THRESHOLD)
        ),
    )

    labeled_records = export_labeled_dataset_rows(conn)
    labeled_features = [record["features"] for record in labeled_records]
    labeled_targets = [int(record["target"]) for record in labeled_records]
    labeled_probabilities = _predict_probabilities(artifact, labeled_features)
    labeled_metrics = _threshold_metrics(labeled_targets, labeled_probabilities, active_threshold)
    threshold_sweep = _threshold_sweep(labeled_targets, labeled_probabilities)
    auc = _safe_auc(labeled_targets, labeled_probabilities)
    brier = _safe_brier(labeled_targets, labeled_probabilities)
    calibration_bins = _calibration_bins(labeled_targets, labeled_probabilities)

    current_rows = [dict(row) for row in conn.execute(text(CURRENT_FINDINGS_SQL)).mappings().all()]
    current_features = [build_risk_feature_vector(_context_from_row(row)) for row in current_rows]
    current_probabilities = _predict_probabilities(artifact, current_features)
    current_prediction_buckets = _bucket_counts(current_probabilities)
    current_average_probability = (
        round(sum(current_probabilities) / len(current_probabilities), 4)
        if current_probabilities
        else None
    )

    training_prediction_buckets = metadata.get("training_prediction_buckets") or {}
    if not training_prediction_buckets and labeled_probabilities:
        training_prediction_buckets = _bucket_counts(labeled_probabilities)

    training_feature_distributions = metadata.get("training_feature_distributions") or {}
    if not training_feature_distributions and labeled_records:
        training_feature_distributions = {
            "severity": _context_distribution(labeled_records, "severity"),
            "source": _context_distribution(labeled_records, "source"),
            "environment": _context_distribution(labeled_records, "environment"),
            "criticality": _context_distribution(labeled_records, "criticality"),
        }

    training_label_counts = metadata.get("label_counts") or {}
    if not training_label_counts and labeled_records:
        training_label_counts = dict(Counter(str(record["label"]) for record in labeled_records))

    training_label_source_counts = metadata.get("label_source_counts") or {}
    if not training_label_source_counts and labeled_records:
        training_label_source_counts = dict(
            Counter(str(record.get("label_source") or "unknown") for record in labeled_records)
        )

    review_items = []
    max_uncertainty_distance = max(active_threshold, 1 - active_threshold, 1e-6)
    for row, probability in zip(current_rows, current_probabilities, strict=False):
        if row.get("label"):
            continue
        distance_from_threshold = abs(float(probability) - active_threshold)
        review_items.append(
            {
                "finding_id": int(row["finding_id"]),
                "finding_key": row.get("finding_key"),
                "title": row.get("title"),
                "asset_key": row.get("asset_key"),
                "severity": row.get("severity"),
                "source": row.get("source"),
                "predicted_probability": round(float(probability), 4),
                "predicted_score": int(round(float(probability) * 100)),
                "uncertainty": round(
                    max(0.0, 1.0 - (distance_from_threshold / max_uncertainty_distance)),
                    4,
                ),
                "distance_from_threshold": round(distance_from_threshold, 4),
                "current_risk_score": row.get("risk_score"),
                "current_risk_level": row.get("risk_level"),
            }
        )
    review_queue = sorted(
        review_items,
        key=lambda item: (
            -item["uncertainty"],
            -item["predicted_score"],
            str(item["severity"] or ""),
        ),
    )[:review_limit]
    drift = {
        "score_distribution_psi": _psi(
            {str(key): int(value) for key, value in training_prediction_buckets.items()},
            current_prediction_buckets,
        ),
        "feature_shifts": {
            "severity": _largest_distribution_shift(
                {
                    str(key): int(value)
                    for key, value in (training_feature_distributions.get("severity") or {}).items()
                },
                _row_distribution(current_rows, "severity"),
            ),
            "source": _largest_distribution_shift(
                {
                    str(key): int(value)
                    for key, value in (training_feature_distributions.get("source") or {}).items()
                },
                _row_distribution(current_rows, "source"),
            ),
            "environment": _largest_distribution_shift(
                {
                    str(key): int(value)
                    for key, value in (
                        training_feature_distributions.get("environment") or {}
                    ).items()
                },
                _row_distribution(current_rows, "environment"),
            ),
            "criticality": _largest_distribution_shift(
                {
                    str(key): int(value)
                    for key, value in (
                        training_feature_distributions.get("criticality") or {}
                    ).items()
                },
                _row_distribution(current_rows, "criticality"),
            ),
        },
    }

    signals = []
    psi = drift["score_distribution_psi"]
    if psi is not None:
        signals.append(
            {
                "metric": "score_distribution_psi",
                "value": psi,
                "severity": "high" if psi >= 0.25 else "medium" if psi >= 0.1 else "low",
                "detail": "Population Stability Index on score buckets",
            }
        )
    for feature_name, payload in drift["feature_shifts"].items():
        if not payload:
            continue
        delta = float(payload["delta"])
        signals.append(
            {
                "metric": f"{feature_name}_share_shift",
                "value": delta,
                "severity": "high" if delta >= 0.2 else "medium" if delta >= 0.1 else "low",
                "detail": f"Largest share shift for {feature_name}: {payload['value']}",
            }
        )
    drift["signals"] = signals

    return {
        "artifact_path": artifact_path,
        "trained_at": metadata.get("trained_at"),
        "threshold": active_threshold,
        "recommended_threshold": metadata.get("recommended_threshold"),
        "threshold_source": metadata.get("threshold_source", "recommended"),
        "labeled_evaluation": {
            "rows": len(labeled_records),
            "accuracy": labeled_metrics["accuracy"],
            "precision": labeled_metrics["precision"],
            "recall": labeled_metrics["recall"],
            "f1": labeled_metrics["f1"],
            "auc": round(float(auc), 4) if auc is not None else None,
            "brier_score": round(float(brier), 4) if brier is not None else None,
            "confusion_matrix": labeled_metrics["confusion_matrix"],
            "label_counts": dict(Counter(record["label"] for record in labeled_records)),
            "label_source_counts": dict(
                Counter(str(record.get("label_source") or "unknown") for record in labeled_records)
            ),
            "prediction_buckets": _bucket_counts(labeled_probabilities),
        },
        "threshold_sweep": threshold_sweep,
        "calibration": {
            "method": metadata.get("calibration_method"),
            "brier_score": round(float(brier), 4) if brier is not None else None,
            "bins": calibration_bins,
        },
        "training_baseline": {
            "dataset_size": metadata.get("dataset_size"),
            "label_counts": training_label_counts,
            "label_source_counts": training_label_source_counts,
            "prediction_buckets": training_prediction_buckets,
            "feature_distributions": training_feature_distributions,
            "test_auc": metadata.get("test_auc"),
            "test_accuracy": metadata.get("test_accuracy"),
            "test_accuracy_active_threshold": metadata.get("test_accuracy_active_threshold"),
            "recommended_threshold": metadata.get("recommended_threshold"),
            "active_threshold": metadata.get("active_threshold"),
            "threshold_source": metadata.get("threshold_source"),
            "calibration_method": metadata.get("calibration_method"),
            "brier_score": metadata.get("brier_score"),
        },
        "current_population": {
            "total_findings": len(current_rows),
            "unlabeled_findings": sum(1 for row in current_rows if not row.get("label")),
            "predicted_positive_count": sum(
                1 for probability in current_probabilities if probability >= active_threshold
            ),
            "average_probability": current_average_probability,
            "prediction_buckets": current_prediction_buckets,
            "feature_distributions": {
                "severity": _row_distribution(current_rows, "severity"),
                "source": _row_distribution(current_rows, "source"),
                "environment": _row_distribution(current_rows, "environment"),
                "criticality": _row_distribution(current_rows, "criticality"),
            },
        },
        "drift": drift,
        "review_queue": review_queue,
    }


def create_risk_model_snapshot(
    conn: Any,
    *,
    actor: str | None = None,
    event_type: str = "manual",
    threshold: float | None = None,
) -> dict[str, Any]:
    evaluation = evaluate_risk_model(conn, threshold=threshold)
    metadata = load_artifact_metadata(evaluation["artifact_path"]) or {}
    row = (
        conn.execute(
            text(SNAPSHOT_INSERT_SQL),
            {
                "created_by": actor,
                "event_type": event_type,
                "model_signature": get_risk_model_signature(),
                "artifact_path": evaluation["artifact_path"],
                "threshold": evaluation["threshold"],
                "recommended_threshold": evaluation.get("recommended_threshold"),
                "dataset_size": evaluation["labeled_evaluation"]["rows"],
                "positive_labels": evaluation["labeled_evaluation"]["label_counts"].get(
                    "incident_worthy", 0
                ),
                "negative_labels": evaluation["labeled_evaluation"]["label_counts"].get(
                    "benign", 0
                ),
                "accuracy": evaluation["labeled_evaluation"].get("accuracy"),
                "precision": evaluation["labeled_evaluation"].get("precision"),
                "recall": evaluation["labeled_evaluation"].get("recall"),
                "f1": evaluation["labeled_evaluation"].get("f1"),
                "auc": evaluation["labeled_evaluation"].get("auc"),
                "brier_score": evaluation["labeled_evaluation"].get("brier_score"),
                "test_auc": metadata.get("test_auc"),
                "drift_psi": evaluation["drift"].get("score_distribution_psi"),
                "summary_json": json.dumps(evaluation),
            },
        )
        .mappings()
        .first()
    )
    if not row:
        raise ValueError("Failed to persist risk model snapshot")
    return {
        "snapshot_id": int(row["id"]),
        "created_at": row["created_at"].isoformat()
        if hasattr(row.get("created_at"), "isoformat")
        else row.get("created_at"),
        "event_type": event_type,
        "threshold": evaluation["threshold"],
        "recommended_threshold": evaluation.get("recommended_threshold"),
        "evaluation": evaluation,
    }


def write_dataset_jsonl(records: list[dict[str, Any]], output_path: str) -> dict[str, Any]:
    file_path = Path(output_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with file_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")
    return {"output": str(file_path), "exported_rows": len(records)}
