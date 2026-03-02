# ML Risk Scoring

This document defines what is required for SecPlat's finding risk scoring to become a real ML system instead of a pure heuristic.

## What "ML model" means here

The target is a supervised binary classifier:

- `incident_worthy` -> positive class (`1`)
- `benign` -> negative class (`0`)

The model predicts a probability that a finding deserves escalation. SecPlat maps that probability to:

- `risk_score` -> `0..100`
- `risk_level` -> `low | medium | high | critical`

The website and API contract stay unchanged. Only the scorer behind them changes.

## Necessary components

1. Stable target definition
- Use one target first: "Would an analyst treat this finding as incident-worthy?"
- Do not mix multiple targets like remediation time and analyst severity override into one label.

2. Label collection
- Manual analyst labels are the cleanest source of ground truth.
- Supported labels are stored in `finding_risk_labels`.
- API endpoints:
  - `GET /findings/{finding_id}/risk-labels`
  - `POST /findings/{finding_id}/risk-labels`
- The Findings UI now supports direct analyst labeling.

3. Shared feature extraction
- Both the heuristic scorer and the ML pipeline use the same derived features from `app/risk_features.py`.
- Current features include severity, confidence, criticality, environment, exposure, age, status, and derived combinations.

4. Dataset export
- Export labeled findings to JSONL with:

```powershell
python services/api/scripts/ml/export_finding_risk_dataset.py `
  --dsn "postgresql+psycopg://secplat:secplat@localhost:5433/secplat" `
  --output services/api/exports/finding-risk-dataset.jsonl
```

5. Readiness check
- Before training, measure whether the dataset is good enough:

```powershell
python services/api/scripts/ml/check_risk_model_readiness.py `
  --dsn "postgresql+psycopg://secplat:secplat@localhost:5433/secplat"
```

Minimum practical baseline:

- at least `100` total labels
- at least `25` positive labels
- at least `25` negative labels
- class balance not completely collapsed

Weak-supervision bootstrap is also available for baseline model bootstrapping:

- `POST /ai/risk-scoring/bootstrap-labels`

This derives:

- positive labels from incident-linked findings
- negative labels from non-production internal findings and resolved/accepted workflow states

These are useful for a first model, but analyst labels remain the higher-quality signal.

6. Baseline model training
- Train the first model with logistic regression:

```powershell
python services/api/scripts/ml/train_finding_risk_model.py `
  --dataset services/api/exports/finding-risk-dataset.jsonl `
  --output services/api/models/finding-risk-model.joblib
```

Artifact contents:

- `model`
- `vectorizer`
- `metadata`

Runtime control-plane endpoints:

- `GET /ai/risk-scoring/status`
- `GET /ai/risk-scoring/evaluation`
- `POST /ai/risk-scoring/threshold`
- `GET /ai/risk-scoring/snapshots`
- `POST /ai/risk-scoring/snapshots`
- `POST /ai/risk-scoring/train`

7. Safe inference rollout
- Enable runtime inference with:

```env
RISK_MODEL_ENABLED=true
RISK_MODEL_ARTIFACT_PATH=/app/models/finding-risk-model.joblib
```

- Rebuild the API image after placing the artifact under `services/api/models/`:

```powershell
docker compose up -d --build api
```

8. Fallback and explainability
- If the artifact is missing or invalid, SecPlat stays on heuristic scoring.
- `risk_factors_json` stores:
  - `score_source`
  - `heuristic_score`
  - model metadata
  - top linear feature contributors when ML is active
  - active threshold and predicted-positive decision when ML is active

9. Monitoring
- Track model accuracy offline before trusting it operationally.
- Keep a holdout dataset and compare ML predictions to analyst outcomes over time.
- Retrain only when label volume and drift justify it.

## What is implemented in this repo now

- Label table and startup migration:
  - `infra/postgres/migrations/015_finding_risk_labels.sql`
  - `services/api/app/db_migrate.py`
- Label API:
  - `services/api/app/routers/findings.py`
- Shared feature extraction:
  - `services/api/app/risk_features.py`
- Optional model loader/inference:
  - `services/api/app/risk_model.py`
- Training / evaluation / snapshot orchestration:
  - `services/api/app/risk_training.py`
- ML lifecycle router:
  - `services/api/app/routers/risk_ml.py`
- Heuristic + ML-compatible scorer:
  - `services/api/app/risk_scoring.py`
- Snapshot persistence:
  - `infra/postgres/migrations/016_risk_model_snapshots.sql`
- Readiness/export/train scripts:
  - `services/api/scripts/ml/check_risk_model_readiness.py`
  - `services/api/scripts/ml/export_finding_risk_dataset.py`
  - `services/api/scripts/ml/train_finding_risk_model.py`

## What still depends on real data

These cannot be automated honestly without analyst behavior:

1. Enough labels
- The model is only real after you have useful ground truth.

2. Label discipline
- Analysts need to apply labels consistently.

3. Evaluation decisions
- You still need to decide acceptable precision/recall before using ML scores operationally.

## Recommended workflow

1. Keep heuristic scoring live as the default.
2. Start applying manual labels to findings.
3. Run the readiness script weekly.
4. Export a dataset once you have enough balanced labels.
5. Train the baseline model.
6. Turn on `RISK_MODEL_ENABLED` in a controlled environment first.
7. Compare ML scores to heuristic scores before fully trusting the model.

## Evaluation surface

The website now includes a dedicated **ML Risk** page with:

- active-threshold tuning and promotion
- calibrated probability view with Brier score and reliability bins
- labeled-set confusion matrix
- precision / recall / F1 / AUC
- label-source breakdown
- threshold sweep for operating-point selection
- score-bucket comparison between training baseline and current findings
- drift signals (PSI + largest categorical share shifts)
- snapshot history with exportable JSON evaluations
- analyst review queue for uncertain unlabeled findings
