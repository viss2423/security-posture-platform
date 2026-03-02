"""Check whether finding risk data is sufficient to train an ML model."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sqlalchemy import create_engine

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.risk_training import get_risk_label_summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsn", required=True, help="SQLAlchemy-compatible Postgres DSN")
    parser.add_argument("--min-labels", type=int, default=100)
    parser.add_argument("--min-positive", type=int, default=25)
    parser.add_argument("--min-negative", type=int, default=25)
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON only")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    engine = create_engine(args.dsn, pool_pre_ping=True)
    with engine.begin() as conn:
        payload = get_risk_label_summary(
            conn,
            min_labels=args.min_labels,
            min_positive=args.min_positive,
            min_negative=args.min_negative,
        )
    payload["next_steps"] = [
        "Add analyst labels through POST /findings/{finding_id}/risk-labels until both classes are represented.",
        "Bootstrap weak labels from historical incident linkage if needed.",
        "Export a dataset with services/api/scripts/ml/export_finding_risk_dataset.py.",
        "Train a baseline artifact with services/api/scripts/ml/train_finding_risk_model.py.",
        "Set RISK_MODEL_ENABLED=true and restart the API.",
    ]

    if args.json:
        print(json.dumps(payload, indent=2))
        return 0

    print(json.dumps(payload, indent=2))
    if payload["status"] != "ready":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
