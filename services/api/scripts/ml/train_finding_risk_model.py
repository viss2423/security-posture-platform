"""Train a baseline logistic-regression model for finding risk scoring."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.risk_training import train_risk_model_from_records


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset", required=True, help="JSONL dataset from export_finding_risk_dataset.py"
    )
    parser.add_argument("--output", required=True, help="Path to write .joblib artifact")
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--random-state", type=int, default=42)
    return parser.parse_args()


def load_dataset(path: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            raw = line.strip()
            if not raw:
                continue
            records.append(json.loads(raw))
    return records


def main() -> int:
    args = parse_args()
    dataset_path = Path(args.dataset)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    records = load_dataset(dataset_path)
    try:
        out = train_risk_model_from_records(
            records,
            output_path=str(output_path),
            random_state=args.random_state,
            test_size=args.test_size,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    print(
        json.dumps(
            {
                "ok": True,
                "output": str(output_path),
                "metadata": {
                    **out["metadata"],
                    "dataset_path": str(dataset_path),
                },
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
