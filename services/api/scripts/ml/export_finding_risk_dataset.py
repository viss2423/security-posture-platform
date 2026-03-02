"""Export labeled finding risk examples for ML training."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sqlalchemy import create_engine

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.risk_training import export_labeled_dataset_rows, write_dataset_jsonl


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsn", required=True, help="SQLAlchemy-compatible Postgres DSN")
    parser.add_argument("--output", required=True, help="Path to write JSONL dataset")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    engine = create_engine(args.dsn, pool_pre_ping=True)
    with engine.begin() as conn:
        records = export_labeled_dataset_rows(conn)
    out = write_dataset_jsonl(records, args.output)
    print(json.dumps({"ok": True, **out}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
