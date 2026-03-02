"""Bootstrap weak finding-risk labels from existing incidents and low-context dev findings."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sqlalchemy import create_engine

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.risk_training import bootstrap_risk_labels


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsn", required=True, help="SQLAlchemy-compatible Postgres DSN")
    parser.add_argument("--actor", default="system-ml-bootstrap")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    engine = create_engine(args.dsn, pool_pre_ping=True)
    with engine.begin() as conn:
        out = bootstrap_risk_labels(conn, actor=args.actor)
    print(json.dumps({"ok": True, **out}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
