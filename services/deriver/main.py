"""
secplat-deriver (Phase 2.1): Read secplat-events, derive posture per asset, write to secplat-asset-status.
Replaces build_asset_status.sh. Runs in a loop (e.g. every 60s).
"""

import json
import logging
import os
import socket
import sys
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

import httpx
from simple_metrics import SimpleMetrics, start_metrics_server

_STANDARD_ATTRS = {
    "name",
    "msg",
    "args",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "exc_info",
    "exc_text",
    "stack_info",
    "lineno",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
}


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str) -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
            "service": self.service,
            "pid": os.getpid(),
        }
        for key, value in record.__dict__.items():
            if key in _STANDARD_ATTRS or key in payload:
                continue
            try:
                json.dumps({key: value})
                payload[key] = value
            except Exception:
                payload[key] = str(value)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=True)


def configure_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(service="secplat-deriver"))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)


configure_logging()
logger = logging.getLogger("deriver")
_otel_configured = False
_otel_enabled = False
_tracer = None
_propagator = None
metrics = SimpleMetrics("secplat-deriver")

OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "http://localhost:9200").rstrip("/")
ASSETS_INDEX = os.environ.get("ASSETS_INDEX", "secplat-assets")
EVENTS_INDEX = os.environ.get("EVENTS_INDEX", "secplat-events")
STATUS_INDEX = os.environ.get("STATUS_INDEX", "secplat-asset-status")
STALE_THRESHOLD_SECONDS = int(os.environ.get("STALE_THRESHOLD_SECONDS", "300"))
DERIVER_INTERVAL_SECONDS = int(os.environ.get("DERIVER_INTERVAL_SECONDS", "60"))
DERIVER_METRICS_PORT = int(os.getenv("DERIVER_METRICS_PORT", "9104"))


class _NoopSpan:
    def set_attribute(self, _key: str, _value: object) -> None:
        return None

    def record_exception(self, _exc: Exception) -> None:
        return None


def configure_otel() -> bool:
    global _otel_configured, _otel_enabled, _tracer, _propagator
    if _otel_configured:
        return _otel_enabled
    _otel_configured = True
    if str(os.getenv("OTEL_ENABLED", "false")).strip().lower() != "true":
        return False
    endpoint = str(os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "") or "").strip()
    if not endpoint:
        return False
    try:
        from opentelemetry import propagate, trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except Exception:
        logger.debug("deriver otel dependencies unavailable", exc_info=True)
        return False
    try:
        resource = Resource.create(
            {
                "service.name": "secplat-deriver",
                "service.instance.id": f"{socket.gethostname()}:{os.getpid()}",
                "deployment.environment": str(os.getenv("ENV", "dev") or "dev"),
            }
        )
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=endpoint)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer("secplat-deriver")
        _propagator = propagate
        _otel_enabled = True
        return True
    except Exception:
        logger.debug("deriver otel initialization failed", exc_info=True)
        _tracer = None
        _propagator = None
        _otel_enabled = False
        return False


def inject_context(carrier: dict[str, object]) -> dict[str, object]:
    if not carrier or not _otel_enabled or _propagator is None:
        return carrier
    try:
        _propagator.inject(carrier=carrier)
    except Exception:
        logger.debug("deriver otel inject failed", exc_info=True)
    return carrier


@contextmanager
def start_span(name: str, *, attributes: dict[str, object] | None = None):
    if not _otel_enabled or _tracer is None:
        yield _NoopSpan()
        return
    with _tracer.start_as_current_span(name) as span:
        for key, value in (attributes or {}).items():
            if value is not None:
                span.set_attribute(str(key), value)
        yield span


def _get(path: str, **kwargs: Any) -> dict:
    url = f"{OPENSEARCH_URL}{path}"
    headers = dict(kwargs.pop("headers", {}) or {})
    inject_context(headers)
    with httpx.Client(timeout=30.0) as client:
        with start_span(
            "http.client.request",
            attributes={"http.request.method": "GET", "url.full": url},
        ):
            r = client.get(url, headers=headers, **kwargs)
        r.raise_for_status()
        return r.json()


def _put(path: str, json: dict) -> dict:
    url = f"{OPENSEARCH_URL}{path}"
    headers: dict[str, object] = {}
    inject_context(headers)
    with httpx.Client(timeout=30.0) as client:
        with start_span(
            "http.client.request",
            attributes={"http.request.method": "PUT", "url.full": url},
        ):
            r = client.put(url, json=json, headers=headers)
        r.raise_for_status()
        return r.json()


def _post(path: str, json: dict | None = None) -> dict:
    url = f"{OPENSEARCH_URL}{path}"
    headers: dict[str, object] = {}
    inject_context(headers)
    with httpx.Client(timeout=30.0) as client:
        with start_span(
            "http.client.request",
            attributes={"http.request.method": "POST", "url.full": url},
        ):
            r = client.post(url, json=json or {}, headers=headers)
        r.raise_for_status()
        return r.json()


def _doc_id(asset_key: str, org_id: str | None = None) -> str:
    tenant = str(org_id or "").strip()
    if not tenant or tenant == "default":
        return asset_key
    return f"{tenant}::{asset_key}"


def ensure_status_index() -> None:
    try:
        _get(f"/{STATUS_INDEX}")
    except httpx.HTTPStatusError as e:
        if e.response.status_code != 404:
            raise
        logger.info("creating index %s", STATUS_INDEX)
        _put(
            f"/{STATUS_INDEX}",
            {
                "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "org_id": {"type": "keyword"},
                        "asset_key": {"type": "keyword"},
                        "name": {"type": "keyword"},
                        "type": {"type": "keyword"},
                        "environment": {"type": "keyword"},
                        "criticality": {"type": "integer"},
                        "owner": {"type": "keyword"},
                        "owner_team": {"type": "keyword"},
                        "status": {"type": "keyword"},
                        "status_num": {"type": "integer"},
                        "code": {"type": "integer"},
                        "latency_ms": {"type": "integer"},
                        "last_seen": {"type": "date"},
                        "source_event_timestamp": {"type": "date"},
                        "staleness_seconds": {"type": "integer"},
                        "posture_score": {"type": "integer"},
                        "posture_state": {"type": "keyword"},
                        "last_status_change": {"type": "date"},
                    }
                },
            },
        )


def fetch_assets() -> list[dict]:
    body = {"size": 1000, "query": {"match_all": {}}}
    data = _post(f"/{ASSETS_INDEX}/_search", json=body)
    hits = data.get("hits", {}).get("hits", [])
    return [h["_source"] for h in hits]


def fetch_latest_health_event(asset_key: str, org_id: str | None = None) -> dict | None:
    filters: list[dict[str, object]] = [{"term": {"level": "health"}}]
    tenant = str(org_id or "").strip()
    if tenant and tenant != "default":
        filters.append({"term": {"org_id.keyword": tenant}})
    body = {
        "size": 1,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "bool": {
                "filter": filters,
                "should": [
                    {"term": {"asset.keyword": asset_key}},
                    {"match": {"asset": asset_key}},
                    {"term": {"service.keyword": asset_key}},
                    {"match": {"service": asset_key}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    data = _post(f"/{EVENTS_INDEX}/_search", json=body)
    hits = data.get("hits", {}).get("hits", [])
    return hits[0]["_source"] if hits else None


def fetch_example_com_event() -> dict | None:
    body = {
        "size": 1,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "bool": {
                "filter": [
                    {"term": {"level": "health"}},
                    {"term": {"asset.keyword": "example-com"}},
                ]
            }
        },
    }
    data = _post(f"/{EVENTS_INDEX}/_search", json=body)
    hits = data.get("hits", {}).get("hits", [])
    return hits[0]["_source"] if hits else None


def get_prev_status(asset_key: str, org_id: str | None = None) -> tuple[str | None, str | None]:
    for candidate in (_doc_id(asset_key, org_id), asset_key):
        try:
            data = _get(f"/{STATUS_INDEX}/_doc/{candidate}")
            if data.get("found"):
                src = data.get("_source", {})
                return (
                    str(src.get("status_num")) if src.get("status_num") is not None else None,
                    src.get("last_status_change"),
                )
        except httpx.HTTPStatusError as e:
            if e.response.status_code != 404:
                raise
    return (None, None)


def iso_to_epoch(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return int(dt.timestamp())
    except Exception:
        return None


def run_derivation() -> None:
    now = datetime.now(UTC)
    now_iso = now.isoformat().replace("+00:00", "Z")
    now_epoch = int(now.timestamp())
    started = time.monotonic()

    with start_span(
        "deriver.run", attributes={"secplat.deriver.interval_seconds": DERIVER_INTERVAL_SECONDS}
    ):
        assets = fetch_assets()
        logger.info("deriving status for %d assets", len(assets))

        example_com_event = fetch_example_com_event()
        example_com_down_recent = False
        if example_com_event:
            st = example_com_event.get("status")
            ts = example_com_event.get("@timestamp")
            ep = iso_to_epoch(ts)
            if st == "down" and ep:
                if (now_epoch - ep) < STALE_THRESHOLD_SECONDS * 2:
                    example_com_down_recent = True

        for asset in assets:
            asset_key = asset.get("asset_key") or ""
            if not asset_key:
                continue
            org_id = str(asset.get("org_id") or "default").strip() or "default"
            name = asset.get("name") or ""
            atype = asset.get("type") or ""
            env = asset.get("environment") or "dev"
            crit = asset.get("criticality", 3)
            if isinstance(crit, str):
                try:
                    crit = int(crit)
                except ValueError:
                    crit = 3
            owner = asset.get("owner") or ""
            owner_team = asset.get("owner_team") or ""

            with start_span(
                "deriver.asset",
                attributes={
                    "secplat.asset.key": asset_key,
                    "secplat.asset.environment": env,
                    "secplat.tenant.id": org_id,
                },
            ):
                event = fetch_latest_health_event(asset_key, org_id)
                status = "unknown"
                status_num = -1
                code = None
                latency_ms = None
                last_seen = None
                event_ts = None
                last_seen_epoch = None

                if event:
                    raw_status = event.get("status", "unknown")
                    code = event.get("code")
                    latency_ms = event.get("latency_ms")
                    last_seen = event.get("@timestamp")
                    event_ts = last_seen
                    last_seen_epoch = iso_to_epoch(last_seen)

                    if last_seen_epoch is not None:
                        age = now_epoch - last_seen_epoch
                        if age > STALE_THRESHOLD_SECONDS:
                            status = "stale"
                            status_num = 0
                            if asset_key == "juice-shop" and example_com_down_recent:
                                status = "down"
                                status_num = -2
                        else:
                            if code == 200 or raw_status == "up":
                                status = "up"
                                status_num = 1
                            else:
                                status = "down"
                                status_num = -2
                    else:
                        status = "unknown"
                        status_num = -1

                staleness_seconds = (now_epoch - last_seen_epoch) if last_seen_epoch else 0
                posture_score = 100
                posture_state = "green"
                if status_num == -2 or status_num == -1:
                    posture_score = 0
                    posture_state = "red"
                elif staleness_seconds > 300:
                    posture_score = 60
                    posture_state = "amber"

                prev_status_num, prev_last_change = get_prev_status(asset_key, org_id)
                last_status_change = prev_last_change or last_seen
                if prev_status_num is not None and str(status_num) != prev_status_num:
                    last_status_change = last_seen

                doc = {
                    "@timestamp": now_iso,
                    "org_id": org_id,
                    "asset_key": asset_key,
                    "name": name,
                    "type": atype,
                    "environment": env,
                    "criticality": crit,
                    "owner": owner,
                    "owner_team": owner_team,
                    "status": status,
                    "status_num": status_num,
                    "code": code,
                    "latency_ms": latency_ms,
                    "last_seen": last_seen,
                    "source_event_timestamp": event_ts,
                    "staleness_seconds": staleness_seconds,
                    "posture_score": posture_score,
                    "posture_state": posture_state,
                    "last_status_change": last_status_change,
                }
                try:
                    _put(f"/{STATUS_INDEX}/_doc/{_doc_id(asset_key, org_id)}", doc)
                except Exception as e:
                    logger.warning("upsert %s failed: %s", asset_key, e)
        try:
            _post(f"/{STATUS_INDEX}/_refresh")
        except Exception as e:
            logger.warning("refresh failed: %s", e)
    metrics.inc_counter("secplat_deriver_runs_completed_total")
    metrics.set_gauge("secplat_deriver_last_run_timestamp", time.time())
    metrics.set_gauge(
        "secplat_deriver_last_run_duration_seconds",
        max(0.0, time.monotonic() - started),
    )
    logger.info("derivation done")


def main() -> None:
    configure_otel()
    start_metrics_server(metrics, port=DERIVER_METRICS_PORT, logger=logger)
    logger.info(
        "secplat-deriver started. OPENSEARCH_URL=%s interval=%ss",
        OPENSEARCH_URL,
        DERIVER_INTERVAL_SECONDS,
    )
    ensure_status_index()
    while True:
        try:
            run_derivation()
        except Exception as e:
            metrics.inc_counter("secplat_deriver_runs_failed_total")
            logger.exception("derivation error: %s", e)
        time.sleep(DERIVER_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
