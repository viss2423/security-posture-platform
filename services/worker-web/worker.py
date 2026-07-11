import json
import logging
import os
import socket
import sys
import threading
import time
from contextlib import contextmanager
from datetime import UTC, datetime

import requests
from simple_metrics import SimpleMetrics, start_metrics_server

REDIS_URL = os.environ.get("REDIS_URL", "").strip() or None
STREAM_SCAN = "secplat.jobs.scan"
STREAM_DLQ = f"{STREAM_SCAN}.dlq"
CONSUMER_GROUP = "workers"
MAX_SCAN_DURATION_SECONDS = int(os.getenv("MAX_SCAN_DURATION_SECONDS", "900"))
STREAM_MAX_RETRIES = int(os.getenv("STREAM_MAX_RETRIES", "5"))
API_URL = (os.getenv("API_URL") or "http://api:8000").rstrip("/")
WORKER_API_USERNAME = os.getenv("WORKER_API_USERNAME", "scanner-service")
WORKER_API_PASSWORD = os.getenv("WORKER_API_PASSWORD", "scanner-local-strong")
WORKER_API_TIMEOUT_SECONDS = int(
    os.getenv(
        "WORKER_API_TIMEOUT_SECONDS",
        str(max(MAX_SCAN_DURATION_SECONDS + 180, 1200)),
    )
)
STREAM_CLAIM_IDLE_MS = int(
    os.getenv(
        "STREAM_CLAIM_IDLE_MS",
        str(max(MAX_SCAN_DURATION_SECONDS + 60, 120) * 1000),
    )
)
HEARTBEAT_INTERVAL_SECONDS = int(
    os.getenv(
        "JOB_HEARTBEAT_INTERVAL_SECONDS",
        str(max(15, min(MAX_SCAN_DURATION_SECONDS // 3, 60))),
    )
)
WORKER_METRICS_PORT = int(os.getenv("WORKER_METRICS_PORT", "9101"))

SUPPORTED_JOB_TYPES = {
    "github_posture",
    "aws_iam_posture",
    "web_exposure",
    "score_recompute",
    "repository_scan",
    "threat_intel_refresh",
    "telemetry_import",
    "network_anomaly_score",
    "attack_lab_run",
    "attack_surface_discovery",
    "detection_rule_test",
    "detection_rule_schedule",
    "correlation_pass",
}

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
    handler.setFormatter(JsonFormatter(service="secplat-worker-web"))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)


configure_logging()
logger = logging.getLogger("worker-web")
_token: str | None = None
_otel_configured = False
_otel_enabled = False
_tracer = None
_propagator = None
metrics = SimpleMetrics("secplat-worker-web")


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
        logger.debug("worker otel dependencies unavailable", exc_info=True)
        return False
    try:
        resource = Resource.create(
            {
                "service.name": "secplat-worker-web",
                "service.instance.id": f"{socket.gethostname()}:{os.getpid()}",
                "deployment.environment": str(os.getenv("ENV", "dev") or "dev"),
            }
        )
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=endpoint)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer("secplat-worker-web")
        _propagator = propagate
        _otel_enabled = True
        return True
    except Exception:
        logger.debug("worker otel initialization failed", exc_info=True)
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
        logger.debug("worker otel inject failed", exc_info=True)
    return carrier


def _extract_context(context_carrier: dict[str, object] | None = None):
    if not context_carrier or not _otel_enabled or _propagator is None:
        return None
    try:
        return _propagator.extract(carrier=context_carrier)
    except Exception:
        logger.debug("worker otel extract failed", exc_info=True)
        return None


@contextmanager
def start_span(
    name: str,
    *,
    attributes: dict[str, object] | None = None,
    context_carrier: dict[str, object] | None = None,
):
    if not _otel_enabled or _tracer is None:
        yield _NoopSpan()
        return
    span_kwargs: dict[str, object] = {}
    extracted = _extract_context(context_carrier)
    if extracted is not None:
        span_kwargs["context"] = extracted
    with _tracer.start_as_current_span(name, **span_kwargs) as span:
        for key, value in (attributes or {}).items():
            if value is not None:
                span.set_attribute(str(key), value)
        yield span


class NonRetryableJobError(Exception):
    """Job failures that should not be retried by the worker."""


def _is_retryable_exception(exc: Exception) -> bool:
    if isinstance(exc, NonRetryableJobError):
        return False
    return isinstance(
        exc,
        (
            TimeoutError,
            ConnectionError,
            OSError,
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
        ),
    )


def _job_error_message(exc: Exception) -> tuple[str, bool]:
    retryable = _is_retryable_exception(exc)
    return (f"retryable={str(retryable).lower()} error={exc}", retryable)


def _worker_token(force_refresh: bool = False) -> str:
    global _token
    if _token and not force_refresh:
        return _token
    response = requests.post(
        f"{API_URL}/auth/login",  # nosemgrep
        data={
            "username": WORKER_API_USERNAME,
            "password": WORKER_API_PASSWORD,
        },
        timeout=15,
    )
    if response.status_code >= 400:
        raise NonRetryableJobError(f"worker_login_failed status={response.status_code}")
    data = response.json()
    token = str(data.get("access_token") or "").strip()
    if not token:
        raise NonRetryableJobError("worker_login_missing_token")
    _token = token
    return token


def _post_with_auth(
    path: str,
    *,
    json_body: dict | None = None,
    trace_id: str | None = None,
    timeout: int = 30,
) -> requests.Response:
    token = _worker_token()
    headers = {"Authorization": f"Bearer {token}"}
    if trace_id:
        headers["x-request-id"] = trace_id
    inject_context(headers)
    with start_span(
        "http.client.request",
        attributes={
            "http.request.method": "POST",
            "url.full": f"{API_URL}{path}",
            "secplat.request_id": trace_id,
        },
    ):
        response = requests.post(
            f"{API_URL}{path}",  # nosemgrep
            headers=headers,
            json=json_body,
            timeout=timeout,
        )
    if response.status_code in (401, 403):
        token = _worker_token(force_refresh=True)
        headers = {"Authorization": f"Bearer {token}"}
        if trace_id:
            headers["x-request-id"] = trace_id
        inject_context(headers)
        with start_span(
            "http.client.request",
            attributes={
                "http.request.method": "POST",
                "url.full": f"{API_URL}{path}",
                "secplat.request_id": trace_id,
                "auth.retry": True,
            },
        ):
            response = requests.post(
                f"{API_URL}{path}",  # nosemgrep
                headers=headers,
                json=json_body,
                timeout=timeout,
            )
    return response


def claim_job_by_id(job_id: int, worker_id: str, trace_id: str | None = None) -> dict:
    response = _post_with_auth(
        f"/internal/jobs/{job_id}/claim",
        json_body={"worker_id": worker_id},
        trace_id=trace_id,
        timeout=30,
    )
    if response.status_code == 404:
        raise NonRetryableJobError("job_not_found")
    if response.status_code == 429 or response.status_code >= 500:
        raise TimeoutError(f"job_claim_unavailable status={response.status_code}")
    if response.status_code >= 400:
        raise NonRetryableJobError(f"job_claim_failed status={response.status_code}")
    payload = response.json() if response.content else {}
    return payload if isinstance(payload, dict) else {}


def heartbeat_job(
    job_id: int,
    claim_token: str,
    worker_id: str,
    trace_id: str | None = None,
) -> dict:
    response = _post_with_auth(
        f"/internal/jobs/{job_id}/heartbeat",
        json_body={"claim_token": claim_token, "worker_id": worker_id},
        trace_id=trace_id,
        timeout=30,
    )
    if response.status_code == 404:
        raise NonRetryableJobError("job_not_found")
    if response.status_code == 409:
        raise NonRetryableJobError("job_claim_invalid")
    if response.status_code == 429 or response.status_code >= 500:
        raise TimeoutError(f"job_heartbeat_unavailable status={response.status_code}")
    if response.status_code >= 400:
        raise NonRetryableJobError(f"job_heartbeat_failed status={response.status_code}")
    payload = response.json() if response.content else {}
    return payload if isinstance(payload, dict) else {}


def complete_job(
    job_id: int,
    claim_token: str,
    worker_id: str,
    *,
    log_line: str = "Done",
    trace_id: str | None = None,
) -> dict:
    response = _post_with_auth(
        f"/internal/jobs/{job_id}/complete",
        json_body={
            "claim_token": claim_token,
            "worker_id": worker_id,
            "log_line": log_line,
        },
        trace_id=trace_id,
        timeout=30,
    )
    if response.status_code == 404:
        raise NonRetryableJobError("job_not_found")
    if response.status_code == 409:
        raise NonRetryableJobError("job_claim_invalid")
    if response.status_code == 429 or response.status_code >= 500:
        raise TimeoutError(f"job_complete_unavailable status={response.status_code}")
    if response.status_code >= 400:
        raise NonRetryableJobError(f"job_complete_failed status={response.status_code}")
    payload = response.json() if response.content else {}
    return payload if isinstance(payload, dict) else {}


def fail_job(
    job_id: int,
    claim_token: str,
    worker_id: str,
    *,
    error: str,
    retryable: bool,
    log_line: str,
    trace_id: str | None = None,
) -> dict:
    response = _post_with_auth(
        f"/internal/jobs/{job_id}/fail",
        json_body={
            "claim_token": claim_token,
            "worker_id": worker_id,
            "error": error,
            "retryable": retryable,
            "log_line": log_line,
        },
        trace_id=trace_id,
        timeout=30,
    )
    if response.status_code == 404:
        raise NonRetryableJobError("job_not_found")
    if response.status_code == 409:
        raise NonRetryableJobError("job_claim_invalid")
    if response.status_code == 429 or response.status_code >= 500:
        raise TimeoutError(f"job_fail_unavailable status={response.status_code}")
    if response.status_code >= 400:
        raise NonRetryableJobError(f"job_fail_failed status={response.status_code}")
    payload = response.json() if response.content else {}
    return payload if isinstance(payload, dict) else {}


def _execute_job_via_api(job_id: int, job_type: str, trace_id: str | None = None) -> dict:
    timeout = max(30, WORKER_API_TIMEOUT_SECONDS)
    response = _post_with_auth(
        f"/jobs/{job_id}/execute",
        trace_id=trace_id,
        timeout=timeout,
    )
    if response.status_code in {400, 404, 409, 422}:
        raise NonRetryableJobError(
            f"api_execute_failed status={response.status_code} job_type={job_type}"
        )
    if response.status_code == 429 or response.status_code >= 500:
        raise TimeoutError(f"api_execute_unavailable status={response.status_code}")
    if response.status_code >= 400:
        raise NonRetryableJobError(
            f"api_execute_failed status={response.status_code} job_type={job_type}"
        )

    payload = response.json() if response.content else {}
    status = str(payload.get("status") or "").strip().lower()
    if status in {"done", "failed"}:
        return payload
    if status in {"queued", "running"}:
        raise TimeoutError(f"api_execute_not_finished status={status}")
    return payload


class JobHeartbeat:
    def __init__(
        self,
        *,
        job_id: int,
        claim_token: str,
        worker_id: str,
        trace_id: str | None,
    ) -> None:
        self.job_id = job_id
        self.claim_token = claim_token
        self.worker_id = worker_id
        self.trace_id = trace_id
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=max(HEARTBEAT_INTERVAL_SECONDS, 5))

    def _run(self) -> None:
        while not self._stop.wait(HEARTBEAT_INTERVAL_SECONDS):
            try:
                payload = heartbeat_job(
                    self.job_id,
                    self.claim_token,
                    self.worker_id,
                    trace_id=self.trace_id,
                )
                if str(payload.get("status") or "").strip().lower() in {"done", "failed"}:
                    return
            except NonRetryableJobError as exc:
                logger.warning(
                    "job_heartbeat_stopped",
                    extra={
                        "action": "job_heartbeat",
                        "status": "stopped",
                        "job_id": self.job_id,
                        "retryable": False,
                        "error": str(exc),
                        "trace_id": self.trace_id,
                    },
                )
                return
            except Exception as exc:
                logger.warning(
                    "job_heartbeat_failed",
                    extra={
                        "action": "job_heartbeat",
                        "status": "error",
                        "job_id": self.job_id,
                        "retryable": True,
                        "error": str(exc),
                        "trace_id": self.trace_id,
                    },
                )


def run_one_job(job: dict, *, worker_id: str, trace_id: str | None = None) -> dict:
    job_id = int(job["job_id"])
    job_type = str(job.get("job_type") or "").strip()
    claim_token = str(job.get("claim_token") or "").strip()
    if job_type not in SUPPORTED_JOB_TYPES:
        raise NonRetryableJobError(f"unsupported_job_type:{job_type}")
    if not claim_token:
        raise NonRetryableJobError("missing_claim_token")

    heartbeat = JobHeartbeat(
        job_id=job_id,
        claim_token=claim_token,
        worker_id=worker_id,
        trace_id=trace_id,
    )
    heartbeat.start()
    try:
        payload = _execute_job_via_api(job_id, job_type, trace_id=trace_id)
    finally:
        heartbeat.stop()
    return payload


def _redis_client():
    if not REDIS_URL:
        return None
    try:
        import redis

        return redis.from_url(REDIS_URL, decode_responses=True)
    except Exception as exc:
        logger.warning(
            "redis_client_failed",
            extra={
                "action": "redis_client",
                "status": "error",
                "retryable": True,
                "error": str(exc),
            },
        )
        return None


def _ensure_stream_group(r):
    try:
        r.xgroup_create(STREAM_SCAN, CONSUMER_GROUP, id="0", mkstream=True)
    except Exception as exc:
        if "BUSYGROUP" not in str(exc):
            raise


def _read_one_from_stream(r, consumer: str):
    if not r:
        return None
    try:
        _ensure_stream_group(r)
        claimed = r.xautoclaim(
            STREAM_SCAN,
            CONSUMER_GROUP,
            consumer,
            min_idle_time=STREAM_CLAIM_IDLE_MS,
            start_id="0-0",
            count=1,
        )
        claimed_messages = (
            claimed[1] if isinstance(claimed, (list, tuple)) and len(claimed) > 1 else []
        )
        if claimed_messages:
            msg_id, fields = claimed_messages[0]
            return ("reclaimed", msg_id, fields)
        streams = r.xreadgroup(CONSUMER_GROUP, consumer, {STREAM_SCAN: ">"}, count=1, block=2000)
        if not streams:
            return None
        for _stream_name, messages in streams:
            for msg_id, fields in messages:
                return ("new", msg_id, fields)
    except Exception as exc:
        if "NOGROUP" in str(exc):
            try:
                _ensure_stream_group(r)
                return None
            except Exception:
                pass
        logger.warning(
            "redis_read_failed",
            extra={
                "action": "redis_read",
                "status": "error",
                "retryable": True,
                "error": str(exc),
            },
        )
    return None


def _ack_stream(r, msg_id: str):
    if not r:
        return
    try:
        r.xack(STREAM_SCAN, CONSUMER_GROUP, msg_id)
    except Exception as exc:
        logger.warning(
            "redis_ack_failed",
            extra={
                "action": "redis_ack",
                "status": "error",
                "retryable": True,
                "message_id": msg_id,
                "error": str(exc),
            },
        )


def _publish_dlq(r, msg_id: str, fields: dict, error: str, retryable: bool, attempts: int):
    if not r:
        return
    try:
        payload = {k: str(v) for k, v in fields.items()}
        payload.update(
            {
                "original_stream": STREAM_SCAN,
                "original_id": msg_id,
                "error": error,
                "retryable": str(retryable).lower(),
                "attempts": str(attempts),
                "failed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            }
        )
        r.xadd(STREAM_DLQ, payload, maxlen=10_000)
        metrics.inc_counter("secplat_worker_jobs_dlq_total")
    except Exception as exc:
        logger.warning(
            "redis_dlq_publish_failed",
            extra={
                "action": "redis_dlq_publish",
                "status": "error",
                "retryable": True,
                "message_id": msg_id,
                "error": str(exc),
            },
        )


def _requeue_stream_message(r, fields: dict, attempts: int):
    if not r:
        return
    payload = {k: str(v) for k, v in fields.items()}
    payload["attempts"] = str(attempts)
    r.xadd(STREAM_SCAN, payload, maxlen=100_000)


def _parse_attempts(fields: dict) -> int:
    try:
        return max(0, int(fields.get("attempts", "0")))
    except Exception:
        return 0


def _json_payload(fields: dict) -> dict:
    raw = fields.get("payload")
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def main():
    configure_otel()
    start_metrics_server(metrics, port=WORKER_METRICS_PORT, logger=logger)
    logger.info(
        "worker_started",
        extra={
            "action": "worker_start",
            "redis_enabled": bool(REDIS_URL),
            "status": "ok",
            "stream_claim_idle_ms": STREAM_CLAIM_IDLE_MS,
            "stream_max_retries": STREAM_MAX_RETRIES,
            "heartbeat_interval_seconds": HEARTBEAT_INTERVAL_SECONDS,
            "api_url": API_URL,
        },
    )
    redis_client = _redis_client()
    consumer_name = f"worker-{socket.gethostname()}-{os.getpid()}"
    worker_id = consumer_name

    while True:
        try:
            from_redis = _read_one_from_stream(redis_client, consumer_name)
            if not from_redis:
                time.sleep(1)
                continue

            delivery, msg_id, fields = from_redis
            attempts = _parse_attempts(fields)
            trace_id = (fields.get("trace_id") or "").strip() or None
            payload = _json_payload(fields)
            job_id_str = (fields.get("job_id") or str(payload.get("job_id") or "")).strip()
            if not job_id_str:
                logger.warning(
                    "redis_job_missing_id",
                    extra={
                        "action": "job_consume",
                        "status": "dropped",
                        "retryable": False,
                        "delivery": delivery,
                        "message_id": msg_id,
                        "trace_id": trace_id,
                    },
                )
                _publish_dlq(
                    redis_client,
                    msg_id,
                    fields,
                    error="missing_job_id",
                    retryable=False,
                    attempts=attempts,
                )
                _ack_stream(redis_client, msg_id)
                continue

            try:
                job_id = int(job_id_str)
            except ValueError:
                logger.warning(
                    "redis_job_invalid_id",
                    extra={
                        "action": "job_consume",
                        "status": "dropped",
                        "retryable": False,
                        "delivery": delivery,
                        "message_id": msg_id,
                        "job_id": job_id_str,
                        "trace_id": trace_id,
                    },
                )
                _publish_dlq(
                    redis_client,
                    msg_id,
                    fields,
                    error="invalid_job_id",
                    retryable=False,
                    attempts=attempts,
                )
                _ack_stream(redis_client, msg_id)
                continue

            try:
                with start_span(
                    "messaging.process",
                    attributes={
                        "messaging.system": "redis",
                        "messaging.destination.name": STREAM_SCAN,
                        "messaging.operation": "process",
                        "messaging.message.id": msg_id,
                        "job.id": job_id,
                    },
                    context_carrier=fields,
                ):
                    job = claim_job_by_id(job_id, worker_id, trace_id=trace_id)
                    if not bool(job.get("claimed")):
                        acknowledge = bool(job.get("acknowledge"))
                        logger.info(
                            "job_not_claimed",
                            extra={
                                "action": "job_claim",
                                "status": str(job.get("status") or "unknown"),
                                "job_id": job_id,
                                "delivery": delivery,
                                "acknowledge": acknowledge,
                                "trace_id": trace_id,
                            },
                        )
                        if acknowledge:
                            _ack_stream(redis_client, msg_id)
                        continue
                    metrics.inc_counter("secplat_worker_jobs_claimed_total")

                    job_type = str(job.get("job_type") or "").strip()
                    try:
                        started = time.monotonic()
                        payload = run_one_job(job, worker_id=worker_id, trace_id=trace_id)
                        metrics.inc_counter("secplat_worker_jobs_completed_total")
                        metrics.set_gauge("secplat_worker_last_completed_timestamp", time.time())
                        metrics.set_gauge(
                            "secplat_worker_last_job_duration_seconds",
                            max(0.0, time.monotonic() - started),
                        )
                        logger.info(
                            "job_completed",
                            extra={
                                "action": "job_run",
                                "status": str(payload.get("status") or "done"),
                                "job_id": job_id,
                                "job_type": job_type,
                                "delivery": delivery,
                                "trace_id": trace_id,
                            },
                        )
                        _ack_stream(redis_client, msg_id)
                    except Exception as exc:
                        error_text, retryable = _job_error_message(exc)
                        should_requeue = retryable and attempts < STREAM_MAX_RETRIES
                        claim_token = str(job.get("claim_token") or "").strip()
                        try:
                            fail_payload = fail_job(
                                job_id,
                                claim_token,
                                worker_id,
                                error=error_text,
                                retryable=should_requeue,
                                log_line=(
                                    f"Retrying from stream after error ({error_text}); attempt={attempts + 1}"
                                    if should_requeue
                                    else f"Unhandled worker error ({error_text})"
                                ),
                                trace_id=trace_id,
                            )
                        except Exception as fail_exc:
                            logger.exception(
                                "job_fail_finalize_failed",
                                extra={
                                    "action": "job_finalize",
                                    "status": "error",
                                    "job_id": job_id,
                                    "job_type": job_type,
                                    "retryable": _is_retryable_exception(fail_exc),
                                    "error": str(fail_exc),
                                    "trace_id": trace_id,
                                },
                            )
                            continue

                        if bool(fail_payload.get("requeued")):
                            _requeue_stream_message(redis_client, fields, attempts + 1)
                            metrics.inc_counter("secplat_worker_jobs_requeued_total")
                            logger.warning(
                                "job_requeued",
                                extra={
                                    "action": "job_requeue",
                                    "status": "queued",
                                    "job_id": job_id,
                                    "job_type": job_type,
                                    "retryable": True,
                                    "attempt": attempts + 1,
                                    "trace_id": trace_id,
                                },
                            )
                            _ack_stream(redis_client, msg_id)
                            continue

                        if not bool(fail_payload.get("existing_terminal")):
                            _publish_dlq(
                                redis_client,
                                msg_id,
                                fields,
                                error=error_text,
                                retryable=retryable,
                                attempts=attempts,
                            )
                        metrics.inc_counter("secplat_worker_jobs_failed_total")
                        metrics.set_gauge("secplat_worker_last_failed_timestamp", time.time())
                        logger.warning(
                            "job_failed",
                            extra={
                                "action": "job_run",
                                "status": str(fail_payload.get("status") or "failed"),
                                "job_id": job_id,
                                "job_type": job_type,
                                "retryable": retryable,
                                "delivery": delivery,
                                "trace_id": trace_id,
                            },
                        )
                        _ack_stream(redis_client, msg_id)
            except Exception as exc:
                error_text, retryable = _job_error_message(exc)
                logger.warning(
                    "job_claim_failed",
                    extra={
                        "action": "job_claim",
                        "status": "error",
                        "job_id": job_id,
                        "delivery": delivery,
                        "retryable": retryable,
                        "error": error_text,
                        "trace_id": trace_id,
                    },
                )
                if not retryable:
                    _publish_dlq(
                        redis_client,
                        msg_id,
                        fields,
                        error=error_text,
                        retryable=False,
                        attempts=attempts,
                    )
                    _ack_stream(redis_client, msg_id)
                continue
        except Exception as exc:
            metrics.inc_counter("secplat_worker_loop_errors_total")
            logger.exception(
                "worker_loop_failed",
                extra={
                    "action": "worker_loop",
                    "status": "error",
                    "retryable": True,
                    "error": str(exc),
                },
            )
            time.sleep(3)


if __name__ == "__main__":
    main()
