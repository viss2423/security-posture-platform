import json
import logging
import os
import socket
import sys
import time
from datetime import UTC, datetime

import psycopg
import requests
from psycopg.rows import dict_row

POSTGRES_DSN = os.environ["POSTGRES_DSN"].replace("postgresql://", "postgresql://")
REDIS_URL = os.environ.get("REDIS_URL", "").strip() or None
STREAM_SCAN = "secplat.jobs.scan"
STREAM_DLQ = f"{STREAM_SCAN}.dlq"
CONSUMER_GROUP = "workers"
MAX_SCAN_DURATION_SECONDS = int(os.getenv("MAX_SCAN_DURATION_SECONDS", "900"))
REQUIRE_DOMAIN_VERIFICATION = os.getenv("REQUIRE_DOMAIN_VERIFICATION", "true").lower() == "true"
STREAM_MAX_RETRIES = int(os.getenv("STREAM_MAX_RETRIES", "5"))
STREAM_CLAIM_IDLE_MS = int(
    os.getenv(
        "STREAM_CLAIM_IDLE_MS",
        str(max(MAX_SCAN_DURATION_SECONDS + 60, 120) * 1000),
    )
)
STALE_RUNNING_TTL_SECONDS = int(
    os.getenv(
        "STALE_RUNNING_TTL_SECONDS",
        str(max(MAX_SCAN_DURATION_SECONDS + 60, 300)),
    )
)
STALE_RECOVERY_INTERVAL_SECONDS = int(os.getenv("STALE_RECOVERY_INTERVAL_SECONDS", "30"))

SAFE_HEADERS_TO_CHECK = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

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


def _is_retryable_exception(exc: Exception) -> bool:
    return isinstance(
        exc,
        (
            TimeoutError,
            ConnectionError,
            OSError,
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            psycopg.OperationalError,
            psycopg.InterfaceError,
        ),
    )


def _job_error_message(exc: Exception) -> tuple[str, bool]:
    retryable = _is_retryable_exception(exc)
    return (f"retryable={str(retryable).lower()} error={exc}", retryable)


def db_conn():
    return psycopg.connect(POSTGRES_DSN, row_factory=dict_row)


def fetch_job(conn):
    """Claim next queued web_exposure job from DB. Returns dict with job_id, target_asset_id or None."""
    with conn.cursor() as cur:
        # Lock one queued row first to avoid duplicate claims across worker replicas.
        cur.execute("""
            WITH next_job AS (
                SELECT job_id
                  FROM scan_jobs
                 WHERE status='queued' AND job_type='web_exposure'
                 ORDER BY created_at ASC
                 FOR UPDATE SKIP LOCKED
                 LIMIT 1
            )
            UPDATE scan_jobs j
               SET status='running', started_at=NOW()
              FROM next_job
             WHERE j.job_id = next_job.job_id
             RETURNING j.job_id, j.target_asset_id;
        """)
        return cur.fetchone()


def claim_job_by_id(conn, job_id: int):
    """Claim a specific job by id if still queued. Returns dict with job_id, target_asset_id or None."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE scan_jobs
               SET status='running', started_at=NOW()
             WHERE job_id = %s AND status = 'queued'
             RETURNING job_id, target_asset_id;
        """,
            (job_id,),
        )
        return cur.fetchone()


def get_job_state(conn, job_id: int):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT job_id, status, started_at, finished_at, retry_count
              FROM scan_jobs
             WHERE job_id = %s
        """,
            (job_id,),
        )
        return cur.fetchone()


def recover_stale_running_jobs(conn, ttl_seconds: int) -> int:
    """Move stale running jobs back to queued so reclaimed stream messages can execute."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE scan_jobs
               SET status = 'queued',
                   started_at = NULL,
                   finished_at = NULL,
                   retry_count = retry_count + 1,
                   error = 'recovered_stale_running_job',
                   log_output = COALESCE(log_output, '') || %s || E'\\n'
             WHERE status = 'running'
               AND started_at IS NOT NULL
               AND started_at < NOW() - (%s * INTERVAL '1 second')
             RETURNING job_id
        """,
            (
                f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] recovered stale running job to queued",
                ttl_seconds,
            ),
        )
        rows = cur.fetchall()
    return len(rows)


def get_asset(conn, asset_id: int):
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM assets WHERE asset_id=%s", (asset_id,))
        return cur.fetchone()


def insert_finding(
    conn,
    asset_id: int,
    category: str,
    title: str,
    severity: str,
    confidence: str,
    evidence: str,
    remediation: str,
):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO findings(asset_id, category, title, severity, confidence, evidence, remediation)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """,
            (asset_id, category, title, severity, confidence, evidence, remediation),
        )


def set_job_log(conn, job_id: int, log_line: str):
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE scan_jobs
               SET log_output = COALESCE(log_output, '') || %s || E'\\n'
             WHERE job_id=%s
        """,
            (log_line, job_id),
        )


def requeue_job(conn, job_id: int, error: str, log_line: str):
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE scan_jobs
               SET status='queued',
                   started_at=NULL,
                   finished_at=NULL,
                   error=%s,
                   retry_count=retry_count + 1,
                   log_output = COALESCE(log_output, '') || %s || E'\\n'
             WHERE job_id=%s
        """,
            (error, log_line, job_id),
        )


def finish_job(conn, job_id: int, ok: bool, error: str | None = None, log_line: str | None = None):
    with conn.cursor() as cur:
        if log_line:
            cur.execute(
                """
                UPDATE scan_jobs
                   SET status=%s, finished_at=NOW(), error=%s, log_output = COALESCE(log_output, '') || %s || E'\\n'
                 WHERE job_id=%s
            """,
                ("done" if ok else "failed", error, log_line, job_id),
            )
        else:
            cur.execute(
                """
                UPDATE scan_jobs
                   SET status=%s, finished_at=NOW(), error=%s
                 WHERE job_id=%s
            """,
                ("done" if ok else "failed", error, job_id),
            )


def run_one_job(conn, job_id: int, asset_id: int):
    """Execute one scan job (after claim). Uses existing get_asset, set_job_log, finish_job, insert_finding."""
    set_job_log(
        conn, job_id, f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Started job for asset_id={asset_id}"
    )
    asset = get_asset(conn, asset_id)

    if not asset:
        finish_job(conn, job_id, ok=False, error="Asset not found", log_line="Asset not found")
        return
    if asset["type"] != "external_web":
        finish_job(
            conn,
            job_id,
            ok=False,
            error="Target is not external_web",
            log_line="Target is not external_web",
        )
        return
    if REQUIRE_DOMAIN_VERIFICATION and not asset["verified"]:
        finish_job(
            conn, job_id, ok=False, error="Domain not verified", log_line="Domain not verified"
        )
        return

    set_job_log(conn, job_id, f"Scanning {asset.get('name', '')} ...")
    start = time.time()
    scan = scan_external_web(asset["name"])
    elapsed = time.time() - start
    set_job_log(
        conn,
        job_id,
        f"Scan completed in {elapsed:.1f}s: HTTPS={scan['reachable_https']}, missing_headers={len(scan['missing_headers'])}",
    )

    evidence = json.dumps({"scan": scan, "elapsed_seconds": elapsed}, indent=2)
    if not scan["reachable_https"]:
        insert_finding(
            conn,
            asset_id,
            category="transport",
            title="HTTPS not reachable",
            severity="high",
            confidence="high",
            evidence=evidence,
            remediation="Ensure HTTPS is enabled and reachable. Configure TLS and redirect HTTP to HTTPS.",
        )
        set_job_log(conn, job_id, "Finding: HTTPS not reachable")
    if scan["missing_headers"]:
        insert_finding(
            conn,
            asset_id,
            category="headers",
            title=f"Missing security headers: {', '.join(scan['missing_headers'])}",
            severity="medium",
            confidence="high",
            evidence=evidence,
            remediation="Add recommended security headers (HSTS, CSP, X-Frame-Options, etc.) via your web server/CDN configuration.",
        )
        set_job_log(conn, job_id, f"Finding: Missing headers {scan['missing_headers']}")
    finish_job(conn, job_id, ok=True, log_line="Done")


def scan_external_web(asset_name: str):
    """
    SAFE checks:
      - HTTPS reachability
      - Security headers presence
      - Certificate expiry checks can be added later (without heavy tooling)
    """
    url = f"http://{asset_name}/"
    https_url = f"https://{asset_name}/"

    results = {"reachable_http": False, "reachable_https": False, "missing_headers": []}

    try:
        r = requests.get(url, timeout=6, allow_redirects=True)
        results["reachable_http"] = True
    except Exception:
        pass

    try:
        r = requests.get(https_url, timeout=8, allow_redirects=True)
        results["reachable_https"] = True
        headers_lower = {k.lower(): v for k, v in r.headers.items()}
        for h in SAFE_HEADERS_TO_CHECK:
            if h not in headers_lower:
                results["missing_headers"].append(h)
    except Exception:
        pass

    return results


def _redis_client():
    if not REDIS_URL:
        return None
    try:
        import redis

        return redis.from_url(REDIS_URL, decode_responses=True)
    except Exception as e:
        logger.warning(
            "redis_client_failed",
            extra={"action": "redis_client", "status": "error", "retryable": True, "error": str(e)},
        )
        return None


def _ensure_stream_group(r):
    try:
        r.xgroup_create(STREAM_SCAN, CONSUMER_GROUP, id="0", mkstream=True)
    except Exception as e:
        # BUSYGROUP = already exists
        if "BUSYGROUP" not in str(e):
            raise


def _read_one_from_stream(r, consumer: str):
    """
    Try reclaim first (XAUTOCLAIM), then read new messages with XREADGROUP.
    Returns (source, msg_id, fields) or None.
    source: reclaimed | new
    """
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
    except Exception as e:
        if "NOGROUP" in str(e):
            try:
                _ensure_stream_group(r)
                return None
            except Exception:
                pass
        logger.warning(
            "redis_read_failed",
            extra={"action": "redis_read", "status": "error", "retryable": True, "error": str(e)},
        )
    return None


def _ack_stream(r, msg_id: str):
    if not r:
        return
    try:
        r.xack(STREAM_SCAN, CONSUMER_GROUP, msg_id)
    except Exception as e:
        logger.warning(
            "redis_ack_failed",
            extra={
                "action": "redis_ack",
                "status": "error",
                "retryable": True,
                "message_id": msg_id,
                "error": str(e),
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
    except Exception as e:
        logger.warning(
            "redis_dlq_publish_failed",
            extra={
                "action": "redis_dlq_publish",
                "status": "error",
                "retryable": True,
                "message_id": msg_id,
                "error": str(e),
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


def main():
    logger.info(
        "worker_started",
        extra={
            "action": "worker_start",
            "redis_enabled": bool(REDIS_URL),
            "status": "ok",
            "stream_claim_idle_ms": STREAM_CLAIM_IDLE_MS,
            "stream_max_retries": STREAM_MAX_RETRIES,
            "stale_running_ttl_seconds": STALE_RUNNING_TTL_SECONDS,
        },
    )
    redis_client = _redis_client()
    consumer_name = f"worker-{socket.gethostname()}-{os.getpid()}"
    last_stale_recovery = 0.0
    while True:
        try:
            # Periodic stale-running recovery keeps DB and stream processing consistent after crashes.
            now = time.time()
            if now - last_stale_recovery >= STALE_RECOVERY_INTERVAL_SECONDS:
                with db_conn() as conn:
                    conn.autocommit = True
                    recovered = recover_stale_running_jobs(conn, STALE_RUNNING_TTL_SECONDS)
                    if recovered:
                        logger.warning(
                            "recovered_stale_running_jobs",
                            extra={
                                "action": "stale_recovery",
                                "status": "recovered",
                                "count": recovered,
                                "ttl_seconds": STALE_RUNNING_TTL_SECONDS,
                                "retryable": True,
                            },
                        )
                last_stale_recovery = now

            # Prefer Redis stream, then DB poll
            job = None
            from_redis = _read_one_from_stream(redis_client, consumer_name)
            if from_redis:
                delivery, msg_id, fields = from_redis
                attempts = _parse_attempts(fields)
                trace_id = (fields.get("trace_id") or "").strip() or None
                job_id_str = (fields.get("job_id") or "").strip()
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
                else:
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
                    else:
                        with db_conn() as conn:
                            conn.autocommit = True
                            job = claim_job_by_id(conn, job_id)
                            if job:
                                try:
                                    run_one_job(conn, job["job_id"], job["target_asset_id"])
                                    logger.info(
                                        "job_completed",
                                        extra={
                                            "action": "job_run",
                                            "status": "done",
                                            "job_id": job["job_id"],
                                            "asset_id": job["target_asset_id"],
                                            "delivery": delivery,
                                            "trace_id": trace_id,
                                        },
                                    )
                                except Exception as e:
                                    error_text, retryable = _job_error_message(e)
                                    if retryable and attempts < STREAM_MAX_RETRIES:
                                        try:
                                            requeue_job(
                                                conn,
                                                job["job_id"],
                                                error=error_text,
                                                log_line=f"Retrying from stream after error ({error_text}); attempt={attempts + 1}",
                                            )
                                        except Exception as requeue_exc:
                                            logger.exception(
                                                "job_requeue_failed",
                                                extra={
                                                    "action": "job_requeue",
                                                    "status": "error",
                                                    "job_id": job["job_id"],
                                                    "retryable": True,
                                                    "error": str(requeue_exc),
                                                    "trace_id": trace_id,
                                                },
                                            )
                                            finish_job(
                                                conn,
                                                job["job_id"],
                                                ok=False,
                                                error=error_text,
                                                log_line=f"Unhandled worker error ({error_text})",
                                            )
                                            _publish_dlq(
                                                redis_client,
                                                msg_id,
                                                fields,
                                                error=error_text,
                                                retryable=retryable,
                                                attempts=attempts,
                                            )
                                        else:
                                            _requeue_stream_message(
                                                redis_client, fields, attempts + 1
                                            )
                                            logger.warning(
                                                "job_requeued",
                                                extra={
                                                    "action": "job_requeue",
                                                    "status": "queued",
                                                    "job_id": job["job_id"],
                                                    "asset_id": job["target_asset_id"],
                                                    "retryable": True,
                                                    "attempt": attempts + 1,
                                                    "trace_id": trace_id,
                                                },
                                            )
                                    else:
                                        finish_job(
                                            conn,
                                            job["job_id"],
                                            ok=False,
                                            error=error_text,
                                            log_line=f"Unhandled worker error ({error_text})",
                                        )
                                        _publish_dlq(
                                            redis_client,
                                            msg_id,
                                            fields,
                                            error=error_text,
                                            retryable=retryable,
                                            attempts=attempts,
                                        )
                                    logger.exception(
                                        "job_failed",
                                        extra={
                                            "action": "job_run",
                                            "status": "failed",
                                            "job_id": job["job_id"],
                                            "asset_id": job["target_asset_id"],
                                            "retryable": retryable,
                                            "attempt": attempts,
                                            "trace_id": trace_id,
                                        },
                                    )
                                _ack_stream(redis_client, msg_id)
                            else:
                                state = get_job_state(conn, job_id)
                                if not state:
                                    _publish_dlq(
                                        redis_client,
                                        msg_id,
                                        fields,
                                        error="job_not_found",
                                        retryable=False,
                                        attempts=attempts,
                                    )
                                    _ack_stream(redis_client, msg_id)
                                elif state["status"] in ("done", "failed"):
                                    # Already terminal in DB, safe to ack stream message.
                                    _ack_stream(redis_client, msg_id)
                                elif state["status"] == "queued":
                                    # Race between consumers; requeue with bounded attempts.
                                    if attempts < STREAM_MAX_RETRIES:
                                        _requeue_stream_message(redis_client, fields, attempts + 1)
                                    else:
                                        _publish_dlq(
                                            redis_client,
                                            msg_id,
                                            fields,
                                            error="queued_job_claim_race_exhausted",
                                            retryable=True,
                                            attempts=attempts,
                                        )
                                    _ack_stream(redis_client, msg_id)
                                else:
                                    # Keep pending for future reclaim; likely still running on another worker.
                                    logger.info(
                                        "job_still_running_message_left_pending",
                                        extra={
                                            "action": "job_consume",
                                            "status": "pending",
                                            "job_id": job_id,
                                            "message_id": msg_id,
                                            "retryable": True,
                                            "trace_id": trace_id,
                                        },
                                    )
            if job is None:
                with db_conn() as conn:
                    conn.autocommit = True
                    job = fetch_job(conn)
                    if job:
                        try:
                            run_one_job(conn, job["job_id"], job["target_asset_id"])
                            logger.info(
                                "job_completed",
                                extra={
                                    "action": "job_run",
                                    "status": "done",
                                    "job_id": job["job_id"],
                                    "asset_id": job["target_asset_id"],
                                },
                            )
                        except Exception as e:
                            error_text, retryable = _job_error_message(e)
                            try:
                                finish_job(
                                    conn,
                                    job["job_id"],
                                    ok=False,
                                    error=error_text,
                                    log_line=f"Unhandled worker error ({error_text})",
                                )
                            except Exception as finish_exc:
                                logger.exception(
                                    "job_finish_failed",
                                    extra={
                                        "action": "job_finish",
                                        "status": "error",
                                        "job_id": job["job_id"],
                                        "retryable": True,
                                        "error": str(finish_exc),
                                    },
                                )
                            logger.exception(
                                "job_failed",
                                extra={
                                    "action": "job_run",
                                    "status": "failed",
                                    "job_id": job["job_id"],
                                    "asset_id": job["target_asset_id"],
                                    "retryable": retryable,
                                },
                            )
            if job is None:
                time.sleep(2)
        except Exception as e:
            logger.exception(
                "worker_loop_failed",
                extra={
                    "action": "worker_loop",
                    "status": "error",
                    "retryable": True,
                    "error": str(e),
                },
            )
            time.sleep(5)


if __name__ == "__main__":
    main()
