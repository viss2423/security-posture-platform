import json
import os
import socket
import time

import psycopg
import requests
from psycopg.rows import dict_row

POSTGRES_DSN = os.environ["POSTGRES_DSN"].replace("postgresql://", "postgresql://")
REDIS_URL = os.environ.get("REDIS_URL", "").strip() or None
STREAM_SCAN = "secplat.jobs.scan"
CONSUMER_GROUP = "workers"
MAX_SCAN_DURATION_SECONDS = int(os.getenv("MAX_SCAN_DURATION_SECONDS", "900"))
REQUIRE_DOMAIN_VERIFICATION = os.getenv("REQUIRE_DOMAIN_VERIFICATION", "true").lower() == "true"

SAFE_HEADERS_TO_CHECK = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def db_conn():
    return psycopg.connect(POSTGRES_DSN, row_factory=dict_row)


def fetch_job(conn):
    """Claim next queued web_exposure job from DB. Returns dict with job_id, target_asset_id or None."""
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE scan_jobs
               SET status='running', started_at=NOW()
             WHERE job_id = (
               SELECT job_id FROM scan_jobs
                WHERE status='queued' AND job_type='web_exposure'
                ORDER BY created_at ASC
                LIMIT 1
             )
             RETURNING job_id, target_asset_id;
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


def _read_one_from_stream():
    """Try to read one message from Redis stream (block 2s). Returns (stream_key, message_id, fields) or None."""
    if not REDIS_URL:
        return None
    try:
        import redis

        r = redis.from_url(REDIS_URL, decode_responses=True)
        try:
            r.xgroup_create(STREAM_SCAN, CONSUMER_GROUP, id="0", mkstream=True)
        except Exception:
            pass  # BUSYGROUP = already exists
        consumer = f"worker-{socket.gethostname()}-{os.getpid()}"
        streams = r.xreadgroup(CONSUMER_GROUP, consumer, {STREAM_SCAN: ">"}, count=1, block=2000)
        if not streams:
            return None
        for stream_name, messages in streams:
            for msg_id, fields in messages:
                return (stream_name, msg_id, fields)
    except Exception as e:
        print(f"[worker-web] redis read: {e}")
    return None


def _ack_stream(msg_id):
    if not REDIS_URL:
        return
    try:
        import redis

        r = redis.from_url(REDIS_URL, decode_responses=True)
        r.xack(STREAM_SCAN, CONSUMER_GROUP, msg_id)
    except Exception as e:
        print(f"[worker-web] redis ack: {e}")


def main():
    print("[worker-web] started (redis=%s)" % ("yes" if REDIS_URL else "no"))
    while True:
        try:
            # Prefer Redis stream, then DB poll
            job = None
            msg_id = None
            from_redis = _read_one_from_stream()
            if from_redis:
                stream_name, msg_id, fields = from_redis
                job_id_str = fields.get("job_id")
                if not job_id_str:
                    _ack_stream(msg_id)
                else:
                    try:
                        job_id = int(job_id_str)
                    except ValueError:
                        _ack_stream(msg_id)
                    else:
                        with db_conn() as conn:
                            conn.autocommit = True
                            job = claim_job_by_id(conn, job_id)
                            if job:
                                run_one_job(conn, job["job_id"], job["target_asset_id"])
                            _ack_stream(msg_id)
            if job is None:
                with db_conn() as conn:
                    conn.autocommit = True
                    job = fetch_job(conn)
                    if job:
                        run_one_job(conn, job["job_id"], job["target_asset_id"])
            if job is None:
                time.sleep(2)
        except Exception as e:
            print(f"[worker-web] error: {e}")
            time.sleep(5)


if __name__ == "__main__":
    main()
