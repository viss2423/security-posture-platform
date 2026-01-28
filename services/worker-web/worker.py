import os
import time
import json
import requests
import psycopg
from psycopg.rows import dict_row
from urllib.parse import urljoin

POSTGRES_DSN = os.environ["POSTGRES_DSN"].replace("postgresql://", "postgresql://")
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

def get_asset(conn, asset_id: int):
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM assets WHERE asset_id=%s", (asset_id,))
        return cur.fetchone()

def insert_finding(conn, asset_id: int, category: str, title: str, severity: str, confidence: str, evidence: str, remediation: str):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO findings(asset_id, category, title, severity, confidence, evidence, remediation)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (asset_id, category, title, severity, confidence, evidence, remediation))

def finish_job(conn, job_id: int, ok: bool, error: str | None = None):
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE scan_jobs
               SET status=%s, finished_at=NOW(), error=%s
             WHERE job_id=%s
        """, ("done" if ok else "failed", error, job_id))

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

def main():
    print("[worker-web] started")
    while True:
        try:
            with db_conn() as conn:
                conn.autocommit = True
                job = fetch_job(conn)
                if not job:
                    time.sleep(3)
                    continue

                job_id = job["job_id"]
                asset_id = job["target_asset_id"]
                asset = get_asset(conn, asset_id)

                if not asset:
                    finish_job(conn, job_id, ok=False, error="Asset not found")
                    continue

                if asset["type"] != "external_web":
                    finish_job(conn, job_id, ok=False, error="Target is not external_web")
                    continue

                if REQUIRE_DOMAIN_VERIFICATION and not asset["verified"]:
                    finish_job(conn, job_id, ok=False, error="Domain not verified")
                    continue

                start = time.time()
                scan = scan_external_web(asset["name"])
                elapsed = time.time() - start

                evidence = json.dumps({"scan": scan, "elapsed_seconds": elapsed}, indent=2)

                if not scan["reachable_https"]:
                    insert_finding(
                        conn, asset_id,
                        category="transport",
                        title="HTTPS not reachable",
                        severity="high",
                        confidence="high",
                        evidence=evidence,
                        remediation="Ensure HTTPS is enabled and reachable. Configure TLS and redirect HTTP to HTTPS."
                    )

                if scan["missing_headers"]:
                    insert_finding(
                        conn, asset_id,
                        category="headers",
                        title=f"Missing security headers: {', '.join(scan['missing_headers'])}",
                        severity="medium",
                        confidence="high",
                        evidence=evidence,
                        remediation="Add recommended security headers (HSTS, CSP, X-Frame-Options, etc.) via your web server/CDN configuration."
                    )

                finish_job(conn, job_id, ok=True)

        except Exception as e:
            print(f"[worker-web] error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()
