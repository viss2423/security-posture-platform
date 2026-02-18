from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    ENV: str = "dev"
    API_SECRET_KEY: str = "change_me"
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "admin"  # dev only; use ADMIN_PASSWORD_HASH in prod
    ADMIN_PASSWORD_HASH: str | None = (
        None  # bcrypt hash; when set, login uses this instead of ADMIN_PASSWORD
    )
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24h; shorten for higher security
    POSTGRES_DSN: str
    OPENSEARCH_URL: str = "http://opensearch:9200"
    REDIS_URL: str | None = None  # Phase 1: when set, API publishes scan jobs to Redis stream
    MAX_SCAN_DURATION_SECONDS: int = 900
    MAX_REQUESTS_PER_SECOND: int = 2
    BLOCK_PRIVATE_IPS: bool = True
    REQUIRE_DOMAIN_VERIFICATION: bool = True

    # Posture / status rules (single source of truth; align with ingestion & Grafana)
    STALE_THRESHOLD_SECONDS: int = 300  # > this = amber/stale
    EXPECTED_CHECK_INTERVAL_SECONDS: int = 60  # ingestion runs every Ns
    LATENCY_SLO_MS: int = 200  # latency above = SLO breach

    # Alerting: optional Slack webhook; when set, POST /posture/alert/send can notify
    SLACK_WEBHOOK_URL: str | None = None
    # Slack interactive (B.4): signing secret to verify interaction payloads
    SLACK_SIGNING_SECRET: str | None = None

    # WhatsApp via Twilio: when set, POST /posture/alert/send can notify (optional, use instead of or with Slack)
    TWILIO_ACCOUNT_SID: str | None = None
    TWILIO_AUTH_TOKEN: str | None = None
    TWILIO_WHATSAPP_FROM: str | None = (
        None  # e.g. whatsapp:+14155238886 (sandbox) or your Twilio WhatsApp number
    )
    WHATSAPP_ALERT_TO: str | None = None  # e.g. whatsapp:+1234567890

    # Jira (B.4): create ticket from incident. Base URL e.g. https://your.atlassian.net
    JIRA_BASE_URL: str | None = None
    JIRA_EMAIL: str | None = None
    JIRA_API_TOKEN: str | None = None
    JIRA_PROJECT_KEY: str | None = None  # default project when not passed in request

    # Retention: applied by POST /retention/apply (or cron calling it)
    EVENTS_RETENTION_DAYS: int = 90  # delete OpenSearch secplat-events older than this
    SNAPSHOTS_RETENTION_KEEP: int = 500  # keep this many newest report snapshots in Postgres

    # Scheduled report snapshots (Phase A.3): when True, API saves a snapshot every N hours in background
    ENABLE_SCHEDULED_SNAPSHOTS: bool = False
    SCHEDULED_SNAPSHOT_INTERVAL_HOURS: float = 24.0

    # Report PDF header (corporate format)
    REPORT_ORG_NAME: str = "SecPlat"
    REPORT_ENV: str = "All"

    # Logging
    LOG_LEVEL: str = "INFO"

    # Rate limiting (in-memory, per process)
    RATE_LIMIT_LOGIN_PER_MINUTE: int = 5
    RATE_LIMIT_RETENTION_PER_HOUR: int = 10

    # OIDC / SSO (Phase B.1). When set, "Sign in with SSO" is available; users must exist in users table (username = IdP preferred_username or email).
    OIDC_ISSUER_URL: str | None = None  # e.g. https://login.microsoftonline.com/TENANT_ID/v2.0
    OIDC_CLIENT_ID: str | None = None
    OIDC_CLIENT_SECRET: str | None = None
    OIDC_REDIRECT_URI: str | None = None  # e.g. http://localhost:8000/auth/oidc/callback
    OIDC_SCOPES: str = "openid profile email"
    FRONTEND_URL: str = "http://localhost:3000"  # redirect here after SSO with #access_token=...


settings = Settings()
