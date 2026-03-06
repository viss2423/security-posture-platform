from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    ENV: str = "dev"
    API_SECRET_KEY: str = "change_me"
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "admin"  # dev only; use ADMIN_PASSWORD_HASH in prod
    ADMIN_PASSWORD_HASH: str | None = (
        None  # bcrypt hash; when set, login uses this instead of ADMIN_PASSWORD
    )
    # Service identities (Phase 1 maturity): seeded in users table at startup.
    SCANNER_SERVICE_USERNAME: str = "scanner-service"
    SCANNER_SERVICE_PASSWORD: str = "scanner-local-strong"
    INGESTION_SERVICE_USERNAME: str = "ingestion-service"
    INGESTION_SERVICE_PASSWORD: str = "ingestion-local-strong"
    CORRELATOR_SERVICE_USERNAME: str = "correlator-service"
    CORRELATOR_SERVICE_PASSWORD: str = "correlator-local-strong"
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
    POSTURE_CACHE_TTL_SECONDS: float = (
        5.0  # reuse posture reads briefly to avoid duplicate OpenSearch work
    )

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

    # AI enrichment (Phase AI-1): incident summary, finding explanation, anomaly notes.
    AI_ENABLED: bool = False
    AI_PROVIDER: str = "ollama"  # ollama | openai
    AI_TIMEOUT_SECONDS: int = 60
    AI_TEMPERATURE: float = 0.2
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.1:8b"
    OLLAMA_KEEP_ALIVE: str | None = "30m"
    OPENAI_API_KEY: str | None = None
    OPENAI_BASE_URL: str = "https://api.openai.com/v1"
    OPENAI_MODEL: str = "gpt-4.1-mini"

    # Trainable finding risk model. Keeps heuristic fallback when disabled or artifact missing.
    RISK_MODEL_ENABLED: bool = False
    RISK_MODEL_ARTIFACT_PATH: str | None = "/app/models/finding-risk-model.joblib"

    # Repository scanner controls used by website-triggered OSV/Trivy jobs.
    REPOSITORY_SCAN_DEFAULT_PATH: str = "/workspace"
    REPOSITORY_SCAN_DEFAULT_ASSET_KEY: str = "secplat-repo"
    REPOSITORY_SCAN_DEFAULT_ASSET_NAME: str = "SecPlat repository"
    REPOSITORY_SCAN_DEFAULT_ENVIRONMENT: str = "dev"
    REPOSITORY_SCAN_DEFAULT_CRITICALITY: str = "medium"
    OSV_SCANNER_BIN: str = "/usr/local/bin/osv-scanner"
    OSV_SCANNER_TIMEOUT_SECONDS: int = 600
    TRIVY_BIN: str = "/usr/local/bin/trivy"
    TRIVY_SCANNERS: str = "vuln,misconfig"
    TRIVY_TIMEOUT_SECONDS: int = 1200
    THREAT_INTEL_HTTP_TIMEOUT_SECONDS: int = 30
    THREAT_INTEL_FEEDS_JSON: str = ""
    THREAT_INTEL_CROWDSEC_API_KEY: str = ""
    THREAT_INTEL_ABUSEIPDB_API_KEY: str = ""
    TELEMETRY_IMPORT_MAX_EVENTS: int = 20000
    TELEMETRY_MIRROR_TO_OPENSEARCH: bool = True
    TELEMETRY_OPENSEARCH_INDEX_PREFIX: str = "secplat-telemetry"
    TELEMETRY_DEFAULT_LOOKBACK_HOURS: int = 24
    ENABLE_SCHEDULED_TELEMETRY_IMPORT: bool = False
    SCHEDULED_TELEMETRY_IMPORT_INTERVAL_SECONDS: int = 300
    TELEMETRY_SCHEDULED_SOURCES: str = "suricata,zeek,auditd,cowrie"
    ENABLE_TELEMETRY_KEEPALIVE: bool = True
    TELEMETRY_KEEPALIVE_INTERVAL_SECONDS: int = 120
    TELEMETRY_KEEPALIVE_MAX_SILENCE_MINUTES: int = 3
    TELEMETRY_KEEPALIVE_CREATE_ALERTS: bool = False
    TELEMETRY_KEEPALIVE_ASSET_KEY: str = ""
    NETWORK_ANOMALY_THRESHOLD: float = 2.5
    ENABLE_SCHEDULED_NETWORK_ANOMALY: bool = True
    SCHEDULED_NETWORK_ANOMALY_INTERVAL_MINUTES: int = 60
    ATTACK_LAB_ALLOWED_NETWORKS: str = "127.0.0.1/32,172.16.0.0/12,192.168.0.0/16"
    ATTACK_LAB_DEFAULT_PORTS: str = "22,80,443,3000,5432,6379,9200"
    ATTACK_LAB_NMAP_BIN: str = "/usr/bin/nmap"
    ATTACK_LAB_WEB_SCAN_TIMEOUT_SECONDS: int = 90
    TELEMETRY_SURICATA_LOG_PATH: str = "/workspace/lab-data/suricata/eve.json"
    TELEMETRY_ZEEK_LOG_PATH: str = "/workspace/lab-data/zeek/conn.log"
    TELEMETRY_AUDITD_LOG_PATH: str = "/workspace/lab-data/auditd/audit.log"
    TELEMETRY_COWRIE_LOG_PATH: str = "/workspace/lab-data/cowrie/cowrie.json"
    CYBERLAB_AUTO_SEED_DEMO: bool = False
    CYBERLAB_AUTO_SEED_FORCE: bool = False
    CYBERLAB_AUTO_SEED_ONCE_VERSION: str = "v1"
    CYBERLAB_DEMO_ASSET_KEY: str = "cyberlab-demo-asset"
    CYBERLAB_DEMO_REPO_ASSET_KEY: str = "cyberlab-demo-repo"
    CYBERLAB_DEMO_IOC_SOURCE: str = "cyberlab-demo"


settings = Settings()
