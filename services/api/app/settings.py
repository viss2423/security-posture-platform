from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    ENV: str = "dev"
    API_SECRET_KEY: str = "change_me"
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "admin"  # plain; set ADMIN_PASSWORD_HASH in prod
    ADMIN_PASSWORD_HASH: str | None = None
    POSTGRES_DSN: str
    OPENSEARCH_URL: str = "http://opensearch:9200"
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

settings = Settings()

