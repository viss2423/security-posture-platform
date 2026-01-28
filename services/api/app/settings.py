from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    ENV: str = "dev"
    API_SECRET_KEY: str = "change_me"
    POSTGRES_DSN: str
    OPENSEARCH_URL: str = "http://opensearch:9200"
    MAX_SCAN_DURATION_SECONDS: int = 900
    MAX_REQUESTS_PER_SECOND: int = 2
    BLOCK_PRIVATE_IPS: bool = True
    REQUIRE_DOMAIN_VERIFICATION: bool = True

settings = Settings()

