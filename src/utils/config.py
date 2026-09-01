"""Application configuration using pydantic-settings."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    app_name: str = "cves-analytics"
    debug: bool = False
    data_dir: str = "data"
    upload_dir: str = "uploads"
    log_level: str = "INFO"

    model_config = {"env_prefix": "CVE_", "env_file": ".env"}


settings = Settings()
