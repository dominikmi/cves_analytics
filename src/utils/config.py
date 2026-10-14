"""Application configuration using pydantic-settings."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    app_name: str = "cves-analytics"
    debug: bool = False
    data_dir: str = "data"
    upload_dir: str = "uploads"
    log_level: str = "INFO"
    github_cve_url: str = (
        "https://api.github.com/repos/CVEProject/cvelistV5/contents/cves/"
    )
    github_max_cve_files: int = 10

    model_config = {"env_prefix": "CVE_", "env_file": ".env", "extra": "ignore"}


settings = Settings()


def get_config() -> Settings:
    """Return the application settings singleton."""
    return settings
